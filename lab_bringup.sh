#!/usr/bin/env bash
# Idempotent bring-up for VLAN, trunk, and optional native VLAN demo (with p4 for native)
set -u

BR="br0"
TRUNK_IF="veth-br"                 # root side for Linux VLAN subifs

# OVS-facing ends
P1="p1"; P2="p2"; P4="p4"

# namespace-facing ends
H1_IF="h1p"; H2_IF="h2p"; H4_IF="h4p"

# IP plans
H1_IP="10.10.10.2/24"             # VLAN 10
H2_IP="10.20.20.2/24"             # VLAN 20

TRUNK_V10_IP="10.10.10.1/24"
TRUNK_V20_IP="10.20.20.1/24"

# Native VLAN demo on p4 (only if ENABLE_NATIVE=1)
ENABLE_NATIVE=${ENABLE_NATIVE:-0}
NATIVE_VID=${NATIVE_VID:-100}
NATIVE_IP_TRUNK="198.51.100.2/24" # base iface veth-br (untagged/native)
NATIVE_IP_H4="198.51.100.3/24"    # on h4p

say(){ echo "[*] $*"; }
ok(){  echo "[OK] $*"; }

exists_ns(){ ip netns list | awk '{print $1}' | grep -qx "$1"; }
ensure_ns(){ exists_ns "$1" || sudo ip netns add "$1" 2>/dev/null || true; }

iface_in_ns(){
  local ifn="$1"
  if ip link show "$ifn" &>/dev/null; then echo root; return; fi
  for ns in $(ip netns list | awk '{print $1}'); do
    if ip -n "$ns" link show "$ifn" &>/dev/null; then echo "$ns"; return; fi
  done
  echo none
}

move_to_ns(){
  local ifn="$1" ns="$2" cur; cur=$(iface_in_ns "$ifn")
  [ "$cur" = "$ns" ] && return 0
  if [ "$cur" = "root" ]; then
    sudo ip link set "$ifn" netns "$ns" 2>/dev/null || true
  elif [ "$cur" = "none" ]; then
    :
  else
    sudo ip -n "$cur" link set "$ifn" netns "$ns" 2>/dev/null || true
  fi
}

link_up(){
  local ns="$1" ifn="$2"
  if [ "$ns" = "root" ]; then
    ip link show "$ifn" &>/dev/null && sudo ip link set "$ifn" up || true
  else
    ip -n "$ns" link show "$ifn" &>/dev/null && sudo ip -n "$ns" link set "$ifn" up || true
  fi
}

ensure_addr(){
  local ns="${1:-}" ifn="${2:-}" cidr="${3:-}"
  [ -z "$ns" ] || [ -z "$ifn" ] || [ -z "$cidr" ] && return 0
  local ipn="${cidr%/*}"
  if [ "$ns" = "root" ]; then
    ip -o -4 addr show dev "$ifn" 2>/dev/null | grep -q " $ipn/" \
      || sudo ip addr add "$cidr" dev "$ifn" 2>/dev/null || true
  else
    ip -n "$ns" -o -4 addr show dev "$ifn" 2>/dev/null | grep -q " $ipn/" \
      || sudo ip -n "$ns" addr add "$cidr" dev "$ifn" 2>/dev/null || true
  fi
}

ensure_vlan(){ # base, name, proto, vid
  local base="$1" name="$2" proto="$3" vid="$4"
  ip link show "$name" &>/dev/null || sudo ip link add link "$base" name "$name" type vlan proto "$proto" id "$vid" 2>/dev/null || true
  sudo ip link set "$name" up 2>/dev/null || true
}

ensure_veth(){ # ensure_veth a b  (creates a<->b if neither exists)
  local a="$1" b="$2"
  if ! ip link show "$a" &>/dev/null && ! ip link show "$b" &>/dev/null; then
    sudo ip link add "$a" type veth peer name "$b" 2>/dev/null || true
  fi
  sudo ip link set "$a" up 2>/dev/null || true
  sudo ip link set "$b" up 2>/dev/null || true
}

# --- OVS bridge and ports ---
say "creating OVS bridge and ports"
sudo ovs-vsctl --may-exist add-br "$BR"

# trunk: veth-br (root) <-> veth-br-peer (OVS)
ensure_veth "$TRUNK_IF" "${TRUNK_IF}-peer"
sudo ovs-vsctl --may-exist add-port "$BR" "${TRUNK_IF}-peer"

# access links: p1/p2/p4 (OVS) <-> h1p/h2p/h4p (namespaces)
ensure_veth "$P1" "$H1_IF"; sudo ovs-vsctl --may-exist add-port "$BR" "$P1"
ensure_veth "$P2" "$H2_IF"; sudo ovs-vsctl --may-exist add-port "$BR" "$P2"
ensure_veth "$P4" "$H4_IF"; sudo ovs-vsctl --may-exist add-port "$BR" "$P4"

# port VLAN modes (p1=10, p2=20, p4=native access when enabled)
sudo ovs-vsctl set port "$P1" vlan_mode=access tag=10
sudo ovs-vsctl set port "$P2" vlan_mode=access tag=20

if [ "$ENABLE_NATIVE" = "1" ]; then
  # Trunk carries 10,20; native VLAN = NATIVE_VID (untagged)
  sudo ovs-vsctl set port "${TRUNK_IF}-peer" vlan_mode=native-untagged trunks=10,20 tag="$NATIVE_VID"
  sudo ovs-vsctl set port "$P4" vlan_mode=access tag="$NATIVE_VID"
else
  sudo ovs-vsctl set port "${TRUNK_IF}-peer" vlan_mode=trunk trunks=10,20
  # Keep p4 present but untagged access on a harmless VLAN (no IP) to avoid confusion
  sudo ovs-vsctl set port "$P4" vlan_mode=access tag="$NATIVE_VID"
fi

# --- namespaces and IPs ---
say "setting up namespaces and moving host ends"
ensure_ns h1; ensure_ns h2; ensure_ns h4

move_to_ns "$H1_IF" h1; link_up h1 "$H1_IF"; ensure_addr h1 "$H1_IF" "$H1_IP"
move_to_ns "$H2_IF" h2; link_up h2 "$H2_IF"; ensure_addr h2 "$H2_IF" "$H2_IP"
move_to_ns "$H4_IF" h4; link_up h4 "$H4_IF"

# --- trunk subinterfaces on Linux (root) ---
say "bringing up trunk ${TRUNK_IF} VLAN subinterfaces"
link_up root "$TRUNK_IF"

ensure_vlan "$TRUNK_IF" "${TRUNK_IF}.10" 802.1Q 10
ensure_vlan "$TRUNK_IF" "${TRUNK_IF}.20" 802.1Q 20
ensure_addr root "${TRUNK_IF}.10" "$TRUNK_V10_IP"
ensure_addr root "${TRUNK_IF}.20" "$TRUNK_V20_IP"

# Native VLAN path (only when enabled): IPs on base trunk and h4
if [ "$ENABLE_NATIVE" = "1" ]; then
  say "enabling native VLAN demo on p4 (untagged/native VID=$NATIVE_VID)"
  ensure_addr root "$TRUNK_IF" "$NATIVE_IP_TRUNK"
  ensure_addr h4 "$H4_IF" "$NATIVE_IP_H4"
fi

ok "bring-up complete"

echo
echo "Quick checks:"
echo "  sudo ovs-vsctl show"
echo "  ip -br link | egrep 'br0|p1|p2|p4|h1p|h2p|h4p|veth-br($|-peer|\\.10|\\.20)'"
echo "  sudo ip -br a | egrep 'veth-br(\\.10|\\.20)|^veth-br\\s'"
echo "  sudo ip netns exec h1 ip -br a"
echo "  sudo ip netns exec h2 ip -br a"
echo "  sudo ip netns exec h4 ip -br a"
echo
echo "Tests:"
echo "  VLAN10 : sudo ip netns exec h1 ping -c 3 ${TRUNK_V10_IP%/*}"
echo "  VLAN20 : sudo ip netns exec h2 ping -c 3 ${TRUNK_V20_IP%/*}"
[ \"$ENABLE_NATIVE\" = \"1\" ] && echo \"  Native : sudo ip netns exec h4 ping -c 3 ${NATIVE_IP_TRUNK%/*}\"
echo
echo "Sniff trunk:"
echo "  sudo tcpdump -i $TRUNK_IF -e -vv vlan 10 -c 3"
echo "  sudo tcpdump -i $TRUNK_IF -e -vv vlan 20 -c 3"
[ \"$ENABLE_NATIVE\" = \"1\" ] && echo \"  sudo tcpdump -i $TRUNK_IF -e -vv 'not vlan' -c 3    # native/untagged\"

