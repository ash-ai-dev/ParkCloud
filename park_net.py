#!/usr/bin/env python3

import argparse
import subprocess
import sys
from pathlib import Path

try:
    import yaml  # PyYAML is typically available; if not, instruct students to install it.
except Exception as e:
    print("PyYAML not available. Install with: pip install pyyaml", file=sys.stderr)
    raise

# -----------------------------------------------------------------------------
# NovaCloud: Multi-tenant VLAN + Q-in-Q Scaffold (Full Working Version)
# -----------------------------------------------------------------------------
# This script configures Open vSwitch (OVS) for:
#   - Customer VLANs (C-VLANs) on provider edge (PE) ports
#   - Q-in-Q (802.1ad) by pushing an S-VLAN on PE ports (dot1q-tunnel)
#   - Trunk links that carry allowed C-VLANs and a defined native VLAN
#
# Design notes:
#   • For Q-in-Q to show double-tagging on the wire, packets must already carry
#     an *inner* 802.1Q tag (C-VLAN) when they arrive at the PE port.
#     In practice, that means the tenant host/interface should send frames on a
#     VLAN subinterface (e.g., eth0.10), or via a CE switch that tags frames.
#   • This script leaves host VLAN subinterfaces to the verification helper.
#   • Dry-run is the default. Use --apply to execute changes.
# -----------------------------------------------------------------------------

def sh(cmd: str, apply: bool):
    """Print a shell command; execute it if apply=True."""
    if apply:
        print(f"$ {cmd}")
        subprocess.run(cmd, shell=True, check=True)
    else:
        print(cmd)

def ovs_set(port: str, kv: dict, apply: bool):
    """Helper to 'set Port <port> k=v ...'"""
    pairs = " ".join(f"{k}={v}" for k, v in kv.items())
    sh(f"sudo ovs-vsctl set Port {port} {pairs}", apply)

def parse_cfg(path: Path) -> dict:
    data = yaml.safe_load(path.read_text())
    required = ["bridge", "provider_vlan", "native_vlan", "trunks", "tenants"]
    for k in required:
        if k not in data:
            raise ValueError(f"Missing required key '{k}' in {path}")
    # Normalize types
    data["trunks"] = list(data["trunks"] or [])
    data["tenants"] = list(data["tenants"] or [])
    return data

def ensure_bridge(br: str, apply: bool):
    # Create bridge if missing; set fail-mode to standalone for simplicity
    sh(f"sudo ovs-vsctl --may-exist add-br {br}", apply)
    sh(f"sudo ovs-vsctl set-fail-mode {br} standalone", apply)

def add_port_if_missing(br: str, port: str, apply: bool):
    # Attach a system interface as a Port to the bridge if not already present
    sh(f"sudo ovs-vsctl --may-exist add-port {br} {port}", apply)

def build_pe_ports(cfg: dict, apply: bool):
    """
    Configure Provider Edge (PE) ports to push an S-VLAN (provider_vlan) and retain
    the inner C-VLAN (that must be present on ingress frames).
    For each tenant entry:
      - pe_ports: list of interface names acting as customer-facing edges
      - c_vlan: customer VLAN id (inner tag)
    We also set external_ids for introspection.
    """
    s_vlan = cfg["provider_vlan"]
    br = cfg["bridge"]
    for t in cfg["tenants"]:
        name = t["name"]
        cvid = int(t["c_vlan"])
        pe_ports = list(t.get("pe_ports", []))
        for p in pe_ports:
            add_port_if_missing(br, p, apply)
            # dot1q-tunnel pushes the S-tag specified by 'tag'. The inner C-tag is preserved.
            # We annotate with external_ids for clarity.
            ovs_set(p, {
                "vlan_mode": "dot1q-tunnel",
                "tag": str(s_vlan),
                "other_config:qinq_ethtype": "0x88a8",
                'external_ids:tenant': f'"{name}"',
                'external_ids:c_vlan': f'"{cvid}"',
                'external_ids:role': '"pe"'
            }, apply)

def build_trunks(cfg: dict, apply: bool):
    """
    Configure provider trunk ports that carry multiple customer VLANs (C-VLANs)
    and define a native VLAN.
      - trunks: list of interface names that act as backbone trunks
      - allowed C-VLANs = union of tenant c_vlan values
      - native_vlan applies to untagged traffic on the trunk
    vlan_mode may be 'native-untagged' or 'native-tagged'; we default to untagged.
    """
    br = cfg["bridge"]
    allowed = sorted({int(t["c_vlan"]) for t in cfg["tenants"]})
    allowed_csv = ",".join(str(v) for v in allowed) if allowed else ""
    native = int(cfg["native_vlan"])
    vlan_mode = cfg.get("trunk_vlan_mode", "native-untagged")  # can be "native-tagged"

    for trunk_if in cfg["trunks"]:
        add_port_if_missing(br, trunk_if, apply)
        if allowed_csv:
            sh(f"sudo ovs-vsctl set Port {trunk_if} trunks={allowed_csv}", apply)
        ovs_set(trunk_if, {
            "other_config:native_vlan": str(native),
            "vlan_mode": vlan_mode,
            'external_ids:role': '"provider-trunk"'
        }, apply)

def print_verify(cfg: dict):
    br = cfg["bridge"]
    s_vlan = cfg["provider_vlan"]
    native = cfg["native_vlan"]
    trunks = cfg["trunks"]
    any_trunk = trunks[0] if trunks else "<TRUNK_IF>"
    # Emit a compact verification guide
    print("\n# --- Verification checklist ---")
    print("# Show OVS state:")
    print("sudo ovs-vsctl show")
    print("\n# Observe double-tagged frames (0x88a8 outer S-tag, 0x8100 inner C-tag):")
    print(f"sudo tcpdump -e -vvv -i {any_trunk} 'ether proto 0x88a8 or (vlan and vlan)'")
    print("\n# Example host-side VLAN subinterfaces (replace IF and IPs):")
    print("# sudo ip link add link IF name IF.10 type vlan id 10")
    print("# sudo ip addr add 10.0.10.2/24 dev IF.10 && sudo ip link set IF.10 up")
    print("# sudo ip link add link IF name IF.20 type vlan id 20")
    print("# sudo ip addr add 10.0.20.2/24 dev IF.20 && sudo ip link set IF.20 up")
    print("# ping -c3 10.0.10.1  # within VLAN10 should succeed")
    print("# ping -c3 10.0.20.1  # within VLAN20 should succeed")
    print("# cross-VLAN pings should fail unless routed")

def main():
    ap = argparse.ArgumentParser(description="NovaCloud Q-in-Q: full working scaffold for OVS")
    ap.add_argument("-c", "--config", default="nova_net.yaml", help="YAML config file")
    ap.add_argument("--apply", action="store_true", help="Apply changes (default prints only)")
    args = ap.parse_args()

    cfg = parse_cfg(Path(args.config))
    ensure_bridge(cfg["bridge"], apply=args.apply)
    build_pe_ports(cfg, apply=args.apply)
    build_trunks(cfg, apply=args.apply)
    print_verify(cfg)

if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)
