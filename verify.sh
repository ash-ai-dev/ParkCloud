#!/usr/bin/env bash
set -eu

# Simple verification helper. Adjust IF names and IPs to your slice.
# This script demonstrates creating VLAN subinterfaces on a *host*
# so that C-tagged frames exist before they reach the PE port.

IF="${1:-eth0}"

echo "[*] Creating VLAN subinterfaces on ${IF} (10 and 20)"
sudo ip link add link "${IF}" name "${IF}.10" type vlan id 10 || true
sudo ip link add link "${IF}" name "${IF}.20" type vlan id 20 || true

sudo ip addr add 10.0.10.2/24 dev "${IF}.10" || true
sudo ip addr add 10.0.20.2/24 dev "${IF}.20" || true

sudo ip link set "${IF}.10" up
sudo ip link set "${IF}.20" up

echo "[*] Ready. Example pings (adjust the .1 addresses to your peer host):"
echo "    ping -c3 10.0.10.1"
echo "    ping -c3 10.0.20.1"
echo
echo "[*] On a provider trunk interface (e.g., ens7), run:"
echo "    sudo tcpdump -e -vvv -i <TRUNK_IF> 'ether proto 0x88a8 or (vlan and vlan)'"

