#!/usr/bin/env python3

# Optional: quick Mininet harness to spin up tenant hosts/namespaces on one node.
# Requires: sudo apt-get install mininet (or run in a Mininet-ready image)
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, Host
from mininet.link import TCLink
from mininet.cli import CLI

def build():
    net = Mininet(controller=Controller, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    c0 = net.addController("c0")

    # One simple OVS bridge switch to hang test hosts off of (not the same as your provider OVS)
    s1 = net.addSwitch("s1")

    # Tenants A/B with two hosts each
    ha1 = net.addHost("ha1")
    ha2 = net.addHost("ha2")
    hb1 = net.addHost("hb1")
    hb2 = net.addHost("hb2")

    net.addLink(ha1, s1)
    net.addLink(ha2, s1)
    net.addLink(hb1, s1)
    net.addLink(hb2, s1)

    net.start()

    # Put hosts into VLANs at L2 by creating vlan subifs (simulates C-tagging).
    for h, vid, ip in [(ha1, 10, "10.0.10.11/24"),
                       (ha2, 10, "10.0.10.12/24"),
                       (hb1, 20, "10.0.20.11/24"),
                       (hb2, 20, "10.0.20.12/24")]:
        intf = h.defaultIntf().name
        h.cmd(f"ip link add link {intf} name {intf}.{vid} type vlan id {vid}")
        h.cmd(f"ip addr add {ip} dev {intf}.{vid}")
        h.cmd(f"ip link set {intf}.{vid} up")

    print("*** Mininet ready. Try pings within VLANs.")
    CLI(net)
    net.stop()

if __name__ == "__main__":
    build()
