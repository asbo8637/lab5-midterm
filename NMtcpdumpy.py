#!/usr/bin/env python3
import sys
from collections import Counter, defaultdict
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.all import rdpcap

FILE = "ping_capture.pcap"
R2_IP = "10.0.0.2"
R3_IP = "10.0.0.3"

def main() -> int:
    packets = rdpcap(FILE)
    ip_counts = Counter()
    ip_to_macs = defaultdict(set)

    for p in packets:
        if not p.haslayer(Ether):
            continue

        #Normalize the mac
        src_mac = (p[Ether].src).lower().replace("-", ":")

        # ICMPv4 echo request (type 8)
        if p.haslayer(IP) and p.haslayer(ICMP):
            ic = p[ICMP]
            if int(getattr(ic, "type", -1)) == 8:  # echo-request
                src_ip = p[IP].src
                ip_counts[src_ip] += 1
                ip_to_macs[src_ip].add(src_mac)
            continue

        # ICMPv6 echo request (type 128) => Scapy class ICMPv6EchoRequest
        if p.haslayer(IPv6) and p.haslayer(ICMPv6EchoRequest):
            src_ip = p[IPv6].src
            ip_counts[src_ip] += 1
            ip_to_macs[src_ip].add(src_mac)
            continue

    if not ip_counts:
        print("No ICMP echo-request traffic found in the pcap.")
        print("Tip: confirm you captured while pings were running, and that your filter didn't exclude ICMP.")
        return 1

    r2_macs = sorted(ip_to_macs.get(R2_IP, set()))
    r3_macs = sorted(ip_to_macs.get(R3_IP, set()))
    print(f"R2 ({R2_IP}) MAC(s): {', '.join(r2_macs) if r2_macs else 'NOT FOUND'}")
    print(f"R3 ({R3_IP}) MAC(s): {', '.join(r3_macs) if r3_macs else 'NOT FOUND'}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())