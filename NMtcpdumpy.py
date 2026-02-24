#!/usr/bin/env python3
from collections import defaultdict
import ipaddress
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.all import rdpcap

FILE = "ping_capture.pcap"
R2_IP = "2001:db8:1:0:c802:31ff:feb1:0"
R3_IP = "2001:db8:1:0:c803:31ff:fec0:0"

def normalize_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip.lower()

def main() -> int:
    packets = rdpcap(FILE)
    macs = defaultdict(set)

    for p in packets:
        if not p.haslayer(Ether):
            continue

        #Normalize the mac
        src_mac = (p[Ether].src).lower().replace("-", ":")

        # ICMPv4 echo request (type 8)
        if p.haslayer(IP) and p.haslayer(ICMP):
            ic = p[ICMP]
            if int(getattr(ic, "type", -1)) == 8:
                src_ip = normalize_ip(p[IP].src)
                macs[src_ip].add(src_mac)
            continue
        if p.haslayer(IPv6) and p.haslayer(ICMPv6EchoRequest):
            src_ip = normalize_ip(p[IPv6].src)
            macs[src_ip].add(src_mac)
            continue

    r2_macs = sorted(macs.get(normalize_ip(R2_IP), set()))
    r3_macs = sorted(macs.get(normalize_ip(R3_IP), set()))
    if r2_macs:
        print(f"R2 at {R2_IP}: {', '.join(r2_macs)}")
    else:
        print(f"R2 at {R2_IP}: nothing found")

    if r3_macs:
        print(f"R3 at {R3_IP}: {', '.join(r3_macs)}")
    else:
        print(f"R3 at {R3_IP}: nothing found")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())