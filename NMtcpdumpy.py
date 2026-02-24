#!/usr/bin/env python3
from collections import defaultdict
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.all import rdpcap

FILE = "ping_capture.pcap"
R2_IP = "2001:DB8:1:0:C802:31FF:FEB1:0"
R3_IP = "2001:DB8:1:0:C803:31FF:FECO:0"

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
            if int(getattr(ic, "type", -1)) == 8:  # echo-request
                src_ip = p[IP].src
                macs[src_ip].add(src_mac)
            continue

        # ICMPv6 echo request (type 128) => Scapy class ICMPv6EchoRequest
        if p.haslayer(IPv6) and p.haslayer(ICMPv6EchoRequest):
            src_ip = p[IPv6].src
            macs[src_ip].add(src_mac)
            continue

    r2_macs = sorted(macs.get(R2_IP, set()))
    r3_macs = sorted(macs.get(R3_IP, set()))
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