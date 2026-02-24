#!/usr/bin/env python3
import asyncio
import ipaddress
import json
from typing import Dict, List, Tuple

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    Udp6TransportTarget,
    next_cmd,
)

ROUTERS = {
    "R1": "2001:db8:10::1",
    "R2": "2001:db8:1:0:c802:31ff:feb1:0",
    "R3": "2001:db8:1:0:c803:31ff:fec0:0",
    "R4": "2001:db8:1::1",
    "R5": "2001:db8:1:0:C805:31FF:FEFC:0",
}

SNMP_COMMUNITY = "public"
SNMP_PORT = 161
SNMP_TIMEOUT_SECONDS = 3
SNMP_RETRIES = 2

IF_OPER_STATUS_OID = "1.3.6.1.2.1.2.2.1.8"
IP_ADDR_IFINDEX_OID = "1.3.6.1.2.1.4.34.1.3"
IF_DESCR_OID = "1.3.6.1.2.1.2.2.1.2"
REPORT_FILE = "report.txt"



def get_transport_target(host: str):
    try:
        ip_obj = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        ip_obj = None

    if isinstance(ip_obj, ipaddress.IPv6Address):
        return Udp6TransportTarget((host, SNMP_PORT), SNMP_TIMEOUT_SECONDS, SNMP_RETRIES)

    return UdpTransportTarget((host, SNMP_PORT), SNMP_TIMEOUT_SECONDS, SNMP_RETRIES)



async def snmp_walk(host: str, oid: str) -> List[Tuple[str, str]]:
    rows: List[Tuple[str, str]] = []
    iterator = next_cmd(
        SnmpEngine(),
        CommunityData(SNMP_COMMUNITY, mpModel=1),
        get_transport_target(host),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False,
    )
    async for _, _, _, var_binds in iterator:
        for var_bind in var_binds:
            rows.append((var_bind[0].prettyPrint(), var_bind[1].prettyPrint()))

    return rows


def parse_interface_status(host: str) -> Dict[str, str]:
    descr = snmp_walk(host, IF_DESCR_OID)
    status = snmp_walk(host, IF_OPER_STATUS_OID)

    index: Dict[str, str] = {}
    for oid, value in descr:
        idx = oid.split(".")[-1]
        index[idx] = value

    status_by_index: Dict[str, str] = {}
    translate_status = {"1": "up", "2": "down"}
    for oid, value in status:
        idx = oid.split(".")[-1]
        status_by_index[idx] = translate_status.get(value, "unknown")

    interface_status: Dict[str, str] = {}
    for idx, name in index.items():
        interface_status[name] = status_by_index.get(idx, "unknown")

    return interface_status


def decode_ip(oid: str) -> Tuple[str, str]:
    base = IP_ADDR_IFINDEX_OID + "."
    suffix = oid[len(base) :]
    parts = [int(x) for x in suffix.split(".") if x]

    if len(parts) < 2:
        return "other", ""

    addr_type = parts[0]
    addr_len = parts[1]
    raw = parts[2 : 2 + addr_len]

    if len(raw) != addr_len:
        return "other", ""

    if addr_type == 1 and addr_len == 4:
        return "ipv4", str(ipaddress.IPv4Address(bytes(raw)))
    if addr_type == 2 and addr_len == 16:
        return "ipv6", str(ipaddress.IPv6Address(bytes(raw)))

    return "other", ""


def parse_ip_addresses(host: str) -> Tuple[List[str], List[str]]:
    rows = snmp_walk(host, IP_ADDR_IFINDEX_OID)

    ipv4_addresses = set()
    ipv6_addresses = set()

    for oid, _ in rows:
        try:
            ip_type, ip_text = decode_ip(oid)
        except ValueError:
            continue

        if ip_type == "ipv4":
            ipv4_addresses.add(ip_text)
        elif ip_type == "ipv6":
            ipv6_addresses.add(ip_text)

    return sorted(ipv4_addresses), sorted(ipv6_addresses)


def collect_router_data(host: str) -> Dict[str, object]:
    ipv4_addresses, ipv6_addresses = parse_ip_addresses(host)
    interface_status = parse_interface_status(host)

    return {
        "ipv4_addresses": ipv4_addresses,
        "ipv6_addresses": ipv6_addresses,
        "interface_status": interface_status,
    }


def main() -> int:
    result: Dict[str, object] = {}

    for router_name, host in ROUTERS.items():
        result[router_name] = collect_router_data(host)

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"SNMP data written: {REPORT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
