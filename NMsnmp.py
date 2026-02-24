#!/usr/bin/env python3
import asyncio
import ipaddress
import json

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



async def get_transport_target(host: str):
    try:
        ip = ipaddress.ip_address(host.split("%")[0])
        is_v6 = isinstance(ip, ipaddress.IPv6Address)
    except:
        is_v6 = False

    if is_v6:
        return await Udp6TransportTarget.create(
            (host, SNMP_PORT), timeout=SNMP_TIMEOUT_SECONDS, retries=SNMP_RETRIES
        )
    else:
        return await UdpTransportTarget.create(
            (host, SNMP_PORT), timeout=SNMP_TIMEOUT_SECONDS, retries=SNMP_RETRIES
        )




async def snmp_walk(host: str, oid: str):
    target = await get_transport_target(host)
    engine = SnmpEngine()
    results = []
    current = oid
    base = oid.split(".")
    
    while True:
        err, status, idx, binds = await next_cmd(
            engine,
            CommunityData(SNMP_COMMUNITY, mpModel=1),
            target,
            ContextData(),
            ObjectType(ObjectIdentity(current)),
            lexicographicMode=False,
        )
        
        if err or status or not binds:
            break
            
        oid_parts = str(binds[0][0]).split(".")
        if oid_parts[:len(base)] != base:
            break
            
        results.append((str(binds[0][0]), str(binds[0][1])))
        current = str(binds[0][0])
    
    return results


async def parse_interface_status(host: str):
    descr = await snmp_walk(host, IF_DESCR_OID)
    status = await snmp_walk(host, IF_OPER_STATUS_OID)

    names = {}
    for oid, val in descr:
        idx = oid.split(".")[-1]
        names[idx] = val

    statuses = {}
    for oid, val in status:
        idx = oid.split(".")[-1]
        if val == "1":
            statuses[idx] = "up"
        elif val == "2":
            statuses[idx] = "down"
        else:
            statuses[idx] = "unknown"

    result = {}
    for idx in names:
        result[names[idx]] = statuses.get(idx, "unknown")
    
    return result


def decode_ip(oid: str):
    suffix = oid.replace(IP_ADDR_IFINDEX_OID + ".", "")
    parts = [int(x) for x in suffix.split(".") if x]

    if len(parts) < 2:
        return None

    type_val = parts[0]
    length = parts[1]
    addr_bytes = parts[2:2+length]

    if len(addr_bytes) != length:
        return None

    if type_val == 1 and length == 4:
        return str(ipaddress.IPv4Address(bytes(addr_bytes)))
    elif type_val == 2 and length == 16:
        return str(ipaddress.IPv6Address(bytes(addr_bytes)))
    
    return None


async def parse_ip_addresses(host: str):
    rows = await snmp_walk(host, IP_ADDR_IFINDEX_OID)

    v4 = []
    v6 = []

    for oid, _ in rows:
        try:
            addr = decode_ip(oid)
            if addr:
                if ":" in addr:
                    v6.append(addr)
                else:
                    v4.append(addr)
        except:
            pass

    return sorted(set(v4)), sorted(set(v6))


async def collect_router_data(host: str):
    v4, v6 = await parse_ip_addresses(host)
    interfaces = await parse_interface_status(host)

    return {
        "ipv4_addresses": v4,
        "ipv6_addresses": v6,
        "interface_status": interfaces,
    }


async def main():
    data = {}
    
    for name, host in ROUTERS.items():
        data[name] = await collect_router_data(host)

    with open(REPORT_FILE, "w") as f:
        json.dump(data, f, indent=2)

    print(f"SNMP data written: {REPORT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
