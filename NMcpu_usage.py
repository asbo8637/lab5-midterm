#!/usr/bin/env python3
import asyncio
import ipaddress
import time
import matplotlib.pyplot as plt

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    Udp6TransportTarget,
    get_cmd,
)

HOST = "2001:db8:10::1"
COMMUNITY = "public"
CPU_OID = "1.3.6.1.4.1.9.2.1.56.0"
INTERVAL = 5
DURATION = 120


async def get_transport(host):
    try:
        ip = ipaddress.ip_address(host)
        if isinstance(ip, ipaddress.IPv6Address):
            return await Udp6TransportTarget.create((host, 161), timeout=3, retries=2)
    except:
        pass
    return await UdpTransportTarget.create((host, 161), timeout=3, retries=2)


async def get_cpu():
    target = await get_transport(HOST)
    
    err, status, idx, binds = await get_cmd(
        SnmpEngine(),
        CommunityData(COMMUNITY, mpModel=1),
        target,
        ContextData(),
        ObjectType(ObjectIdentity(CPU_OID)),
    )
    
    if err or status or not binds:
        return None
    
    return int(str(binds[0][1]))


async def main():
    times = []
    cpus = []
    
    print(f"Collecting CPU data for {DURATION} seconds")
    start = time.time()
    count = 0
    
    while time.time() - start < DURATION:
        cpu = await get_cpu()
        if cpu:
            t = time.time() - start
            times.append(t)
            cpus.append(cpu)
            count += 1
            print(f"{count}. CPU: {cpu}%")
        
        await asyncio.sleep(INTERVAL)
    
    if not cpus:
        print("No data!")
        return 1
    
    plt.figure(figsize=(10, 6))
    plt.plot(times, cpus, 'b-o')
    plt.xlabel('Time (seconds)')
    plt.ylabel('CPU (%)')
    plt.title('R1 CPU Usage')
    plt.grid(True)
    plt.savefig('cpu_usage.jpg')
    print("Saved cpu_usage.jpg")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
