#!/usr/bin/env python3
"""ARP watch — monitors for ARP spoofing/MITM attacks.
Usage: python3 arpwatch.py [gateway_ip] [iface]
Emits JSON lines on stdout.
"""
import sys, json, time, subprocess, re

gateway = sys.argv[1] if len(sys.argv) > 1 else '192.168.0.1'
iface   = sys.argv[2] if len(sys.argv) > 2 else 'eth0'

def emit(event: str, **kwargs):
    print(json.dumps({'event': event, 'ts': time.time(), **kwargs}), flush=True)

def get_arp_table():
    try:
        out = subprocess.check_output(['arp', '-n'], text=True)
        table = {}
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3 and parts[2] not in ('(incomplete)', '<incomplete>'):
                table[parts[0]] = parts[2].lower()
        return table
    except Exception:
        return {}

def get_gateway_mac():
    try:
        out = subprocess.check_output(['arp', '-n', gateway], text=True)
        m = re.search(r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})', out, re.I)
        return m.group(1).lower() if m else None
    except Exception:
        return None

emit('started', gateway=gateway, iface=iface)

# Try scapy first for live sniffing
try:
    from scapy.all import sniff, ARP  # type: ignore

    known_macs: dict = {}

    def handle_arp(pkt):
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # is-at
            ip  = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc.lower()
            prev = known_macs.get(ip)
            if prev and prev != mac:
                emit('spoof_detected', ip=ip, old_mac=prev, new_mac=mac,
                     msg=f'ARP spoof: {ip} changed from {prev} to {mac}')
            else:
                emit('arp_update', ip=ip, mac=mac)
            known_macs[ip] = mac

    emit('mode', value='scapy')
    sniff(filter='arp', prn=handle_arp, store=0, iface=iface)

except ImportError:
    # Fallback: poll arp table every 5 seconds
    emit('mode', value='poll')
    known: dict = get_arp_table()
    gw_mac = get_gateway_mac()

    while True:
        time.sleep(5)
        current = get_arp_table()

        for ip, mac in current.items():
            prev = known.get(ip)
            if prev is None:
                emit('new_device', ip=ip, mac=mac)
            elif prev != mac:
                emit('spoof_detected', ip=ip, old_mac=prev, new_mac=mac,
                     msg=f'ARP spoof: {ip} changed MAC {prev} -> {mac}')

        # Check gateway MAC hasn't changed
        new_gw = get_gateway_mac()
        if gw_mac and new_gw and new_gw != gw_mac:
            emit('spoof_detected', ip=gateway, old_mac=gw_mac, new_mac=new_gw,
                 msg=f'GATEWAY ARP SPOOF DETECTED: {gateway} MAC changed!')
            gw_mac = new_gw

        known = current
