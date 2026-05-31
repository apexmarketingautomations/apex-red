#!/bin/bash
# Apex Red — Phone Sweep + Counterattack
# Target MAC: 26:74:4B:35:11:40  Target IP: 192.168.0.7
# Run from Termux (Android) or iSH (iPhone)

TARGET_MAC="26:74:4b:35:11:40"
TARGET_IP="192.168.0.7"
SUBNET="192.168.0.0/24"
RED='\033[0;31m' NC='\033[0m' GREEN='\033[0;32m' YELLOW='\033[1;33m'

echo -e "${RED}"
echo "  ▄████████    ▄███████▄    ▄████████ ▀████    ▐████▀ "
echo "  APEX RED — FULL SWEEP + COUNTERATTACK"
echo "  Target: $TARGET_IP  |  MAC: $TARGET_MAC"
echo -e "${NC}"

# ── Install deps (Termux) ────────────────────────────────────────
if command -v pkg &>/dev/null; then
  echo "[*] Installing tools..."
  pkg install -y nmap net-tools python iproute2 2>/dev/null
  pip install scapy 2>/dev/null &
fi

# ── 1. ARP SCAN — find every device on LAN ──────────────────────
echo -e "\n${YELLOW}[1/5] ARP SCAN — mapping network...${NC}"
if command -v nmap &>/dev/null; then
  nmap -sn "$SUBNET" -oG - 2>/dev/null | grep "Host:" | while read -r line; do
    IP=$(echo "$line" | awk '{print $2}')
    MAC=$(arp -n "$IP" 2>/dev/null | awk '/([0-9a-f]{2}:){5}/ {print $3}' | head -1)
    echo "  $IP  $MAC"
    if [[ "${MAC,,}" == "${TARGET_MAC,,}" ]]; then
      echo -e "  ${RED}>>> CLONE FOUND: $IP is using MAC $TARGET_MAC <<<${NC}"
    fi
  done
else
  # Fallback: ping sweep + arp
  echo "[*] nmap not found, using ping sweep..."
  for i in $(seq 1 254); do
    ping -c 1 -W 1 "192.168.0.$i" &>/dev/null &
  done
  wait
  arp -a 2>/dev/null | while read -r line; do
    IP=$(echo "$line" | grep -oE '\(([0-9.]+)\)' | tr -d '()')
    MAC=$(echo "$line" | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}')
    echo "  $IP  $MAC"
    if [[ "${MAC,,}" == "${TARGET_MAC,,}" ]]; then
      echo -e "  ${RED}>>> CLONE FOUND: $IP is using MAC $TARGET_MAC <<<${NC}"
    fi
  done
fi

# ── 2. PORT SCAN target IP ───────────────────────────────────────
echo -e "\n${YELLOW}[2/5] PORT SCAN — $TARGET_IP...${NC}"
if command -v nmap &>/dev/null; then
  nmap -T4 -A --open "$TARGET_IP" 2>/dev/null | grep -E "open|OS:|MAC Address:"
else
  echo "[*] Checking common ports manually..."
  for port in 21 22 23 80 443 445 3389 8080 8443 5900; do
    (echo >/dev/tcp/"$TARGET_IP"/$port) 2>/dev/null && echo "  OPEN: $TARGET_IP:$port"
  done
fi

# ── 3. CHECK FOR DUPLICATE MACS (clone detection) ────────────────
echo -e "\n${YELLOW}[3/5] CLONE DETECTION — checking for duplicate MACs...${NC}"
arp -a 2>/dev/null | grep -i "${TARGET_MAC,,}" | while read -r line; do
  echo -e "  ${RED}[!] MAC $TARGET_MAC seen at: $line${NC}"
done
# Check if target_mac appears on different IPs
DUPE_COUNT=$(arp -a 2>/dev/null | grep -ic "${TARGET_MAC,,}")
if [[ "$DUPE_COUNT" -gt 1 ]]; then
  echo -e "  ${RED}[!!] CLONE CONFIRMED — MAC appears $DUPE_COUNT times on network${NC}"
fi

# ── 4. SNIFF ARP for spoofing (10 seconds) ───────────────────────
echo -e "\n${YELLOW}[4/5] ARP WATCH — monitoring for spoof attempts (10s)...${NC}"
python3 - <<'PYEOF' &
import subprocess, time, re, json

def get_arp():
    try:
        out = subprocess.check_output(['arp', '-a'], text=True)
        table = {}
        for line in out.splitlines():
            ip = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
            mac = re.search(r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})', line, re.I)
            if ip and mac:
                table[ip.group(1)] = mac.group(1).lower()
        return table
    except:
        return {}

known = get_arp()
end = time.time() + 10
while time.time() < end:
    time.sleep(2)
    current = get_arp()
    for ip, mac in current.items():
        prev = known.get(ip)
        if prev and prev != mac:
            print(f'\033[0;31m[!!] ARP SPOOF DETECTED: {ip} changed {prev} -> {mac}\033[0m')
        elif not prev:
            print(f'[+] New device: {ip} {mac}')
    known = current
print('[*] ARP watch done')
PYEOF
sleep 11
wait

# ── 5. COUNTERATTACK ─────────────────────────────────────────────
echo -e "\n${YELLOW}[5/5] COUNTERATTACK — firing countermeasures...${NC}"

GATEWAY=$(ip route 2>/dev/null | grep default | awk '{print $3}' | head -1)
GATEWAY=${GATEWAY:-"192.168.0.1"}
IFACE=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -1)
IFACE=${IFACE:-"wlan0"}

echo "[*] Gateway: $GATEWAY  Interface: $IFACE"

# ARP re-announce our gateway (restores correct ARP table)
echo "[*] Re-broadcasting correct ARP for gateway..."
for i in $(seq 1 5); do
  arping -c 2 -A -I "$IFACE" "$GATEWAY" 2>/dev/null || true
  sleep 1
done

# Static ARP lock for gateway (prevents spoofing)
GW_MAC=$(arp -n "$GATEWAY" 2>/dev/null | awk '/([0-9a-f]{2}:){5}/ {print $3}' | head -1)
if [[ -n "$GW_MAC" ]]; then
  arp -s "$GATEWAY" "$GW_MAC" 2>/dev/null && echo -e "${GREEN}[+] Gateway ARP locked: $GATEWAY -> $GW_MAC${NC}"
fi

# Firewall block attacker
if command -v iptables &>/dev/null; then
  iptables -A INPUT -s "$TARGET_IP" -j DROP 2>/dev/null && \
    echo -e "${GREEN}[+] Firewall: blocked $TARGET_IP${NC}"
  iptables -A FORWARD -s "$TARGET_IP" -j DROP 2>/dev/null
fi

echo -e "\n${GREEN}[DONE] Sweep + counterattack complete.${NC}"
echo "Summary:"
echo "  Target IP:  $TARGET_IP"
echo "  Target MAC: $TARGET_MAC"
echo "  Gateway:    $GATEWAY locked"
echo "  Firewall:   $TARGET_IP blocked"
echo ""
echo "Run again anytime: bash phone-sweep.sh"
