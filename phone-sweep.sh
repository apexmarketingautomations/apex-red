#!/bin/bash
# Apex Red — Full Sweep + Geo Trace + Threat Intel
# Target: 192.168.0.7 | MAC: 26:74:4B:35:11:40
# Optimized for Termux on Android

TARGET_MAC="26:74:4b:35:11:40"
TARGET_IP="192.168.0.7"
RED='\033[0;31m' NC='\033[0m' GREEN='\033[0;32m' YELLOW='\033[1;33m' CYAN='\033[0;36m' BOLD='\033[1m'

echo -e "${RED}${BOLD}"
echo "  ▄████████    ▄███████▄    ▄████████ "
echo "  APEX RED — SWEEP + GEO TRACE + THREAT INTEL"
echo "  Target: $TARGET_IP  |  MAC: $TARGET_MAC"
echo -e "${NC}"

# ── Install deps ─────────────────────────────────────────────────
echo "[*] Checking tools..."
pkg install -y nmap net-tools iproute2 python traceroute dnsutils 2>/dev/null | grep -v "^W:"
pip install -q requests 2>/dev/null

# ── Detect real network interface ────────────────────────────────
# Force wlan0 on Android, fallback to default route interface
IFACE=$(ip route show default 2>/dev/null | grep -v '172\.' | awk 'NR==1 {print $5}')
IFACE=${IFACE:-wlan0}
GATEWAY=$(ip route show default 2>/dev/null | grep -v '172\.' | awk 'NR==1 {print $3}')
GATEWAY=${GATEWAY:-192.168.0.1}
MY_IP=$(ip addr show "$IFACE" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1)
SUBNET=$(ip route show dev "$IFACE" 2>/dev/null | grep -v default | grep '192.168' | awk '{print $1}' | head -1)
SUBNET=${SUBNET:-192.168.0.0/24}

echo -e "${CYAN}[*] Interface: $IFACE | Gateway: $GATEWAY | My IP: $MY_IP | Subnet: $SUBNET${NC}"

# ── 0. YOUR PUBLIC IP + GEO ───────────────────────────────────────
echo -e "\n${YELLOW}[0/6] YOUR PUBLIC IP + GEO LOCATION...${NC}"
PUBLIC_IP=$(curl -s --max-time 5 https://api.ipify.org)
if [[ -n "$PUBLIC_IP" ]]; then
  echo -e "  ${GREEN}Public IP: $PUBLIC_IP${NC}"
  GEO=$(curl -s --max-time 5 "http://ip-api.com/json/$PUBLIC_IP?fields=country,regionName,city,isp,org,as,proxy,hosting,mobile")
  echo "$GEO" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Country : {d.get(\"country\",\"?\")}')
print(f'  Region  : {d.get(\"regionName\",\"?\")}')
print(f'  City    : {d.get(\"city\",\"?\")}')
print(f'  ISP     : {d.get(\"isp\",\"?\")}')
print(f'  Org     : {d.get(\"org\",\"?\")}')
print(f'  AS      : {d.get(\"as\",\"?\")}')
print(f'  Proxy   : {d.get(\"proxy\",False)}')
print(f'  Hosting : {d.get(\"hosting\",False)}')
" 2>/dev/null || echo "$GEO"
else
  echo "  Could not get public IP"
fi

# ── 1. ARP SCAN ───────────────────────────────────────────────────
echo -e "\n${YELLOW}[1/6] ARP SCAN — mapping $SUBNET...${NC}"
FOUND_IPS=()

# Ping sweep first to populate ARP table (works without root)
echo "[*] Ping sweeping $SUBNET..."
for i in $(seq 1 254); do
  ping -c 1 -W 1 "192.168.0.$i" &>/dev/null &
done
wait
echo "[*] Reading ARP table..."

# Use ip neigh (works on Android without root)
ip neigh show 2>/dev/null | while read -r IP _ _ _ MAC STATE; do
  [[ "$STATE" == "FAILED" || -z "$IP" || -z "$MAC" ]] && continue
  FOUND_IPS+=("$IP")
  if [[ "${MAC,,}" == "${TARGET_MAC,,}" ]]; then
    echo -e "  ${RED}[!!] TARGET MAC FOUND: $IP -> $MAC  STATE:$STATE${NC}"
  else
    echo -e "  ${GREEN}$IP${NC}  $MAC  $STATE"
  fi
done

# Also dump full ip neigh for visibility
echo ""
echo "[*] Full neighbor table:"
ip neigh show 2>/dev/null | grep -v FAILED

# ── 2. PORT SCAN TARGET ───────────────────────────────────────────
echo -e "\n${YELLOW}[2/6] PORT SCAN — $TARGET_IP...${NC}"
if command -v nmap &>/dev/null; then
  nmap -T4 -A --open -p 1-1000 "$TARGET_IP" 2>/dev/null | grep -E "open|MAC Address:|OS details:|Service Info:" | while read -r line; do
    echo -e "  ${RED}$line${NC}"
  done
else
  for port in 21 22 23 25 80 443 445 3389 5900 8080 8443; do
    (echo >/dev/tcp/"$TARGET_IP"/$port) 2>/dev/null && echo -e "  ${RED}OPEN: $TARGET_IP:$port${NC}"
  done
fi

# ── 3. CLONE DETECTION ────────────────────────────────────────────
echo -e "\n${YELLOW}[3/6] CLONE DETECTION...${NC}"
# Check ip neigh for target MAC
CLONE_IPS=$(ip neigh show 2>/dev/null | grep -i "$TARGET_MAC" | awk '{print $1}')
COUNT=0
while IFS= read -r ip; do [[ -n "$ip" ]] && ((COUNT++)); done <<< "$CLONE_IPS"

if [[ "$COUNT" -gt 1 ]]; then
  echo -e "  ${RED}[!!] CLONE CONFIRMED — MAC $TARGET_MAC on multiple IPs:${NC}"
  echo "$CLONE_IPS" | while read -r ip; do [[ -n "$ip" ]] && echo -e "  ${RED}  -> $ip${NC}"; done
elif [[ "$COUNT" -eq 1 ]]; then
  echo -e "  ${GREEN}[OK] MAC $TARGET_MAC seen once at: $CLONE_IPS${NC}"
else
  echo -e "  [?] MAC $TARGET_MAC not seen — device offline, or using MAC randomization"
fi

# Check for ANY duplicate MACs across the whole table (catches clones of other devices too)
echo ""
echo "[*] Checking ALL MACs for duplicates..."
ip neigh show 2>/dev/null | grep -v FAILED | awk '{print $5}' | sort | uniq -d | while read -r dup; do
  [[ -z "$dup" || "$dup" == "lladdr" ]] && continue
  IPS=$(ip neigh show 2>/dev/null | grep -i "$dup" | awk '{print $1}' | tr '\n' ' ')
  echo -e "  ${RED}[!!] DUPLICATE MAC: $dup seen on IPs: $IPS${NC}"
done

# ── 4. GEO TRACE — traceroute + geolocate every hop ─────────────
echo -e "\n${YELLOW}[4/6] GEO TRACE to $TARGET_IP (then external)...${NC}"

python3 - "$TARGET_IP" "$PUBLIC_IP" <<'PYEOF'
import subprocess, sys, re, json
try:
    from urllib.request import urlopen
    from urllib.parse import quote
except:
    sys.exit(0)

target = sys.argv[1] if len(sys.argv) > 1 else '8.8.8.8'

def geo(ip):
    try:
        url = f'http://ip-api.com/json/{ip}?fields=country,city,isp,org,proxy,hosting'
        r = urlopen(url, timeout=3)
        d = json.loads(r.read())
        return f"{d.get('city','?')}, {d.get('country','?')} | {d.get('isp','?')}" + (' [PROXY]' if d.get('proxy') else '') + (' [HOSTING]' if d.get('hosting') else '')
    except:
        return '?'

def traceroute(host):
    try:
        out = subprocess.check_output(['traceroute', '-m', '15', '-w', '2', host],
                                      stderr=subprocess.DEVNULL, text=True, timeout=30)
        return out
    except:
        return ''

print(f'\n  Tracing route to {target}...')
tr = traceroute(target)
if tr:
    ips_seen = []
    for line in tr.splitlines():
        ips = re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', line)
        for ip in ips:
            if ip not in ips_seen and not ip.startswith('192.168') and not ip.startswith('10.') and not ip.startswith('172.'):
                ips_seen.append(ip)
        if ips:
            g = geo(ips[-1]) if ips else ''
            print(f'  {line.strip():<50} {g}')
        else:
            print(f'  {line.strip()}')

# Also trace outbound to google to see full path
print(f'\n  Tracing outbound path (8.8.8.8)...')
tr2 = traceroute('8.8.8.8')
seen = set()
for line in tr2.splitlines()[1:]:
    ips = re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', line)
    for ip in ips:
        if ip not in seen and not ip.startswith(('192.168','10.','172.')):
            seen.add(ip)
            g = geo(ip)
            print(f'  {ip:<18} {g}')
PYEOF

# ── 5. THREAT INTEL — check all discovered IPs ───────────────────
echo -e "\n${YELLOW}[5/6] THREAT INTEL — checking all LAN IPs + public IP...${NC}"
python3 - "${FOUND_IPS[@]}" "$PUBLIC_IP" <<'PYEOF'
import sys, json, time
from urllib.request import urlopen

ips = list(set(sys.argv[1:]))
suspicious = []

for ip in ips:
    if not ip or ip.startswith(('192.168','10.','172.')):
        continue
    try:
        url = f'http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,proxy,hosting,mobile,query'
        r = urlopen(url, timeout=3)
        d = json.loads(r.read())
        flags = []
        if d.get('proxy'): flags.append('PROXY')
        if d.get('hosting'): flags.append('HOSTING/VPN')
        if flags:
            suspicious.append(ip)
            print(f'  \033[0;31m[SUSPICIOUS] {ip} — {d.get("city")}, {d.get("country")} | {d.get("isp")} | {" ".join(flags)}\033[0m')
        else:
            print(f'  \033[0;32m[CLEAN] {ip} — {d.get("city","?")}, {d.get("country","?")} | {d.get("isp","?")}\033[0m')
        time.sleep(0.5)
    except Exception as e:
        print(f'  [?] {ip} — lookup failed')

if suspicious:
    print(f'\n  \033[0;31m[!!] {len(suspicious)} suspicious external IPs detected: {", ".join(suspicious)}\033[0m')
PYEOF

# ── 6. COUNTERATTACK ─────────────────────────────────────────────
echo -e "\n${YELLOW}[6/6] COUNTERATTACK — locking down...${NC}"

# Re-announce correct gateway ARP
echo "[*] Locking gateway ARP ($GATEWAY)..."
for i in $(seq 1 5); do
  arping -c 2 -A -I "$IFACE" "$GATEWAY" 2>/dev/null || true
  sleep 1
done

# Static ARP lock for gateway
GW_MAC=$(arp -n "$GATEWAY" 2>/dev/null | awk '/([0-9a-f]{2}:){5}/ {print $3}' | head -1)
[[ -n "$GW_MAC" ]] && arp -s "$GATEWAY" "$GW_MAC" 2>/dev/null && echo -e "${GREEN}[+] ARP locked: $GATEWAY -> $GW_MAC${NC}"

# Block attacker
iptables -A INPUT -s "$TARGET_IP" -j DROP 2>/dev/null && echo -e "${GREEN}[+] Firewall blocked $TARGET_IP${NC}"
iptables -A FORWARD -s "$TARGET_IP" -j DROP 2>/dev/null

echo -e "\n${GREEN}${BOLD}[DONE] Full sweep complete.${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Public IP : $PUBLIC_IP"
echo "  Target    : $TARGET_IP blocked"
echo "  Gateway   : $GATEWAY locked"
echo "  Interface : $IFACE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Run again: bash phone-sweep.sh"
# This file was already rewritten — see Write below
