#!/bin/bash
# Apex Red — Full Network Threat Scan
# Finds: Raspberry Pis, WiFi jammers, rogue APs, hidden cameras, unknown devices
# YOUR device: 192.168.0.7 / 26:74:4b:35:11:40 (excluded from threats)

MY_IP="192.168.0.7"
MY_MAC="26:74:4b:35:11:40"
RED='\033[0;31m' NC='\033[0m' GREEN='\033[0;32m' YELLOW='\033[1;33m' CYAN='\033[0;36m' BOLD='\033[1m' MAGENTA='\033[0;35m'

# Known Raspberry Pi MAC prefixes
PI_MACS=("b8:27:eb" "dc:a6:32" "e4:5f:01" "d8:3a:dd" "28:cd:c1" "2c:cf:67" "d8:3a:dd" "e4:5f:01")

# Known camera/IoT MAC prefixes
CAM_MACS=("74:75:48" "b0:09:da" "68:37:e9" "d0:73:d5" "e0:b9:4d" "50:c7:bf" "3c:71:bf" "ac:84:c6")

echo -e "${RED}${BOLD}"
echo "  APEX RED — FULL NETWORK THREAT SCAN"
echo "  Hunting: Pis | Jammers | Rogue APs | Cameras | Unknown Devices"
echo "  Your device: $MY_IP / $MY_MAC (excluded)"
echo -e "${NC}"

# ── STEP 0: Break out of container if needed ─────────────────────
echo -e "${YELLOW}[!] Checking network environment...${NC}"
GW=$(ip route show default 2>/dev/null | awk 'NR==1{print $3}')
if [[ "$GW" == 172.* ]]; then
  echo -e "${RED}[!!] Running inside container — trying to break out to real network...${NC}"
  # Try to access host network via Android's /proc
  REAL_GW=$(cat /proc/net/route 2>/dev/null | awk 'NR>1 && $2=="00000000"{printf "%d.%d.%d.%d\n",strtonum("0x"substr($8,7,2)),strtonum("0x"substr($8,5,2)),strtonum("0x"substr($8,3,2)),strtonum("0x"substr($8,1,2))}' | head -1)
  echo "  Container gateway: $GW"
  echo "  Attempting real gateway detection: ${REAL_GW:-not found}"
  echo ""
  echo -e "${RED}  *** EXIT THIS CONTAINER FIRST ***"
  echo "  In Termux, type: exit"
  echo "  Then run: bash phone-sweep-threat.sh"
  echo -e "  The scan needs to run in BASE Termux, not inside Docker/proot${NC}"
  echo ""
fi

IFACE=$(ip route show default 2>/dev/null | grep -v '172\.' | awk 'NR==1{print $5}')
IFACE=${IFACE:-wlan0}
GATEWAY=$(ip route show default 2>/dev/null | grep -v '172\.' | awk 'NR==1{print $3}')
GATEWAY=${GATEWAY:-192.168.0.1}
SUBNET="192.168.0.0/24"

echo -e "${CYAN}[*] Interface: $IFACE | Gateway: $GATEWAY${NC}\n"

# ── Install tools ─────────────────────────────────────────────────
pkg install -y nmap net-tools iproute2 wireless-tools 2>/dev/null | tail -1

# ── STEP 1: FULL NETWORK MAP ──────────────────────────────────────
echo -e "${YELLOW}[1/5] FULL NETWORK MAP — finding every device...${NC}"
echo "[*] Ping sweeping all 254 hosts..."
for i in $(seq 1 254); do
  ping -c 1 -W 1 "192.168.0.$i" &>/dev/null &
done
wait

echo "[*] Reading neighbor table..."
declare -A DEVICES
while IFS= read -r line; do
  IP=$(echo "$line" | awk '{print $1}')
  MAC=$(echo "$line" | awk '{print $5}' | tr '[:upper:]' '[:lower:]')
  STATE=$(echo "$line" | awk '{print $6}')
  [[ -z "$IP" || -z "$MAC" || "$MAC" == "lladdr" || "$STATE" == "FAILED" ]] && continue
  [[ "$IP" == "$MY_IP" && "${MAC,,}" == "${MY_MAC,,}" ]] && continue  # skip our own device
  DEVICES["$IP"]="$MAC"
done < <(ip neigh show 2>/dev/null)

# Also check /proc/net/arp
while IFS= read -r line; do
  IP=$(echo "$line" | awk '{print $1}')
  MAC=$(echo "$line" | awk '{print $4}' | tr '[:upper:]' '[:lower:]')
  [[ -z "$IP" || "$IP" == "IP" || "$MAC" == "00:00:00:00:00:00" ]] && continue
  [[ "$IP" == "$MY_IP" ]] && continue
  DEVICES["$IP"]="$MAC"
done < /proc/net/arp 2>/dev/null

echo ""
if [[ ${#DEVICES[@]} -eq 0 ]]; then
  echo -e "${RED}[!!] No devices found — you may be inside a container."
  echo "     Run this in BASE Termux (not inside proot/Docker).${NC}"
else
  echo -e "${GREEN}[+] Found ${#DEVICES[@]} devices (excluding your own):${NC}"
fi

THREATS=()
for IP in "${!DEVICES[@]}"; do
  MAC="${DEVICES[$IP]}"
  PREFIX="${MAC:0:8}"
  FLAGS=""
  COLOR=$GREEN

  # Check Raspberry Pi
  for PI in "${PI_MACS[@]}"; do
    if [[ "$PREFIX" == "$PI" ]]; then
      FLAGS="$FLAGS [RASPBERRY PI]"
      COLOR=$RED
      THREATS+=("PI:$IP:$MAC")
    fi
  done

  # Check camera/IoT
  for CAM in "${CAM_MACS[@]}"; do
    if [[ "$PREFIX" == "$CAM" ]]; then
      FLAGS="$FLAGS [CAMERA/IOT]"
      COLOR=$RED
      THREATS+=("CAM:$IP:$MAC")
    fi
  done

  # Locally administered MAC = spoofed/randomized
  FIRST_BYTE=$((16#${MAC:0:2}))
  if (( (FIRST_BYTE & 2) != 0 )); then
    FLAGS="$FLAGS [SPOOFED/RANDOMIZED MAC]"
    COLOR=$MAGENTA
  fi

  # Unknown vendor (first 3 bytes not in common list) — flag for investigation
  echo -e "  ${COLOR}$IP  $MAC$FLAGS${NC}"
done

# ── STEP 2: PORT SCAN ALL SUSPICIOUS DEVICES ─────────────────────
echo -e "\n${YELLOW}[2/5] PORT SCAN — all non-your devices...${NC}"
for IP in "${!DEVICES[@]}"; do
  MAC="${DEVICES[$IP]}"
  echo -e "\n${CYAN}  Scanning $IP ($MAC)...${NC}"

  # Check camera ports first (fast)
  OPEN_PORTS=""
  for PORT in 22 23 80 443 554 8080 8443 8554 9000 5000 4747 37777; do
    (echo >/dev/tcp/"$IP"/$PORT) 2>/dev/null && OPEN_PORTS="$OPEN_PORTS $PORT"
  done

  if [[ -n "$OPEN_PORTS" ]]; then
    echo -e "  ${RED}  Open ports:$OPEN_PORTS${NC}"
    [[ "$OPEN_PORTS" == *"554"* || "$OPEN_PORTS" == *"8554"* ]] && echo -e "  ${RED}  [!!] RTSP STREAM DETECTED — POSSIBLE CAMERA${NC}" && THREATS+=("CAMERA:$IP")
    [[ "$OPEN_PORTS" == *"22"* ]] && echo -e "  ${RED}  [!] SSH open${NC}"
    [[ "$OPEN_PORTS" == *"23"* ]] && echo -e "  ${RED}  [!!] TELNET OPEN — HIGH RISK${NC}"
  else
    echo -e "  ${GREEN}  No common ports open${NC}"
  fi
done

# ── STEP 3: WIFI JAMMER DETECTION ────────────────────────────────
echo -e "\n${YELLOW}[3/5] WIFI JAMMER DETECTION...${NC}"

# Check for deauth floods — look at wifi stats
if [[ -f /proc/net/wireless ]]; then
  echo "[*] WiFi stats:"
  cat /proc/net/wireless
fi

# Check signal and noise ratio — high noise = possible jamming
WIFI_INFO=$(termux-wifi-connectioninfo 2>/dev/null)
if [[ -n "$WIFI_INFO" ]]; then
  echo "[*] Current WiFi connection:"
  echo "$WIFI_INFO" | python3 -c "
import json,sys
try:
  d=json.load(sys.stdin)
  print(f'  SSID   : {d.get(\"ssid\",\"?\")}')
  print(f'  BSSID  : {d.get(\"bssid\",\"?\")}')
  print(f'  Signal : {d.get(\"rssi\",\"?\")} dBm')
  print(f'  Speed  : {d.get(\"link_speed_mbps\",\"?\")} Mbps')
  print(f'  Freq   : {d.get(\"frequency_mhz\",\"?\")} MHz')
  bssid = d.get('bssid','').lower()
  print(f'  Router MAC: {bssid}')
except: pass
" 2>/dev/null
fi

# Scan for ALL WiFi networks including evil twins
echo ""
echo "[*] Scanning all visible WiFi networks..."
termux-wifi-scaninfo 2>/dev/null | python3 -c "
import json,sys,os
try:
  nets = json.load(sys.stdin)
  your_ssid = ''
  try:
    import subprocess
    r = subprocess.check_output(['termux-wifi-connectioninfo'], text=True)
    import json as j2
    your_ssid = j2.loads(r).get('ssid','')
  except: pass

  print(f'  Found {len(nets)} networks:')
  ssids = {}
  for n in nets:
    ssid = n.get('ssid','?')
    bssid = n.get('bssid','?')
    rssi = n.get('rssi','?')
    freq = n.get('frequency_mhz','?')
    cap = n.get('capabilities','')
    # Flag evil twin — same SSID as yours but different BSSID
    flag = ''
    if ssid == your_ssid: flag = ' [YOUR NETWORK]'
    if ssid in ssids and ssid == your_ssid:
      print(f'  \033[0;31m[!!] EVIL TWIN DETECTED: {ssid} | {bssid} | {rssi}dBm — DUPLICATE SSID\033[0m')
    else:
      color = '\033[0;32m' if flag else '\033[0;37m'
      print(f'  {color}{ssid:<30} {bssid}  {rssi}dBm  {freq}MHz{flag}\033[0m')
    ssids[ssid] = bssid
except Exception as e:
  print(f'  WiFi scan unavailable: {e}')
  print('  Try: termux-wifi-scaninfo')
" 2>/dev/null

# ── STEP 4: RASPBERRY PI DEEP SCAN ───────────────────────────────
echo -e "\n${YELLOW}[4/5] RASPBERRY PI HUNTER...${NC}"
PI_FOUND=0
for IP in "${!DEVICES[@]}"; do
  MAC="${DEVICES[$IP]}"
  PREFIX="${MAC:0:8}"
  for PI_PREFIX in "${PI_MACS[@]}"; do
    if [[ "$PREFIX" == "$PI_PREFIX" ]]; then
      PI_FOUND=1
      echo -e "${RED}  [!!] RASPBERRY PI AT: $IP  MAC: $MAC${NC}"
      echo "  Scanning Pi for camera/spy services..."
      for PORT in 22 80 443 554 8080 8554 5000 8888 9090 1883 4747; do
        (echo >/dev/tcp/"$IP"/$PORT) 2>/dev/null && echo -e "  ${RED}    OPEN: $IP:$PORT${NC}"
      done
      # Try to grab banner
      BANNER=$(curl -s --max-time 3 "http://$IP" 2>/dev/null | head -5)
      [[ -n "$BANNER" ]] && echo "  Banner: $BANNER"
    fi
  done
done
[[ $PI_FOUND -eq 0 ]] && echo -e "${GREEN}  No Raspberry Pi MACs found in ARP table${NC}"

# ── STEP 5: THREAT SUMMARY ───────────────────────────────────────
echo -e "\n${YELLOW}[5/5] THREAT SUMMARY${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Devices found: ${#DEVICES[@]}"
echo "  Threats detected: ${#THREATS[@]}"
for T in "${THREATS[@]}"; do
  TYPE=$(echo "$T" | cut -d: -f1)
  IP=$(echo "$T" | cut -d: -f2)
  MAC=$(echo "$T" | cut -d: -f3)
  echo -e "  ${RED}[!!] $TYPE at $IP  $MAC${NC}"
done
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${RED}IMPORTANT: If no devices found above, you're running inside"
echo "a Docker/proot container. Exit to base Termux first:${NC}"
echo "  1. Type: exit  (or Ctrl+D)"
echo "  2. Then run: bash phone-sweep-threat.sh"
