import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

// OUI prefix → vendor (first 3 bytes of MAC)
const OUI_MAP: Record<string, string> = {
  'b8:27:eb': 'Raspberry Pi Foundation',
  'dc:a6:32': 'Raspberry Pi Foundation',
  'e4:5f:01': 'Raspberry Pi Foundation',
  'd8:3a:dd': 'Raspberry Pi Foundation',
  '00:50:56': 'VMware',
  '08:00:27': 'VirtualBox',
  '00:0c:29': 'VMware',
  'ac:de:48': 'Apple',
  '3c:22:fb': 'Apple',
  'f4:5c:89': 'Apple',
  '00:1a:11': 'Google',
  '54:60:09': 'Google',
  'b4:ce:f6': 'Amazon',
  'fc:65:de': 'Amazon',
  '68:37:e9': 'Amazon Echo',
  '74:75:48': 'Ring',
  'b0:09:da': 'Nest/Google',
};

function vendorFromMac(mac: string): string {
  const prefix = mac.toLowerCase().slice(0, 8);
  return OUI_MAP[prefix] ?? 'Unknown';
}

async function nmapProbe(ip: string) {
  try {
    const { stdout } = await execAsync(`nmap -O -T4 --osscan-guess ${ip} 2>/dev/null | head -30`, { timeout: 15000 });
    return stdout;
  } catch { return ''; }
}

async function pingProbe(ip: string) {
  try {
    const { stdout } = await execAsync(`ping -c 1 -W 2 ${ip} 2>/dev/null`);
    return stdout.includes('1 received');
  } catch { return false; }
}

export async function profileDevice(ip: string, mac: string): Promise<any> {
  const vendor = vendorFromMac(mac);
  const alive = await pingProbe(ip);
  const nmapOut = await nmapProbe(ip);

  const osMatch = nmapOut.match(/OS details?:\s*(.+)/i) ?? nmapOut.match(/Running:\s*(.+)/i);
  const portMatches = nmapOut.match(/(\d+)\/(tcp|udp)\s+open\s+([\w-]+)/g) ?? [];
  const openPorts = portMatches.map(p => {
    const [port, , service] = p.split(/[\s/]+/);
    return { port: parseInt(port), service };
  });

  const isPi = vendor.includes('Raspberry Pi') || nmapOut.toLowerCase().includes('raspberry');
  const isCamera = isPi || vendor.includes('Ring') || vendor.includes('Nest') || openPorts.some(p => [554, 8554, 8080].includes(p.port));
  const isRouter = openPorts.some(p => [53, 67, 68].includes(p.port));
  const isPhone = vendor.includes('Apple') || vendor.includes('Samsung') || vendor.includes('Google');

  const deviceType = isPi ? 'Raspberry Pi / SBC' : isCamera ? 'Camera / IoT' : isRouter ? 'Router / Gateway' : isPhone ? 'Mobile Device' : 'Unknown';

  const riskFlags: string[] = [];
  if (isPi) riskFlags.push('Possible surveillance device');
  if (openPorts.some(p => [554, 8554].includes(p.port))) riskFlags.push('RTSP stream detected');
  if (openPorts.some(p => p.port === 22)) riskFlags.push('SSH exposed');
  if (openPorts.some(p => p.port === 23)) riskFlags.push('Telnet exposed');

  return {
    ip, mac, vendor, deviceType, alive,
    os: osMatch?.[1]?.trim() ?? 'Unknown',
    openPorts,
    riskFlags,
    riskLevel: riskFlags.length >= 2 ? 'high' : riskFlags.length === 1 ? 'medium' : 'low',
    profiledAt: new Date().toISOString(),
  };
}
