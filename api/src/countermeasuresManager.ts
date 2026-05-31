import { EventEmitter } from 'events';
import { exec, spawn } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export const cmEmitter = new EventEmitter();
cmEmitter.setMaxListeners(100);

let active = false;
let session: any = null;
let honeypotServer: any = null;

export function isActive() { return active; }
export function getSession() { return session; }

function emit(event: string, data: any = {}) {
  cmEmitter.emit('any', { event, ...data });
}

export async function firewallBlock(attackerIp: string, _attackerMac = '') {
  try {
    await execAsync(`iptables -A INPUT -s ${attackerIp} -j DROP && iptables -A FORWARD -s ${attackerIp} -j DROP`);
    emit('firewall_blocked', { ip: attackerIp });
  } catch (e) {
    emit('firewall_error', { error: String(e) });
    throw e;
  }
}

export async function firewallUnblock() {
  try {
    await execAsync(`iptables -F INPUT; iptables -F FORWARD`);
    emit('firewall_unblocked');
  } catch (e) {
    emit('firewall_error', { error: String(e) });
    throw e;
  }
}

export async function nullRoute(attackerIp: string) {
  try {
    await execAsync(`ip route add blackhole ${attackerIp}/32`);
    emit('null_routed', { ip: attackerIp });
  } catch (e) {
    emit('null_route_error', { error: String(e) });
    throw e;
  }
}

export async function nullRouteRemove(attackerIp: string) {
  try {
    await execAsync(`ip route del blackhole ${attackerIp}/32`);
    emit('null_route_removed', { ip: attackerIp });
  } catch (e) { throw e; }
}

export async function staticArpLock(ip: string, mac: string) {
  try {
    await execAsync(`arp -s ${ip} ${mac}`);
    emit('arp_locked', { ip, mac });
  } catch (e) {
    emit('arp_lock_error', { error: String(e) });
    throw e;
  }
}

export function arpFlood(attackerIp: string, attackerMac: string, gatewayIp: string, iface: string) {
  emit('arp_flood_start', { attackerIp, attackerMac });
  let count = 0;
  const interval = setInterval(async () => {
    if (count++ >= 15) { // 30s at 2s interval
      clearInterval(interval);
      emit('arp_flood_done', { attackerIp });
      return;
    }
    try {
      await execAsync(`arping -c 1 -A -I ${iface} ${gatewayIp}`);
    } catch {}
  }, 2000);
}

export function startHoneypot(port: number) {
  const net = require('net');
  if (honeypotServer) return;
  honeypotServer = net.createServer((socket: any) => {
    const remote = socket.remoteAddress;
    emit('honeypot_hit', { ip: remote, port, ts: new Date().toISOString() });
    socket.write('SSH-2.0-OpenSSH_8.9\r\n');
    setTimeout(() => socket.destroy(), 3000);
  });
  honeypotServer.listen(port, () => emit('honeypot_started', { port }));
}

export async function captureEvidence(attackerIp: string) {
  emit('evidence_capture_start', { ip: attackerIp });
  const ts = Date.now();
  const outFile = `/tmp/apex-evidence-${ts}.pcap`;
  const proc = spawn('tcpdump', ['-i', 'any', '-w', outFile, `host ${attackerIp}`, '-G', '60', '-W', '1']);
  proc.on('exit', () => emit('evidence_capture_done', { ip: attackerIp, file: outFile }));
}

export function autoRespond(attackerIp: string, attackerMac: string, gatewayIp: string, iface: string) {
  active = true;
  session = { attackerIp, attackerMac, gatewayIp, iface, startedAt: new Date().toISOString() };
  emit('auto_respond_start', session);

  Promise.all([
    firewallBlock(attackerIp, attackerMac).catch(() => {}),
    nullRoute(attackerIp).catch(() => {}),
    captureEvidence(attackerIp).catch(() => {}),
  ]).then(() => emit('auto_respond_deployed', { attackerIp }));
}

export function stopAll() {
  active = false;
  if (honeypotServer) { honeypotServer.close(); honeypotServer = null; }
  firewallUnblock().catch(() => {});
  emit('all_stopped');
}
