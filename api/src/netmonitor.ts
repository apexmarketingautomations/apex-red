import { EventEmitter } from 'events';
import { spawn, ChildProcess } from 'child_process';

export const emitter = new EventEmitter();
emitter.setMaxListeners(100);

let proc: ChildProcess | null = null;
let capturing = false;
let currentIface = '';
let packetCount = 0;
let startedAt: string | null = null;

export function getStatus() {
  return { capturing, iface: currentIface, packetCount, startedAt };
}

export function startCapture(iface = 'eth0', filter = '') {
  if (capturing) return;
  const args = ['-i', iface, '-n', '-l', '--immediate-mode', '-tttt'];
  if (filter) args.push(filter);

  proc = spawn('tcpdump', args, { stdio: ['ignore', 'pipe', 'pipe'] });
  capturing = true;
  currentIface = iface;
  startedAt = new Date().toISOString();
  packetCount = 0;

  emitter.emit('status', getStatus());

  let buf = '';
  proc.stdout?.setEncoding('utf8');
  proc.stdout?.on('data', (chunk: string) => {
    buf += chunk;
    const lines = buf.split('\n');
    buf = lines.pop() ?? '';
    for (const line of lines) {
      if (!line.trim()) continue;
      packetCount++;
      const pkt = parseTcpdumpLine(line);
      emitter.emit('packet', pkt);
    }
  });

  proc.stderr?.on('data', (d: Buffer) => {
    const msg = d.toString();
    if (!msg.includes('listening')) {
      emitter.emit('error', { message: msg.trim() });
    }
  });

  proc.on('exit', () => {
    capturing = false;
    proc = null;
    emitter.emit('status', getStatus());
  });
}

export function stopCapture() {
  proc?.kill('SIGTERM');
  capturing = false;
  proc = null;
  emitter.emit('status', getStatus());
}

function parseTcpdumpLine(line: string): object {
  const ipMatch = line.match(/(\d+\.\d+\.\d+\.\d+)\.?(\d+)?\s*>\s*(\d+\.\d+\.\d+\.\d+)\.?(\d+)?/);
  const proto = line.match(/\b(TCP|UDP|ICMP|ARP|DNS)\b/i)?.[1]?.toUpperCase() ?? 'UNKNOWN';
  const length = line.match(/length (\d+)/)?.[1];
  return {
    ts: Date.now(),
    raw: line.slice(0, 120),
    src: ipMatch ? `${ipMatch[1]}${ipMatch[2] ? ':' + ipMatch[2] : ''}` : null,
    dst: ipMatch ? `${ipMatch[3]}${ipMatch[4] ? ':' + ipMatch[4] : ''}` : null,
    proto,
    length: length ? parseInt(length) : null,
  };
}
