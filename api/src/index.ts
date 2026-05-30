import express from 'express';
import cors from 'cors';
import { v4 as uuid } from 'uuid';
import pg from 'pg';
import { runScan } from './scanner.js';
import { generateReport } from './aiReport.js';
import { startCapture, stopCapture, getStatus, emitter as monitorEmitter } from './netmonitor.js';
import { startMitm, stopMitm, getMitmSession, isMitming, mitmEmitter } from './mitmManager.js';
import { profileDevice } from './deviceProfiler.js';
import { probeLink }    from './linkProbe.js';
import {
  autoRespond, firewallBlock, firewallUnblock, nullRoute, nullRouteRemove,
  staticArpLock, arpFlood, startHoneypot, captureEvidence, stopAll,
  getSession as getCmSession, isActive as isCmActive, cmEmitter,
} from './countermeasuresManager.js';
import {
  startEvilTwin, stopEvilTwin, getEvilTwinSession, isEvilTwinActive, etEmitter,
  setAutoMode, getAutoMode, visitLog,
} from './evilTwin.js';
import { spawn as spawnProc } from 'child_process';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── ARP Watch singleton ────────────────────────────────────────
import { EventEmitter } from 'events';
const arpWatchEmitter = new EventEmitter();
arpWatchEmitter.setMaxListeners(100);
let arpWatchProc: import('child_process').ChildProcess | null = null;

function startArpWatch(gateway = '192.168.0.1', iface = 'en0') {
  if (arpWatchProc) return;
  arpWatchProc = spawnProc('python3', [path.join(__dirname, 'arpwatch.py'), gateway, iface]);
  let buf = '';
  arpWatchProc.stdout?.setEncoding('utf8');
  arpWatchProc.stdout?.on('data', (chunk: string) => {
    buf += chunk;
    const lines = buf.split('\n');
    buf = lines.pop() ?? '';
    for (const line of lines) {
      try {
        const d = JSON.parse(line.trim());
        arpWatchEmitter.emit(d.event, d);
        arpWatchEmitter.emit('any', d);
        // Log critical alerts to console
        if (d.event === 'spoof_detected') console.warn('[ARP ALERT]', d.msg);
      } catch {}
    }
  });
  arpWatchProc.on('exit', () => { arpWatchProc = null; });
}

// Auto-start ARP watch on boot
startArpWatch();
import { config } from 'dotenv';
config();

const app = express();
app.use(cors());
app.use(express.json());

const DB = process.env.DATABASE_URL ?? 'postgresql://apexmarketingautomations@localhost:5432/apexred';
const pool = new pg.Pool({ connectionString: DB });

// SSE clients per investigation
const sseClients = new Map<string, Set<express.Response>>();

// Event replay buffer — keeps last 500 events per investigation
const sseReplay = new Map<string, Array<{ event: string; data: unknown; ts: number }>>();

export function broadcast(invId: string, event: string, data: unknown) {
  // Store in replay buffer
  if (!sseReplay.has(invId)) sseReplay.set(invId, []);
  const buf = sseReplay.get(invId)!;
  buf.push({ event, data, ts: Date.now() });
  if (buf.length > 500) buf.splice(0, buf.length - 500);

  const clients = sseClients.get(invId);
  if (!clients?.size) return;
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of clients) res.write(payload);
}

export { pool };

// ── Investigations ─────────────────────────────────────────────
app.get('/api/investigations', async (_req, res) => {
  const { rows } = await pool.query(`
    SELECT i.*,
      COUNT(DISTINCT e.id)  AS entity_count,
      COUNT(DISTINCT f.id)  AS finding_count,
      COUNT(DISTINCT f.id) FILTER (WHERE f.severity='critical') AS critical_count,
      COUNT(DISTINCT f.id) FILTER (WHERE f.severity='high')     AS high_count
    FROM investigations i
    LEFT JOIN entities e ON e.investigation_id = i.id
    LEFT JOIN findings f ON f.investigation_id = i.id
    GROUP BY i.id
    ORDER BY i.created_at DESC
  `);
  res.json(rows);
});

app.post('/api/investigations', async (req, res) => {
  try {
    const { name, seeds, depth, modules } = req.body;
    const invId = uuid();

    await pool.query(
      `INSERT INTO investigations (id, name, status, config) VALUES ($1,$2,'pending',$3)`,
      [invId, name, JSON.stringify({ seeds, depth, modules })]
    );

    for (const s of seeds) {
      await pool.query(
        `INSERT INTO entities (investigation_id, type, value, is_seed, confidence)
         VALUES ($1,$2,$3,true,1.0) ON CONFLICT DO NOTHING`,
        [invId, s.type, s.value]
      );
    }

    await pool.query(`UPDATE investigations SET status='running', started_at=NOW() WHERE id=$1`, [invId]);
    res.json({ id: invId, status: 'running' });

    // Fire scan in background — non-blocking
    runScan(invId, seeds, depth ?? 'standard', modules ?? {}, broadcast).catch(err => {
      console.error('Scan error:', err);
      pool.query(`UPDATE investigations SET status='failed' WHERE id=$1`, [invId]);
      broadcast(invId, 'status', { status: 'failed', error: String(err) });
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err) });
  }
});

app.get('/api/investigations/:id', async (req, res) => {
  const { id } = req.params;
  const [inv, entities, relationships, findings, evidence, modules, scores] = await Promise.all([
    pool.query(`SELECT * FROM investigations WHERE id=$1`, [id]),
    pool.query(`SELECT e.*, r.overall AS risk_overall FROM entities e
                LEFT JOIN risk_scores r ON r.entity_id = e.id
                WHERE e.investigation_id=$1`, [id]),
    pool.query(`SELECT * FROM relationships WHERE investigation_id=$1`, [id]),
    pool.query(`SELECT f.*, e.type as entity_type, e.value as entity_value
                FROM findings f LEFT JOIN entities e ON e.id=f.entity_id
                WHERE f.investigation_id=$1
                ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                  WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END`, [id]),
    pool.query(`SELECT * FROM evidence WHERE investigation_id=$1 ORDER BY timestamp DESC`, [id]),
    pool.query(`SELECT * FROM module_runs WHERE investigation_id=$1`, [id]),
    pool.query(`SELECT r.*, e.type, e.value FROM risk_scores r
                JOIN entities e ON e.id=r.entity_id
                WHERE r.investigation_id=$1 ORDER BY r.overall DESC`, [id]),
  ]);
  if (!inv.rows.length) return res.status(404).json({ error: 'Not found' });
  res.json({ ...inv.rows[0], entities: entities.rows, relationships: relationships.rows,
    findings: findings.rows, evidence: evidence.rows, modules: modules.rows, riskScores: scores.rows });
});

app.delete('/api/investigations/:id', async (req, res) => {
  await pool.query(`DELETE FROM investigations WHERE id=$1`, [req.params.id]);
  res.json({ deleted: true });
});

app.post('/api/investigations/:id/pause', async (req, res) => {
  await pool.query(`UPDATE investigations SET status='paused' WHERE id=$1`, [req.params.id]);
  broadcast(req.params.id, 'status', { status: 'paused' });
  res.json({ status: 'paused' });
});

app.post('/api/investigations/:id/resume', async (req, res) => {
  await pool.query(`UPDATE investigations SET status='running' WHERE id=$1`, [req.params.id]);
  broadcast(req.params.id, 'status', { status: 'running' });
  res.json({ status: 'running' });
});

app.get('/api/investigations/:id/graph', async (req, res) => {
  const [entities, relationships] = await Promise.all([
    pool.query(`SELECT e.*, r.overall AS risk_overall FROM entities e
                LEFT JOIN risk_scores r ON r.entity_id=e.id
                WHERE e.investigation_id=$1`, [req.params.id]),
    pool.query(`SELECT * FROM relationships WHERE investigation_id=$1`, [req.params.id]),
  ]);
  res.json({ nodes: entities.rows, edges: relationships.rows });
});

app.get('/api/investigations/:id/findings', async (req, res) => {
  const { severity, category, module } = req.query as Record<string, string>;
  let q = `SELECT f.*, e.type as entity_type, e.value as entity_value
           FROM findings f LEFT JOIN entities e ON e.id=f.entity_id
           WHERE f.investigation_id=$1`;
  const p: unknown[] = [req.params.id];
  if (severity) { q += ` AND f.severity=$${p.length+1}`; p.push(severity); }
  if (category) { q += ` AND f.category=$${p.length+1}`; p.push(category); }
  if (module)   { q += ` AND f.module=$${p.length+1}`;   p.push(module); }
  q += ` ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
           WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END`;
  const { rows } = await pool.query(q, p);
  res.json(rows);
});

app.get('/api/investigations/:id/evidence', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM evidence WHERE investigation_id=$1 ORDER BY timestamp DESC`,
    [req.params.id]
  );
  res.json(rows);
});

app.get('/api/investigations/:id/report', async (req, res) => {
  const { rows } = await pool.query(`SELECT ai_report, name, status FROM investigations WHERE id=$1`, [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Not found' });

  // Auto-generate if not yet done and scan is complete
  if (!rows[0].ai_report && rows[0].status === 'completed') {
    try {
      const report = await generateReport(req.params.id);
      if (req.query.format === 'md') {
        res.setHeader('Content-Type', 'text/markdown');
        res.setHeader('Content-Disposition', `attachment; filename="apex-red-${req.params.id}.md"`);
        return res.send(report);
      }
      return res.json({ report, name: rows[0].name });
    } catch (e) {
      return res.status(500).json({ error: String(e) });
    }
  }

  if (req.query.format === 'md') {
    res.setHeader('Content-Type', 'text/markdown');
    res.setHeader('Content-Disposition', `attachment; filename="apex-red-${req.params.id}.md"`);
    return res.send(rows[0].ai_report ?? '# Report not yet generated');
  }
  res.json({ report: rows[0].ai_report, name: rows[0].name });
});

// SSE live feed
app.get('/api/investigations/:id/live', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();
  const { id } = req.params;

  // Replay buffered events so late-connecting clients see the full history
  const buf = sseReplay.get(id) ?? [];
  for (const e of buf) {
    res.write(`event: ${e.event}\ndata: ${JSON.stringify({ ...e.data as object, _replayed: true, _ts: e.ts })}\n\n`);
  }

  if (!sseClients.has(id)) sseClients.set(id, new Set());
  sseClients.get(id)!.add(res);
  const hb = setInterval(() => res.write(': ping\n\n'), 15000);
  req.on('close', () => { clearInterval(hb); sseClients.get(id)?.delete(res); });
});

// ── Network Monitor ────────────────────────────────────────────
app.get('/api/netmonitor/status', (_req, res) => {
  res.json(getStatus());
});

app.post('/api/netmonitor/start', (req, res) => {
  const { iface = 'en0', filter = '' } = req.body ?? {};
  try {
    startCapture(iface, filter);
    res.json({ ok: true, ...getStatus() });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.post('/api/netmonitor/stop', (_req, res) => {
  stopCapture();
  res.json({ ok: true, ...getStatus() });
});

// SSE stream — sends packet events in real time
app.get('/api/netmonitor/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  // Send current status immediately
  res.write(`event: status\ndata: ${JSON.stringify(getStatus())}\n\n`);

  const onPacket = (pkt: unknown) => {
    res.write(`event: packet\ndata: ${JSON.stringify(pkt)}\n\n`);
  };
  const onStatus = (s: unknown) => {
    res.write(`event: status\ndata: ${JSON.stringify(s)}\n\n`);
  };
  const onError = (e: unknown) => {
    res.write(`event: error\ndata: ${JSON.stringify(e)}\n\n`);
  };

  monitorEmitter.on('packet', onPacket);
  monitorEmitter.on('status', onStatus);
  monitorEmitter.on('error', onError);

  const hb = setInterval(() => res.write(': ping\n\n'), 15000);
  req.on('close', () => {
    clearInterval(hb);
    monitorEmitter.off('packet', onPacket);
    monitorEmitter.off('status', onStatus);
    monitorEmitter.off('error', onError);
  });
});

// ── ARP Watch / Spoof Detection ───────────────────────────────
app.get('/api/arpwatch/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const onAny = (d: unknown) => {
    const data = d as any;
    res.write(`event: ${data.event ?? 'update'}\ndata: ${JSON.stringify(d)}\n\n`);
  };
  arpWatchEmitter.on('any', onAny);
  const hb = setInterval(() => res.write(': ping\n\n'), 15000);
  req.on('close', () => { clearInterval(hb); arpWatchEmitter.off('any', onAny); });
});

// ── MITM / ARP Spoof ──────────────────────────────────────────
app.get('/api/mitm/status', (_req, res) => {
  res.json({ active: isMitming(), session: getMitmSession() });
});

app.post('/api/mitm/start', (req, res) => {
  const { targetIp, gatewayIp = '192.168.0.1', iface = 'en0' } = req.body ?? {};
  if (!targetIp) return res.status(400).json({ error: 'targetIp required' });
  try {
    startMitm(targetIp, gatewayIp, iface);
    res.json({ ok: true, session: getMitmSession() });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.post('/api/mitm/stop', (_req, res) => {
  stopMitm();
  res.json({ ok: true });
});

// SSE stream for MITM events
app.get('/api/mitm/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  res.write(`event: status\ndata: ${JSON.stringify({ active: isMitming(), session: getMitmSession() })}\n\n`);

  const onAny = (data: unknown) => {
    const d = data as any;
    res.write(`event: ${d.event ?? 'update'}\ndata: ${JSON.stringify(d)}\n\n`);
  };

  mitmEmitter.on('any', onAny);
  const hb = setInterval(() => res.write(': ping\n\n'), 15000);
  req.on('close', () => { clearInterval(hb); mitmEmitter.off('any', onAny); });
});

// ── Link Probe ─────────────────────────────────────────────────
app.post('/api/probe', async (req, res) => {
  const { url } = req.body ?? {};
  if (!url) return res.status(400).json({ error: 'url required' });
  try {
    const report = await probeLink(url);
    res.json(report);
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// ── Device Profiler ────────────────────────────────────────────
app.post('/api/profile', async (req, res) => {
  const { ip, mac } = req.body ?? {};
  if (!ip || !mac) return res.status(400).json({ error: 'ip and mac required' });
  try {
    const brief = await profileDevice(ip, mac);
    res.json(brief);
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// ── Countermeasures ────────────────────────────────────────────
app.get('/api/countermeasures/status', (_req, res) => {
  res.json({ active: isCmActive(), session: getCmSession() });
});

app.post('/api/countermeasures/auto', async (req, res) => {
  const { attackerIp, attackerMac, gatewayIp = '192.168.0.1', iface = 'en0' } = req.body ?? {};
  if (!attackerIp || !attackerMac) return res.status(400).json({ error: 'attackerIp and attackerMac required' });
  autoRespond(attackerIp, attackerMac, gatewayIp, iface);
  res.json({ ok: true, msg: 'Auto-response launched' });
});

app.post('/api/countermeasures/firewall_block', async (req, res) => {
  const { attackerIp, attackerMac = '' } = req.body ?? {};
  if (!attackerIp) return res.status(400).json({ error: 'attackerIp required' });
  try { await firewallBlock(attackerIp, attackerMac); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/countermeasures/firewall_unblock', async (_req, res) => {
  try { await firewallUnblock(); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/countermeasures/null_route', async (req, res) => {
  const { attackerIp } = req.body ?? {};
  if (!attackerIp) return res.status(400).json({ error: 'attackerIp required' });
  try { await nullRoute(attackerIp); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/countermeasures/null_route_remove', async (req, res) => {
  const { attackerIp } = req.body ?? {};
  if (!attackerIp) return res.status(400).json({ error: 'attackerIp required' });
  try { await nullRouteRemove(attackerIp); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/countermeasures/arp_lock', async (req, res) => {
  const { ip, mac } = req.body ?? {};
  if (!ip || !mac) return res.status(400).json({ error: 'ip and mac required' });
  try { await staticArpLock(ip, mac); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: String(e) }); }
});

app.post('/api/countermeasures/arp_flood', async (req, res) => {
  const { attackerIp, attackerMac, gatewayIp = '192.168.0.1', iface = 'en0' } = req.body ?? {};
  if (!attackerIp || !attackerMac) return res.status(400).json({ error: 'attackerIp and attackerMac required' });
  arpFlood(attackerIp, attackerMac, gatewayIp, iface);
  res.json({ ok: true, msg: 'ARP flood started (30s)' });
});

app.post('/api/countermeasures/honeypot', async (req, res) => {
  const { port = 2222 } = req.body ?? {};
  startHoneypot(Number(port));
  res.json({ ok: true, msg: `Honeypot started on port ${port}` });
});

app.post('/api/countermeasures/evidence', async (req, res) => {
  const { attackerIp } = req.body ?? {};
  if (!attackerIp) return res.status(400).json({ error: 'attackerIp required' });
  captureEvidence(attackerIp).catch(() => {});
  res.json({ ok: true, msg: 'Evidence capture started (60s)' });
});

app.post('/api/countermeasures/stop_all', (_req, res) => {
  stopAll();
  res.json({ ok: true });
});

// SSE stream for countermeasures events
app.get('/api/countermeasures/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  res.write(`event: status\ndata: ${JSON.stringify({ active: isCmActive(), session: getCmSession() })}\n\n`);

  const onAny = (data: unknown) => {
    const d = data as any;
    res.write(`event: ${d.event ?? 'update'}\ndata: ${JSON.stringify(d)}\n\n`);
  };
  cmEmitter.on('any', onAny);
  const hb = setInterval(() => res.write(': ping\n\n'), 15000);
  req.on('close', () => { clearInterval(hb); cmEmitter.off('any', onAny); });
});

// ── Evil Twin AP ───────────────────────────────────────────────
app.get('/api/eviltwin/status', (_req, res) => {
  res.json({ active: isEvilTwinActive(), session: getEvilTwinSession() });
});

app.post('/api/eviltwin/start', async (req, res) => {
  const { ssid = 'Connected Network', password = '' } = req.body ?? {};
  if (isEvilTwinActive()) return res.status(409).json({ error: 'Evil twin already running' });
  try {
    await startEvilTwin(ssid, password);
    res.json({ ok: true, session: getEvilTwinSession() });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

app.post('/api/eviltwin/stop', async (req, res) => {
  const permanent = req.body?.permanent !== false; // default true — disable auto-mode too
  try {
    const ended = isEvilTwinActive() ? await stopEvilTwin(permanent) : null;
    if (permanent) setAutoMode(false, '');
    res.json({ ok: true, session: ended });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// ── Auto-mode (always-on) ──────────────────────────────────────
app.post('/api/eviltwin/automode', async (req, res) => {
  const { enabled, ssid = 'Connected Network', password = '' } = req.body ?? {};
  setAutoMode(!!enabled, ssid, password);
  res.json({ ok: true, autoMode: getAutoMode() });
});

app.get('/api/eviltwin/automode', (_req, res) => {
  res.json(getAutoMode());
});

// ── Visit log ──────────────────────────────────────────────────
app.get('/api/eviltwin/visits', (_req, res) => {
  res.json(visitLog.slice().reverse()); // newest first
});

// ── macOS native notification ─────────────────────────────────
app.post('/api/eviltwin/notify', (req, res) => {
  const { title = 'Apex Red', body = '' } = req.body ?? {};
  // Trigger macOS notification via osascript (silent, no sound)
  spawnProc('osascript', [
    '-e', `display notification "${body.replace(/"/g, "'")}" with title "${title.replace(/"/g, "'")}"`,
  ]);
  res.json({ ok: true });
});

// ── Auto macOS notifications for critical evil twin events ─────
etEmitter.on('any', (data: any) => {
  if (data.event === 'camera_app_detected') {
    spawnProc('osascript', ['-e',
      `display notification "Camera app detected: ${data.cameraApp}" with title "🎥 Apex Red — CAMERA FOUND" sound name "Sosumi"`,
    ]);
  } else if (data.event === 'client_connected') {
    spawnProc('osascript', ['-e',
      `display notification "Device connected: ${data.mac} → ${data.ip}" with title "📱 Evil Twin: New Device"`,
    ]);
  } else if (data.event === 'credential_captured') {
    spawnProc('osascript', ['-e',
      `display notification "Auth token captured from connected device" with title "🔑 Apex Red — TOKEN CAPTURED" sound name "Sosumi"`,
    ]);
  }
});

// SSE stream for evil twin events
app.get('/api/eviltwin/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  // Send current state immediately
  res.write(`event: status\ndata: ${JSON.stringify({ active: isEvilTwinActive(), session: getEvilTwinSession() })}\n\n`);

  const onAny = (data: unknown) => {
    const d = data as any;
    res.write(`event: ${d.event ?? 'update'}\ndata: ${JSON.stringify(d)}\n\n`);
  };
  etEmitter.on('any', onAny);
  const hb = setInterval(() => res.write(': ping\n\n'), 15000);
  req.on('close', () => { clearInterval(hb); etEmitter.off('any', onAny); });
});

app.get('/api/stats', async (_req, res) => {
  const [invStats, findingStats, entityStats] = await Promise.all([
    pool.query(`SELECT status, COUNT(*) FROM investigations GROUP BY status`),
    pool.query(`SELECT severity, COUNT(*) FROM findings GROUP BY severity`),
    pool.query(`SELECT type, COUNT(*) FROM entities GROUP BY type ORDER BY count DESC LIMIT 10`),
  ]);
  res.json({ investigations: invStats.rows, findings: findingStats.rows, topEntityTypes: entityStats.rows });
});

// ── Remote scan ingestion (local Mac scanner POSTs here) ──────
const remoteScanLog: any[] = [];

app.post('/api/remote/scan', (req, res) => {
  const key = req.headers['x-apex-key'];
  if (key !== (process.env.APEX_REMOTE_KEY ?? 'apex-red-local')) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  const event = { ...req.body, receivedAt: new Date().toISOString() };
  remoteScanLog.unshift(event);
  if (remoteScanLog.length > 500) remoteScanLog.pop();

  // Fire SSE to any connected dashboards
  arpWatchEmitter.emit('remote', event);

  // Alert on Pi detection
  if (event.event === 'pi_online') {
    spawnProc('osascript', ['-e', `display notification "🚨 Pi camera is LIVE on your network" with title "APEX RED ALERT" sound name "Sosumi"`]);
  }

  res.json({ ok: true });
});

app.get('/api/remote/scan', (_req, res) => {
  res.json({ events: remoteScanLog.slice(0, 100) });
});

// SSE stream for remote events
app.get('/api/remote/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const onRemote = (data: unknown) => {
    res.write(`event: remote_scan\ndata: ${JSON.stringify(data)}\n\n`);
  };
  arpWatchEmitter.on('remote', onRemote);
  const hb = setInterval(() => res.write(': ping\n\n'), 15000);
  req.on('close', () => { clearInterval(hb); arpWatchEmitter.off('remote', onRemote); });
});

const PORT = process.env.PORT ?? 4000;
app.listen(PORT, () => console.log(`Apex Red API :${PORT}`));
