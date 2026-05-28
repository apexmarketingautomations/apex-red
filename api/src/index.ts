import express from 'express';
import cors from 'cors';
import { Client, Connection } from '@temporalio/client';
import { v4 as uuid } from 'uuid';
import pg from 'pg';
import type { ScanConfig } from '../../shared/src/types/index.js';

const app = express();
app.use(cors());
app.use(express.json());

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

// SSE clients per scan
const sseClients = new Map<string, Set<express.Response>>();

function broadcastToScan(scanId: string, event: string, data: unknown) {
  const clients = sseClients.get(scanId);
  if (!clients) return;
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of clients) res.write(payload);
}

let temporalClient: Client;
async function getClient() {
  if (!temporalClient) {
    const conn = await Connection.connect({
      address: process.env.TEMPORAL_ADDRESS ?? 'localhost:7233',
    });
    temporalClient = new Client({ connection: conn });
  }
  return temporalClient;
}

// ── Scans ──────────────────────────────────────────────────────────

app.get('/api/scans', async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT s.*,
       COUNT(f.id) AS finding_count,
       COUNT(f.id) FILTER (WHERE f.severity='critical') AS critical_count,
       COUNT(f.id) FILTER (WHERE f.severity='high') AS high_count
     FROM scans s
     LEFT JOIN findings f ON f.scan_id = s.id
     GROUP BY s.id
     ORDER BY s.created_at DESC`
  );
  res.json(rows);
});

app.post('/api/scans', async (req, res) => {
  try {
    const config: ScanConfig = req.body;
    const scanId = uuid();

    await pool.query(
      `INSERT INTO scans (id, name, status, config) VALUES ($1,$2,'pending',$3)`,
      [scanId, config.name, JSON.stringify(config)]
    );

    // Seed targets into DB
    for (const t of config.targets) {
      await pool.query(
        `INSERT INTO targets (scan_id, type, value, scope) VALUES ($1,$2,$3,'in')`,
        [scanId, t.type, t.value]
      );
    }

    const client = await getClient();
    await client.workflow.start('apexRedScan', {
      args: [{ ...config, scanId }],
      taskQueue: 'apex-red',
      workflowId: scanId,
    });

    await pool.query(`UPDATE scans SET status='running', started_at=NOW() WHERE id=$1`, [scanId]);

    res.json({ scanId, status: 'running' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err) });
  }
});

app.get('/api/scans/:id', async (req, res) => {
  const scan = await pool.query(`SELECT * FROM scans WHERE id=$1`, [req.params.id]);
  if (!scan.rows.length) return res.status(404).json({ error: 'Not found' });

  const [phases, findings, hosts, targets] = await Promise.all([
    pool.query(`SELECT * FROM phases WHERE scan_id=$1 ORDER BY started_at ASC NULLS LAST`, [req.params.id]),
    pool.query(
      `SELECT * FROM findings WHERE scan_id=$1 ORDER BY
         CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
           WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, created_at DESC`,
      [req.params.id]
    ),
    pool.query(`SELECT * FROM hosts WHERE scan_id=$1`, [req.params.id]),
    pool.query(`SELECT * FROM targets WHERE scan_id=$1`, [req.params.id]),
  ]);

  res.json({
    ...scan.rows[0],
    phases: phases.rows,
    findings: findings.rows,
    hosts: hosts.rows,
    targets: targets.rows,
  });
});

app.post('/api/scans/:id/pause', async (req, res) => {
  const c = await getClient();
  await c.workflow.getHandle(req.params.id).signal('pause');
  await pool.query(`UPDATE scans SET status='paused' WHERE id=$1`, [req.params.id]);
  broadcastToScan(req.params.id, 'status', { status: 'paused' });
  res.json({ status: 'paused' });
});

app.post('/api/scans/:id/resume', async (req, res) => {
  const c = await getClient();
  await c.workflow.getHandle(req.params.id).signal('resume');
  await pool.query(`UPDATE scans SET status='running' WHERE id=$1`, [req.params.id]);
  broadcastToScan(req.params.id, 'status', { status: 'running' });
  res.json({ status: 'running' });
});

app.delete('/api/scans/:id', async (req, res) => {
  try {
    const c = await getClient();
    await c.workflow.getHandle(req.params.id).terminate('Deleted by user').catch(() => {});
  } catch {}
  await pool.query(`DELETE FROM scans WHERE id=$1`, [req.params.id]);
  res.json({ deleted: true });
});

// ── Findings ───────────────────────────────────────────────────────

app.get('/api/scans/:id/findings', async (req, res) => {
  const { severity, category, tool } = req.query as Record<string, string>;
  let q = `SELECT * FROM findings WHERE scan_id=$1`;
  const p: unknown[] = [req.params.id];
  if (severity) { q += ` AND severity=$${p.length + 1}`; p.push(severity); }
  if (category) { q += ` AND category=$${p.length + 1}`; p.push(category); }
  if (tool)     { q += ` AND tool=$${p.length + 1}`;     p.push(tool); }
  q += ` ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
           WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, created_at DESC`;
  const { rows } = await pool.query(q, p);
  res.json(rows);
});

// ── Hosts ──────────────────────────────────────────────────────────

app.get('/api/scans/:id/hosts', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT h.*, COUNT(f.id) AS finding_count
     FROM hosts h
     LEFT JOIN findings f ON f.host_id = h.id
     WHERE h.scan_id=$1
     GROUP BY h.id`,
    [req.params.id]
  );
  res.json(rows);
});

// ── SSE live feed ──────────────────────────────────────────────────

app.get('/api/scans/:id/live', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const { id } = req.params;
  if (!sseClients.has(id)) sseClients.set(id, new Set());
  sseClients.get(id)!.add(res);

  // Heartbeat every 15s to keep connection alive
  const heartbeat = setInterval(() => res.write(': ping\n\n'), 15000);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.get(id)?.delete(res);
  });
});

// ── Internal: worker pushes events here ───────────────────────────

app.post('/internal/events/:scanId', async (req, res) => {
  const { scanId } = req.params;
  const { event, data } = req.body;
  broadcastToScan(scanId, event, data);

  // Persist phase/finding updates
  if (event === 'finding') {
    await pool.query(
      `INSERT INTO findings (scan_id, title, severity, category, description, proof, tool, url, raw)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [scanId, data.title, data.severity, data.category, data.description,
       data.proof ?? null, data.tool, data.url ?? null, JSON.stringify(data)]
    );
  } else if (event === 'phase_update') {
    await pool.query(
      `INSERT INTO phases (scan_id, phase, status, started_at, completed_at, findings_count, tools_used)
       VALUES ($1,$2,$3,
         CASE WHEN $3='running' THEN NOW() END,
         CASE WHEN $3='completed' THEN NOW() END,
         $4, $5)
       ON CONFLICT (scan_id, phase) DO UPDATE SET
         status=EXCLUDED.status,
         started_at=COALESCE(phases.started_at, EXCLUDED.started_at),
         completed_at=EXCLUDED.completed_at,
         findings_count=EXCLUDED.findings_count`,
      [scanId, data.phase, data.status, data.findings_count ?? 0, JSON.stringify(data.tools ?? [])]
    );
  } else if (event === 'host_found') {
    await pool.query(
      `INSERT INTO hosts (scan_id, hostname, ip, ports, technologies, discovered_by)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT DO NOTHING`,
      [scanId, data.hostname ?? null, data.ip ?? null,
       JSON.stringify(data.ports ?? []), JSON.stringify(data.technologies ?? []), data.tool]
    );
  } else if (event === 'scan_completed') {
    await pool.query(
      `UPDATE scans SET status='completed', completed_at=NOW() WHERE id=$1`, [scanId]
    );
  }

  res.json({ ok: true });
});

// ── Report download ────────────────────────────────────────────────

app.get('/api/scans/:id/report', async (req, res) => {
  const scan = await pool.query(`SELECT * FROM scans WHERE id=$1`, [req.params.id]);
  if (!scan.rows.length) return res.status(404).json({ error: 'Not found' });

  const findings = await pool.query(
    `SELECT * FROM findings WHERE scan_id=$1 ORDER BY
       CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
         WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END`,
    [req.params.id]
  );
  const hosts = await pool.query(`SELECT * FROM hosts WHERE scan_id=$1`, [req.params.id]);

  const report = {
    meta: {
      generated: new Date().toISOString(),
      platform: 'Apex Red',
      scan: scan.rows[0],
    },
    summary: {
      total: findings.rows.length,
      critical: findings.rows.filter((f: any) => f.severity === 'critical').length,
      high:     findings.rows.filter((f: any) => f.severity === 'high').length,
      medium:   findings.rows.filter((f: any) => f.severity === 'medium').length,
      low:      findings.rows.filter((f: any) => f.severity === 'low').length,
      info:     findings.rows.filter((f: any) => f.severity === 'info').length,
      hosts:    hosts.rows.length,
    },
    findings: findings.rows,
    hosts: hosts.rows,
  };

  const fmt = req.query.format ?? 'json';
  if (fmt === 'json') {
    res.setHeader('Content-Disposition', `attachment; filename="apex-red-report-${req.params.id}.json"`);
    res.json(report);
  } else {
    // HTML report
    res.setHeader('Content-Disposition', `attachment; filename="apex-red-report-${req.params.id}.html"`);
    res.send(buildHtmlReport(report));
  }
});

function buildHtmlReport(report: any): string {
  const sevBadge = (s: string) => ({
    critical: 'background:#dc2626;color:#fff',
    high:     'background:#f97316;color:#fff',
    medium:   'background:#eab308;color:#000',
    low:      'background:#3b82f6;color:#fff',
    info:     'background:#71717a;color:#fff',
  }[s] ?? '');

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Apex Red Report — ${report.meta.scan.name}</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0a0a0a;color:#e4e4e7;margin:0;padding:32px}
  h1{color:#dc2626}h2{color:#a1a1aa;font-size:14px;text-transform:uppercase;letter-spacing:.1em}
  .summary{display:flex;gap:16px;margin:24px 0}
  .stat{background:#18181b;border:1px solid #27272a;border-radius:8px;padding:16px 24px;min-width:80px}
  .stat .n{font-size:32px;font-weight:700}.stat .l{font-size:12px;color:#71717a;margin-top:4px}
  .critical .n{color:#dc2626}.high .n{color:#f97316}.medium .n{color:#eab308}
  table{width:100%;border-collapse:collapse;margin-top:16px}
  th{text-align:left;font-size:12px;color:#71717a;padding:8px 12px;border-bottom:1px solid #27272a}
  td{padding:10px 12px;border-bottom:1px solid #18181b;font-size:13px;vertical-align:top}
  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
  .proof{background:#18181b;border:1px solid #27272a;border-radius:4px;padding:8px;font-family:monospace;font-size:11px;margin-top:6px;white-space:pre-wrap}
</style></head><body>
<h1>Apex Red — Security Report</h1>
<p style="color:#71717a">${report.meta.scan.name} &nbsp;·&nbsp; Generated ${new Date(report.meta.generated).toLocaleString()}</p>
<h2>Summary</h2>
<div class="summary">
  <div class="stat critical"><div class="n">${report.summary.critical}</div><div class="l">Critical</div></div>
  <div class="stat high"><div class="n">${report.summary.high}</div><div class="l">High</div></div>
  <div class="stat medium"><div class="n">${report.summary.medium}</div><div class="l">Medium</div></div>
  <div class="stat"><div class="n">${report.summary.low}</div><div class="l">Low</div></div>
  <div class="stat"><div class="n">${report.summary.hosts}</div><div class="l">Hosts</div></div>
</div>
<h2>Findings</h2>
<table>
  <thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>Tool</th><th>Details</th></tr></thead>
  <tbody>
    ${report.findings.map((f: any) => `
    <tr>
      <td><span class="badge" style="${sevBadge(f.severity)}">${f.severity.toUpperCase()}</span></td>
      <td><strong>${f.title}</strong>${f.url ? `<br><small style="color:#71717a">${f.url}</small>` : ''}</td>
      <td>${f.category}</td>
      <td>${f.tool}</td>
      <td>${f.description ?? ''}${f.proof ? `<div class="proof">${f.proof}</div>` : ''}</td>
    </tr>`).join('')}
  </tbody>
</table>
</body></html>`;
}

// ── Stats ──────────────────────────────────────────────────────────

app.get('/api/stats', async (_req, res) => {
  const [scans, findings] = await Promise.all([
    pool.query(`SELECT status, COUNT(*) FROM scans GROUP BY status`),
    pool.query(`SELECT severity, COUNT(*) FROM findings GROUP BY severity`),
  ]);
  res.json({ scans: scans.rows, findings: findings.rows });
});

const PORT = process.env.PORT ?? 4000;
app.listen(PORT, () => console.log(`Apex Red API :${PORT}`));
