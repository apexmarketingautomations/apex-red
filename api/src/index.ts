import express from 'express';
import cors from 'cors';
import { Client, Connection } from '@temporalio/client';
import { v4 as uuid } from 'uuid';
import pg from 'pg';

const app = express();
app.use(cors());
app.use(express.json());

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

// SSE clients per investigation
const sseClients = new Map<string, Set<express.Response>>();

function broadcast(invId: string, event: string, data: unknown) {
  const clients = sseClients.get(invId);
  if (!clients?.size) return;
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

// ── Investigations ─────────────────────────────────────────────────────────

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

    // Seed entities
    for (const s of seeds) {
      await pool.query(
        `INSERT INTO entities (investigation_id, type, value, is_seed, confidence)
         VALUES ($1,$2,$3,true,1.0)`,
        [invId, s.type, s.value]
      );
    }

    const client = await getClient();
    await client.workflow.start('apexRedInvestigation', {
      args: [{ investigationId: invId, depth, modules }],
      taskQueue: 'apex-red',
      workflowId: invId,
    });

    await pool.query(`UPDATE investigations SET status='running', started_at=NOW() WHERE id=$1`, [invId]);
    res.json({ id: invId, status: 'running' });
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
  res.json({
    ...inv.rows[0],
    entities: entities.rows,
    relationships: relationships.rows,
    findings: findings.rows,
    evidence: evidence.rows,
    modules: modules.rows,
    riskScores: scores.rows,
  });
});

app.delete('/api/investigations/:id', async (req, res) => {
  try {
    const c = await getClient();
    await c.workflow.getHandle(req.params.id).terminate('Deleted').catch(() => {});
  } catch {}
  await pool.query(`DELETE FROM investigations WHERE id=$1`, [req.params.id]);
  res.json({ deleted: true });
});

app.post('/api/investigations/:id/pause', async (req, res) => {
  const c = await getClient();
  await c.workflow.getHandle(req.params.id).signal('pause');
  await pool.query(`UPDATE investigations SET status='paused' WHERE id=$1`, [req.params.id]);
  broadcast(req.params.id, 'status', { status: 'paused' });
  res.json({ status: 'paused' });
});

app.post('/api/investigations/:id/resume', async (req, res) => {
  const c = await getClient();
  await c.workflow.getHandle(req.params.id).signal('resume');
  await pool.query(`UPDATE investigations SET status='running' WHERE id=$1`, [req.params.id]);
  broadcast(req.params.id, 'status', { status: 'running' });
  res.json({ status: 'running' });
});

// ── Entity Graph ───────────────────────────────────────────────────────────

app.get('/api/investigations/:id/graph', async (req, res) => {
  const [entities, relationships] = await Promise.all([
    pool.query(`SELECT e.*, r.overall AS risk_overall FROM entities e
                LEFT JOIN risk_scores r ON r.entity_id=e.id
                WHERE e.investigation_id=$1`, [req.params.id]),
    pool.query(`SELECT * FROM relationships WHERE investigation_id=$1`, [req.params.id]),
  ]);
  res.json({ nodes: entities.rows, edges: relationships.rows });
});

// ── Findings ───────────────────────────────────────────────────────────────

app.get('/api/investigations/:id/findings', async (req, res) => {
  const { severity, category, module, tool } = req.query as Record<string, string>;
  let q = `SELECT f.*, e.type as entity_type, e.value as entity_value
           FROM findings f LEFT JOIN entities e ON e.id=f.entity_id
           WHERE f.investigation_id=$1`;
  const p: unknown[] = [req.params.id];
  if (severity) { q += ` AND f.severity=$${p.length+1}`;  p.push(severity); }
  if (category) { q += ` AND f.category=$${p.length+1}`;  p.push(category); }
  if (module)   { q += ` AND f.module=$${p.length+1}`;    p.push(module); }
  if (tool)     { q += ` AND f.tool=$${p.length+1}`;      p.push(tool); }
  q += ` ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
           WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END`;
  const { rows } = await pool.query(q, p);
  res.json(rows);
});

// ── Evidence ───────────────────────────────────────────────────────────────

app.get('/api/investigations/:id/evidence', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT ev.*, e.type as entity_type, e.value as entity_value
     FROM evidence ev LEFT JOIN entities e ON e.id=ev.entity_id
     WHERE ev.investigation_id=$1 ORDER BY ev.timestamp DESC`,
    [req.params.id]
  );
  res.json(rows);
});

// ── AI Report ─────────────────────────────────────────────────────────────

app.get('/api/investigations/:id/report', async (req, res) => {
  const { rows } = await pool.query(`SELECT ai_report, name FROM investigations WHERE id=$1`, [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Not found' });

  const fmt = req.query.format ?? 'json';
  if (fmt === 'json') {
    res.json({ report: rows[0].ai_report, name: rows[0].name });
  } else {
    // Return markdown as downloadable file
    res.setHeader('Content-Type', 'text/markdown');
    res.setHeader('Content-Disposition', `attachment; filename="apex-red-${req.params.id}.md"`);
    res.send(rows[0].ai_report ?? '# Report not yet generated');
  }
});

// ── SSE Live Feed ──────────────────────────────────────────────────────────

app.get('/api/investigations/:id/live', (req, res) => {
  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection',    'keep-alive');
  res.flushHeaders();

  const { id } = req.params;
  if (!sseClients.has(id)) sseClients.set(id, new Set());
  sseClients.get(id)!.add(res);

  const hb = setInterval(() => res.write(': ping\n\n'), 15000);
  req.on('close', () => { clearInterval(hb); sseClients.get(id)?.delete(res); });
});

// ── Internal: worker → API event bus ──────────────────────────────────────

app.post('/internal/events/:invId', async (req, res) => {
  const { invId } = req.params;
  const { event, data } = req.body;
  broadcast(invId, event, data);

  if (event === 'entity_found') {
    // Already in DB via graph.ts upsertEntity — just broadcast
  } else if (event === 'finding') {
    // Already in DB via graph.ts addFinding — just broadcast
  } else if (event === 'investigation_completed') {
    await pool.query(`UPDATE investigations SET status='completed', completed_at=NOW() WHERE id=$1`, [invId]);
  } else if (event === 'investigation_failed') {
    await pool.query(`UPDATE investigations SET status='failed' WHERE id=$1`, [invId]);
  }

  res.json({ ok: true });
});

// ── Stats ──────────────────────────────────────────────────────────────────

app.get('/api/stats', async (_req, res) => {
  const [invStats, findingStats, entityStats] = await Promise.all([
    pool.query(`SELECT status, COUNT(*) FROM investigations GROUP BY status`),
    pool.query(`SELECT severity, COUNT(*) FROM findings GROUP BY severity`),
    pool.query(`SELECT type, COUNT(*) FROM entities GROUP BY type ORDER BY count DESC LIMIT 10`),
  ]);
  res.json({
    investigations: invStats.rows,
    findings: findingStats.rows,
    topEntityTypes: entityStats.rows,
  });
});

const PORT = process.env.PORT ?? 4000;
app.listen(PORT, () => console.log(`Apex Red API :${PORT}`));
