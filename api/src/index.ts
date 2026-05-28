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

let temporalClient: Client;

async function getTemporalClient() {
  if (!temporalClient) {
    const connection = await Connection.connect({
      address: process.env.TEMPORAL_ADDRESS ?? 'localhost:7233',
    });
    temporalClient = new Client({ connection });
  }
  return temporalClient;
}

// ── Start a scan ───────────────────────────────────────────────────
app.post('/api/scans', async (req, res) => {
  try {
    const config: ScanConfig = req.body;
    const scanId = uuid();

    await pool.query(
      `INSERT INTO scans (id, name, status, config) VALUES ($1,$2,'pending',$3)`,
      [scanId, config.name, JSON.stringify(config)]
    );

    const client = await getTemporalClient();
    await client.workflow.start('apexRedScan', {
      args: [config],
      taskQueue: 'apex-red',
      workflowId: scanId,
    });

    res.json({ scanId, status: 'started' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err) });
  }
});

// ── Get scan status ────────────────────────────────────────────────
app.get('/api/scans/:id', async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM scans WHERE id=$1`, [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Not found' });

  const phases = await pool.query(`SELECT * FROM phases WHERE scan_id=$1`, [req.params.id]);
  const findings = await pool.query(
    `SELECT * FROM findings WHERE scan_id=$1 ORDER BY
       CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
         WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END`,
    [req.params.id]
  );

  res.json({ ...rows[0], phases: phases.rows, findings: findings.rows });
});

// ── List all scans ─────────────────────────────────────────────────
app.get('/api/scans', async (_req, res) => {
  const { rows } = await pool.query(`SELECT * FROM scans ORDER BY created_at DESC`);
  res.json(rows);
});

// ── Pause / resume ─────────────────────────────────────────────────
app.post('/api/scans/:id/pause', async (req, res) => {
  const client = await getTemporalClient();
  const handle = client.workflow.getHandle(req.params.id);
  await handle.signal('pause');
  await pool.query(`UPDATE scans SET status='paused' WHERE id=$1`, [req.params.id]);
  res.json({ status: 'paused' });
});

app.post('/api/scans/:id/resume', async (req, res) => {
  const client = await getTemporalClient();
  const handle = client.workflow.getHandle(req.params.id);
  await handle.signal('resume');
  await pool.query(`UPDATE scans SET status='running' WHERE id=$1`, [req.params.id]);
  res.json({ status: 'running' });
});

// ── Findings ───────────────────────────────────────────────────────
app.get('/api/scans/:id/findings', async (req, res) => {
  const { severity, category } = req.query as Record<string, string>;
  let query = `SELECT * FROM findings WHERE scan_id=$1`;
  const params: unknown[] = [req.params.id];
  if (severity) { query += ` AND severity=$${params.length + 1}`; params.push(severity); }
  if (category) { query += ` AND category=$${params.length + 1}`; params.push(category); }
  query += ` ORDER BY created_at DESC`;
  const { rows } = await pool.query(query, params);
  res.json(rows);
});

// ── Hosts ──────────────────────────────────────────────────────────
app.get('/api/scans/:id/hosts', async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM hosts WHERE scan_id=$1`, [req.params.id]);
  res.json(rows);
});

const PORT = process.env.PORT ?? 4000;
app.listen(PORT, () => console.log(`Apex Red API running on :${PORT}`));
