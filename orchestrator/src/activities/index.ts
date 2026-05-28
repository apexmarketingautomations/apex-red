import { heartbeat } from '@temporalio/activity';
import { execDocker } from '../utils/docker.js';
import { db } from '../utils/db.js';
import type { ScanConfig, Target, TargetType } from '../../../shared/src/types/index.js';

// ── Recon ──────────────────────────────────────────────────────────

export async function runRecon(
  scanId: string,
  targets: Array<{ type: TargetType; value: string }>,
  depth: ScanConfig['depth']
) {
  const results: { hosts: string[]; subdomains: string[]; findings: unknown[] } = {
    hosts: [],
    subdomains: [],
    findings: [],
  };

  for (const target of targets) {
    heartbeat(`Reconning ${target.value}`);

    if (target.type === 'domain') {
      // subfinder for subdomains
      const subOut = await execDocker('apex-red-reconftw', [
        'subfinder', '-d', target.value, '-silent', '-all'
      ]);
      const subs = subOut.trim().split('\n').filter(Boolean);
      results.subdomains.push(...subs);

      // httpx to find live hosts
      const httpxOut = await execDocker('apex-red-reconftw', [
        'httpx', '-list', '-', '-silent', '-no-color'
      ], subs.join('\n'));
      results.hosts.push(...httpxOut.trim().split('\n').filter(Boolean));

      // Save discovered subdomains as targets
      await db.query(
        `INSERT INTO targets (scan_id, type, value, scope, discovered_from)
         SELECT $1, 'domain', unnest($2::text[]), 'in',
           (SELECT id FROM targets WHERE scan_id=$1 AND value=$3 LIMIT 1)`,
        [scanId, subs, target.value]
      );

    } else if (target.type === 'ip' || target.type === 'cidr') {
      // nmap for IP/CIDR
      const nmapOut = await execDocker('apex-red-reconftw', [
        'nmap', '-sV', '-T4', '--open', '-oG', '-', target.value
      ]);
      results.hosts.push(target.value);
    }
  }

  return results;
}

// ── Nuclei ─────────────────────────────────────────────────────────

export async function runNuclei(scanId: string, depth: ScanConfig['depth']) {
  heartbeat('Running Nuclei scan');

  const severityFlag = depth === 'surface' ? 'medium,high,critical' : 'low,medium,high,critical';

  // Get all live hosts from DB
  const hostsResult = await db.query(
    `SELECT DISTINCT value FROM targets WHERE scan_id = $1 AND type IN ('domain','url','ip')`,
    [scanId]
  );
  const hosts = hostsResult.rows.map((r: { value: string }) => r.value);

  if (!hosts.length) return { findings: [] };

  const nucleiOut = await execDocker('apex-red-nuclei', [
    'nuclei',
    '-list', '-',
    '-severity', severityFlag,
    '-json',
    '-silent',
    '-update-templates',
  ], hosts.join('\n'));

  const findings = nucleiOut
    .trim()
    .split('\n')
    .filter(Boolean)
    .map(line => {
      try { return JSON.parse(line); } catch { return null; }
    })
    .filter(Boolean);

  // Save to DB
  for (const f of findings) {
    await db.query(
      `INSERT INTO findings (scan_id, title, severity, category, description, tool, url, raw)
       VALUES ($1,$2,$3,$4,$5,'nuclei',$6,$7)`,
      [scanId, f.info?.name, f.info?.severity, f.info?.tags?.[0] ?? 'other',
       f.info?.description ?? '', f.matched_at, JSON.stringify(f)]
    );
    heartbeat(`Finding: ${f.info?.name}`);
  }

  return { findings };
}

// ── Shannon (AI Pentester) ─────────────────────────────────────────

export async function runShannon(scanId: string, config: ScanConfig) {
  heartbeat('Starting Shannon AI pentest');

  const target = config.targets.find(t => t.type === 'domain' || t.type === 'url');
  if (!target) return { findings: [] };

  const shannonOut = await execDocker('apex-red-shannon', [
    'shannon', 'start',
    '-u', target.value,
    '--json',
  ]);

  const result = JSON.parse(shannonOut || '{"findings":[]}');

  for (const f of result.findings ?? []) {
    await db.query(
      `INSERT INTO findings (scan_id, title, severity, category, description, proof, tool, url, raw)
       VALUES ($1,$2,$3,$4,$5,$6,'shannon',$7,$8)`,
      [scanId, f.title, f.severity, f.category, f.description,
       f.proof ?? null, f.url ?? null, JSON.stringify(f)]
    );
    heartbeat(`Shannon finding: ${f.title}`);
  }

  return result;
}

// ── OSINT ──────────────────────────────────────────────────────────

export async function runOsint(
  scanId: string,
  targets: Array<{ type: TargetType; value: string }>
) {
  heartbeat('Running OSINT');
  const emails: string[] = [];
  const leaks: unknown[] = [];

  for (const target of targets) {
    if (target.type === 'domain' || target.type === 'company') {
      // theHarvester for emails
      const harvOut = await execDocker('apex-red-reconftw', [
        'theHarvester', '-d', target.value, '-b', 'bing,google,linkedin', '-f', '/tmp/harv'
      ]).catch(() => '');

      const emailMatches = harvOut.match(/[\w.+-]+@[\w-]+\.[a-z]{2,}/gi) ?? [];
      emails.push(...emailMatches);

      // Check for leaked creds via trufflehog on GitHub org
      if (target.type === 'company') {
        heartbeat(`Checking GitHub for leaks: ${target.value}`);
        const truffleOut = await execDocker('apex-red-reconftw', [
          'trufflehog', 'github', '--org', target.value, '--json', '--only-verified'
        ]).catch(() => '');

        const leakLines = truffleOut.trim().split('\n').filter(Boolean);
        leaks.push(...leakLines.map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean));
      }
    }

    // Save email findings
    for (const email of emailMatches ?? []) {
      await db.query(
        `INSERT INTO findings (scan_id, title, severity, category, description, tool)
         VALUES ($1,'Discovered email address','info','info_disclosure',$2,'theHarvester')`,
        [scanId, `Email found: ${email}`]
      );
    }
  }

  return { emails, leaks };
}

// ── WiFi ───────────────────────────────────────────────────────────

export async function runWifi(scanId: string) {
  heartbeat('Running WiFi scan');

  // bettercap WiFi recon (requires host network + wireless adapter)
  const wifiOut = await execDocker('apex-red-bettercap', [
    'bettercap', '-eval',
    'wifi.recon on; sleep 15; wifi.show; exit'
  ]).catch(() => '');

  const networks = wifiOut
    .split('\n')
    .filter(l => l.includes('BSSID') || l.match(/[0-9a-f]{2}:[0-9a-f]{2}:/i))
    .map(l => l.trim());

  for (const network of networks) {
    await db.query(
      `INSERT INTO findings (scan_id, title, severity, category, description, tool)
       VALUES ($1,'WiFi network discovered','info','wifi',$2,'bettercap')`,
      [scanId, network]
    );
  }

  return { networks };
}

// ── Phase tracking ─────────────────────────────────────────────────

export async function updatePhase(
  scanId: string,
  phase: string,
  status: string,
  results?: unknown
) {
  await db.query(
    `INSERT INTO phases (scan_id, phase, status, started_at, completed_at, findings_count)
     VALUES ($1,$2,$3,
       CASE WHEN $3='running' THEN NOW() ELSE NULL END,
       CASE WHEN $3='completed' THEN NOW() ELSE NULL END,
       $4)
     ON CONFLICT (scan_id, phase) DO UPDATE SET
       status = EXCLUDED.status,
       started_at = COALESCE(phases.started_at, EXCLUDED.started_at),
       completed_at = EXCLUDED.completed_at,
       findings_count = EXCLUDED.findings_count`,
    [scanId, phase, status, (results as any)?.findings?.length ?? 0]
  );
}

export async function saveFinding(scanId: string, finding: unknown) {
  const f = finding as any;
  await db.query(
    `INSERT INTO findings (scan_id, title, severity, category, description, proof, tool, url, raw)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [scanId, f.title, f.severity, f.category, f.description,
     f.proof ?? null, f.tool, f.url ?? null, JSON.stringify(f)]
  );
}

export async function finalizeReport(scanId: string, format: ScanConfig['reportFormat']) {
  heartbeat('Generating report');

  const findings = await db.query(
    `SELECT * FROM findings WHERE scan_id = $1 ORDER BY
       CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
         WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END`,
    [scanId]
  );

  const reportPath = `/reports/${scanId}/report.json`;

  await db.query(
    `UPDATE scans SET status='completed', completed_at=NOW() WHERE id=$1`,
    [scanId]
  );

  return reportPath;
}

export async function notifyProgress(scanId: string, event: string, data: unknown) {
  await db.query(
    `INSERT INTO phases (scan_id, phase, status) VALUES ($1,$2,'running')
     ON CONFLICT DO NOTHING`,
    [scanId, event]
  );
  console.log(`[${scanId}] ${event}`, data);
}
