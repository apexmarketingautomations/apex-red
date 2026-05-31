import { exec } from 'child_process';
import { promisify } from 'util';
import { pool } from './db.js';

const execAsync = promisify(exec);

async function upsertEntity(invId: string, type: string, value: string, meta: any = {}) {
  const { rows } = await pool.query(
    `INSERT INTO entities (investigation_id, type, value, confidence, metadata)
     VALUES ($1,$2,$3,0.9,$4)
     ON CONFLICT (investigation_id, type, value) DO UPDATE SET metadata = $4
     RETURNING id`,
    [invId, type, value, JSON.stringify(meta)]
  );
  return rows[0].id;
}

async function addFinding(invId: string, entityId: string, title: string, description: string, severity: string, category: string, module: string, raw: any = {}) {
  await pool.query(
    `INSERT INTO findings (investigation_id, entity_id, title, description, severity, category, module, raw_data)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [invId, entityId, title, description, severity, category, module, JSON.stringify(raw)]
  );
}

async function markModule(invId: string, module: string, status: string, meta: any = {}) {
  await pool.query(
    `INSERT INTO module_runs (investigation_id, module, status, metadata)
     VALUES ($1,$2,$3,$4)
     ON CONFLICT (investigation_id, module) DO UPDATE SET status=$3, metadata=$4, updated_at=NOW()`,
    [invId, module, status, JSON.stringify(meta)]
  );
}

async function dnsLookup(domain: string) {
  try {
    const { stdout } = await execAsync(`nslookup ${domain} 2>/dev/null || host ${domain} 2>/dev/null || echo "FAILED"`);
    return stdout.trim();
  } catch { return ''; }
}

async function whoisLookup(domain: string) {
  try {
    const { stdout } = await execAsync(`whois ${domain} 2>/dev/null | head -40`);
    return stdout.trim();
  } catch { return ''; }
}

async function httpProbe(target: string) {
  try {
    const { stdout } = await execAsync(`curl -sI --max-time 10 --location https://${target} 2>/dev/null | head -20`);
    return stdout.trim();
  } catch { return ''; }
}

async function portScan(ip: string) {
  try {
    const { stdout } = await execAsync(`nmap -T4 -F --open ${ip} 2>/dev/null | grep -E "open|filtered" | head -30`);
    return stdout.trim();
  } catch { return ''; }
}

async function scanDomain(invId: string, domain: string, depth: string, broadcast: Function) {
  const entityId = await upsertEntity(invId, 'domain', domain);
  broadcast(invId, 'entity', { type: 'domain', value: domain, id: entityId });

  // DNS
  await markModule(invId, 'dns', 'running');
  broadcast(invId, 'module_start', { module: 'dns', target: domain });
  const dnsResult = await dnsLookup(domain);
  const ipMatches = dnsResult.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) ?? [];
  for (const ip of [...new Set(ipMatches)]) {
    const ipId = await upsertEntity(invId, 'ip', ip, { source: 'dns' });
    await pool.query(
      `INSERT INTO relationships (investigation_id, source_id, target_id, type, weight)
       SELECT $1,$2,$3,'resolves_to',1.0 WHERE NOT EXISTS (
         SELECT 1 FROM relationships WHERE investigation_id=$1 AND source_id=$2 AND target_id=$3)`,
      [invId, entityId, ipId]
    );
    broadcast(invId, 'entity', { type: 'ip', value: ip, id: ipId });
  }
  await markModule(invId, 'dns', 'completed', { ips: ipMatches });
  broadcast(invId, 'module_done', { module: 'dns', ips: ipMatches });

  // HTTP probe
  await markModule(invId, 'http_probe', 'running');
  broadcast(invId, 'module_start', { module: 'http_probe', target: domain });
  const headers = await httpProbe(domain);
  if (headers) {
    const serverMatch = headers.match(/server:\s*(.+)/i);
    const server = serverMatch?.[1]?.trim();
    if (server) {
      await addFinding(invId, entityId, `Web server: ${server}`, `Server header reveals technology: ${server}`, 'info', 'fingerprinting', 'http_probe', { headers });
      broadcast(invId, 'finding', { severity: 'info', title: `Web server: ${server}` });
    }
    if (headers.includes('200') || headers.includes('301') || headers.includes('302')) {
      await upsertEntity(invId, 'url', `https://${domain}`, { headers: headers.slice(0, 500) });
    }
  }
  await markModule(invId, 'http_probe', 'completed');
  broadcast(invId, 'module_done', { module: 'http_probe' });

  // Whois
  await markModule(invId, 'whois', 'running');
  broadcast(invId, 'module_start', { module: 'whois', target: domain });
  const whoisData = await whoisLookup(domain);
  if (whoisData) {
    const registrarMatch = whoisData.match(/registrar:\s*(.+)/i);
    const expiryMatch = whoisData.match(/expir\w+:\s*(.+)/i);
    const emailsInWhois = [...new Set(whoisData.match(/[\w.+-]+@[\w-]+\.[\w.]+/g) ?? [])];
    for (const email of emailsInWhois) {
      const eid = await upsertEntity(invId, 'email', email, { source: 'whois' });
      await pool.query(
        `INSERT INTO relationships (investigation_id, source_id, target_id, type, weight)
         SELECT $1,$2,$3,'registered_by',0.8 WHERE NOT EXISTS (
           SELECT 1 FROM relationships WHERE investigation_id=$1 AND source_id=$2 AND target_id=$3)`,
        [invId, entityId, eid]
      );
      broadcast(invId, 'entity', { type: 'email', value: email });
    }
    await addFinding(invId, entityId, 'WHOIS data collected', `Registrar: ${registrarMatch?.[1] ?? 'unknown'}. Expiry: ${expiryMatch?.[1] ?? 'unknown'}`, 'info', 'osint', 'whois', { whois: whoisData.slice(0, 1000) });
    broadcast(invId, 'finding', { severity: 'info', title: 'WHOIS data collected' });
  }
  await markModule(invId, 'whois', 'completed');
  broadcast(invId, 'module_done', { module: 'whois' });

  // Port scan (standard/deep only)
  if (depth !== 'quick' && ipMatches.length > 0) {
    await markModule(invId, 'portscan', 'running');
    broadcast(invId, 'module_start', { module: 'portscan', target: ipMatches[0] });
    const ports = await portScan(ipMatches[0]);
    if (ports) {
      const openPorts = ports.match(/(\d+)\/(tcp|udp)\s+open/g)?.map(p => p.split('/')[0]) ?? [];
      if (openPorts.includes('22')) {
        await addFinding(invId, entityId, 'SSH port open (22)', 'SSH service exposed. Ensure key-based auth only and fail2ban configured.', 'medium', 'network', 'portscan', { ports });
        broadcast(invId, 'finding', { severity: 'medium', title: 'SSH port open (22)' });
      }
      if (openPorts.includes('3389')) {
        await addFinding(invId, entityId, 'RDP port open (3389)', 'Remote Desktop exposed to internet — high risk.', 'high', 'network', 'portscan', { ports });
        broadcast(invId, 'finding', { severity: 'high', title: 'RDP port open (3389)' });
      }
      if (openPorts.includes('23')) {
        await addFinding(invId, entityId, 'Telnet port open (23)', 'Telnet is unencrypted — critical risk.', 'critical', 'network', 'portscan', { ports });
        broadcast(invId, 'finding', { severity: 'critical', title: 'Telnet port open (23)' });
      }
      await markModule(invId, 'portscan', 'completed', { openPorts });
      broadcast(invId, 'module_done', { module: 'portscan', openPorts });
    } else {
      await markModule(invId, 'portscan', 'completed', { note: 'no open ports or nmap unavailable' });
      broadcast(invId, 'module_done', { module: 'portscan' });
    }
  }
}

async function scanEmail(invId: string, email: string, broadcast: Function) {
  const entityId = await upsertEntity(invId, 'email', email);
  broadcast(invId, 'entity', { type: 'email', value: email, id: entityId });

  const domain = email.split('@')[1];
  if (domain) {
    const domainId = await upsertEntity(invId, 'domain', domain, { source: 'email_parse' });
    await pool.query(
      `INSERT INTO relationships (investigation_id, source_id, target_id, type, weight)
       SELECT $1,$2,$3,'belongs_to',1.0 WHERE NOT EXISTS (
         SELECT 1 FROM relationships WHERE investigation_id=$1 AND source_id=$2 AND target_id=$3)`,
      [invId, entityId, domainId]
    );
    broadcast(invId, 'entity', { type: 'domain', value: domain });
    await scanDomain(invId, domain, 'quick', broadcast);
  }
}

async function scanIp(invId: string, ip: string, depth: string, broadcast: Function) {
  const entityId = await upsertEntity(invId, 'ip', ip);
  broadcast(invId, 'entity', { type: 'ip', value: ip, id: entityId });

  await markModule(invId, 'portscan', 'running');
  broadcast(invId, 'module_start', { module: 'portscan', target: ip });
  const ports = await portScan(ip);
  if (ports) {
    await addFinding(invId, entityId, 'Port scan results', ports, 'info', 'network', 'portscan', { raw: ports });
    broadcast(invId, 'finding', { severity: 'info', title: 'Port scan results' });
  }
  await markModule(invId, 'portscan', 'completed');
  broadcast(invId, 'module_done', { module: 'portscan' });
}

export async function runScan(invId: string, seeds: any[], depth: string, modules: any, broadcast: Function) {
  broadcast(invId, 'status', { status: 'running', message: 'Scan started' });

  for (const seed of seeds) {
    try {
      broadcast(invId, 'progress', { seed: seed.value, type: seed.type });
      switch (seed.type) {
        case 'domain':
          await scanDomain(invId, seed.value, depth, broadcast);
          break;
        case 'email':
          await scanEmail(invId, seed.value, broadcast);
          break;
        case 'ip':
          await scanIp(invId, seed.value, depth, broadcast);
          break;
        default:
          await upsertEntity(invId, seed.type, seed.value);
          broadcast(invId, 'entity', { type: seed.type, value: seed.value });
      }
    } catch (err) {
      broadcast(invId, 'error', { seed: seed.value, error: String(err) });
    }
  }

  await pool.query(`UPDATE investigations SET status='completed', completed_at=NOW() WHERE id=$1`, [invId]);
  broadcast(invId, 'status', { status: 'completed' });
}
