import { heartbeat } from '@temporalio/activity';
import { execDocker } from '../utils/docker.js';
import { upsertEntity, upsertRelationship, postEvent } from '../utils/graph.js';
import type { Entity } from '../../../shared/src/types/index.js';

export async function runRecon(investigationId: string, seeds: Entity[]) {
  const domainSeeds = seeds.filter(e => e.type === 'domain' || e.type === 'subdomain');
  const ipSeeds     = seeds.filter(e => e.type === 'ip' || e.type === 'cidr');
  let discovered = 0;

  for (const seed of domainSeeds) {
    heartbeat(`Recon: ${seed.value}`);

    // 1. Subdomains via subfinder
    try {
      const subOut = await execDocker('apex-red-reconftw', ['subfinder', '-d', seed.value, '-silent', '-all']);
      const subs = subOut.trim().split('\n').filter(Boolean);
      for (const sub of subs) {
        const e = await upsertEntity(investigationId, 'subdomain', sub, {
          discoveredBy: 'subfinder', discoveredFrom: seed.id, confidence: 0.9,
        });
        await upsertRelationship(investigationId, seed.id, e.id, 'subdomain_of', 'subfinder');
        discovered++;
        await postEvent(investigationId, 'entity_found', { type: 'subdomain', value: sub });
      }
    } catch {}

    // 2. DNS records via dnsx
    try {
      const dnsOut = await execDocker('apex-red-reconftw', [
        'dnsx', '-d', seed.value, '-a', '-mx', '-txt', '-cname', '-ns', '-resp', '-json',
      ]);
      for (const line of dnsOut.trim().split('\n').filter(Boolean)) {
        try {
          const rec = JSON.parse(line);
          const e = await upsertEntity(investigationId, 'dns_record', `${rec.host}:${rec.type}`, {
            discoveredBy: 'dnsx', discoveredFrom: seed.id,
            metadata: rec, confidence: 1.0,
          });
          await upsertRelationship(investigationId, seed.id, e.id, 'contains', 'dnsx');
          // If A record → also create IP entity
          if (rec.type === 'A' && rec.a?.length) {
            for (const ip of rec.a) {
              const ipE = await upsertEntity(investigationId, 'ip', ip, {
                discoveredBy: 'dnsx', discoveredFrom: seed.id, confidence: 1.0,
              });
              await upsertRelationship(investigationId, seed.id, ipE.id, 'resolves_to', 'dnsx');
              discovered++;
            }
          }
        } catch {}
      }
    } catch {}

    // 3. Cert transparency via crt.sh
    try {
      const crtOut = await execDocker('apex-red-reconftw', [
        'curl', '-s', `https://crt.sh/?q=%.${seed.value}&output=json`,
      ]);
      const certs: any[] = JSON.parse(crtOut || '[]');
      for (const cert of certs.slice(0, 50)) {
        const e = await upsertEntity(investigationId, 'certificate', cert.id?.toString() ?? cert.name_value, {
          discoveredBy: 'crtsh', discoveredFrom: seed.id,
          metadata: { issuer: cert.issuer_name, expiry: cert.not_after, domains: cert.name_value },
          confidence: 1.0,
        });
        await upsertRelationship(investigationId, seed.id, e.id, 'certificate_for', 'crtsh');
        discovered++;
      }
    } catch {}

    // 4. Live hosts + tech stack via httpx
    try {
      const httpxOut = await execDocker('apex-red-reconftw', [
        'httpx', '-u', seed.value, '-json', '-tech-detect', '-status-code', '-title', '-silent',
      ]);
      for (const line of httpxOut.trim().split('\n').filter(Boolean)) {
        try {
          const h = JSON.parse(line);
          await upsertEntity(investigationId, 'url', h.url, {
            discoveredBy: 'httpx', discoveredFrom: seed.id,
            metadata: { status: h.status_code, title: h.title, tech: h.tech },
            confidence: 1.0,
          });
          await postEvent(investigationId, 'entity_found', { type: 'url', value: h.url, tech: h.tech });
        } catch {}
      }
    } catch {}

    // 5. Port scan via nmap
    try {
      const nmapOut = await execDocker('apex-red-reconftw', [
        'nmap', '-sV', '-T4', '--open', '-oX', '-', seed.value,
      ]);
      // Parse open ports and emit port entities
      const portMatches = nmapOut.matchAll(/<port protocol="(\w+)" portid="(\d+)"[\s\S]*?<state state="open"[\s\S]*?<service name="([^"]*)"[^/]*\/>/g);
      for (const m of portMatches) {
        const portE = await upsertEntity(investigationId, 'port', `${seed.value}:${m[2]}/${m[1]}`, {
          discoveredBy: 'nmap', discoveredFrom: seed.id,
          metadata: { protocol: m[1], port: parseInt(m[2]), service: m[3] },
          confidence: 1.0,
        });
        await upsertRelationship(investigationId, seed.id, portE.id, 'contains', 'nmap');
        await postEvent(investigationId, 'entity_found', { type: 'port', value: `${m[2]}/${m[1]} ${m[3]}` });
        discovered++;
      }
    } catch {}
  }

  for (const seed of ipSeeds) {
    heartbeat(`Recon: ${seed.value}`);
    try {
      const nmapOut = await execDocker('apex-red-reconftw', [
        'nmap', '-sV', '-T4', '--open', seed.value,
      ]);
      await postEvent(investigationId, 'module_progress', {
        module: 'recon', message: `Port scan complete: ${seed.value}`,
      });
    } catch {}
  }

  return { discovered };
}
