import { heartbeat } from '@temporalio/activity';
import { execDocker } from '../utils/docker.js';
import { upsertEntity, upsertRelationship, addFinding, addEvidence, postEvent } from '../utils/graph.js';
import type { Entity } from '../../../shared/src/types/index.js';

export async function runVulns(investigationId: string, seeds: Entity[], depth: string) {
  const webTargets = seeds.filter(e =>
    ['domain', 'subdomain', 'url', 'ip', 'app'].includes(e.type)
  );
  let discovered = 0;

  const severityFlag = depth === 'surface' ? 'medium,high,critical' : 'low,medium,high,critical';

  for (const seed of webTargets) {
    heartbeat(`Vulns: ${seed.value}`);

    // 1. Nuclei — template-based scanning
    try {
      const nucleiOut = await execDocker('apex-red-nuclei', [
        'nuclei', '-u', seed.value,
        '-severity', severityFlag,
        '-json', '-silent',
        '-update-templates',
      ]);

      for (const line of nucleiOut.trim().split('\n').filter(Boolean)) {
        try {
          const f = JSON.parse(line);
          const vulnE = await upsertEntity(investigationId, 'vulnerability',
            `${seed.value}:${f.template_id}`, {
              discoveredBy: 'nuclei', discoveredFrom: seed.id,
              metadata: { templateId: f.template_id, matcher: f.matcher_name },
              confidence: 0.9,
            });
          await upsertRelationship(investigationId, seed.id, vulnE.id, 'exposed_in', 'nuclei');

          await addFinding(investigationId, seed.id, {
            title: f.info?.name ?? f.template_id,
            severity: (f.info?.severity ?? 'info') as any,
            category: mapNucleiTag(f.info?.tags),
            description: f.info?.description ?? '',
            proof: f.matched_at,
            remediation: f.info?.remediation ?? undefined,
            module: 'vuln_engine', tool: 'nuclei',
            url: f.matched_at, cve: f.info?.classification?.cve_id?.[0],
            cwe: f.info?.classification?.cwe_id?.[0],
            raw: f,
          });

          await postEvent(investigationId, 'finding', {
            severity: f.info?.severity, title: f.info?.name, module: 'vuln_engine',
          });
          discovered++;
        } catch {}
      }
    } catch {}

    // 2. Shannon AI pentest (domain/app only, needs source repo)
    if ((seed.type === 'domain' || seed.type === 'app') && seed.metadata?.repoPath) {
      try {
        heartbeat(`Shannon pentest: ${seed.value}`);
        const shannonOut = await execDocker('apex-red-shannon', [
          'shannon', 'start', '-u', seed.value,
          '-r', seed.metadata.repoPath as string,
          '--json',
        ]);
        const result = JSON.parse(shannonOut || '{"findings":[]}');
        for (const f of result.findings ?? []) {
          await addFinding(investigationId, seed.id, {
            title: f.title, severity: f.severity, category: f.category,
            description: f.description, proof: f.proof,
            remediation: f.remediation, module: 'vuln_engine', tool: 'shannon',
            url: f.url, raw: f,
          });
          await postEvent(investigationId, 'finding', {
            severity: f.severity, title: f.title, module: 'vuln_engine',
          });
        }
      } catch {}
    }
  }

  return { discovered };
}

function mapNucleiTag(tags?: string[]): any {
  if (!tags) return 'other';
  if (tags.includes('sqli')) return 'injection';
  if (tags.includes('xss')) return 'xss';
  if (tags.includes('ssrf')) return 'ssrf';
  if (tags.includes('rce')) return 'code_vulnerability';
  if (tags.includes('lfi') || tags.includes('traversal')) return 'idor';
  if (tags.includes('exposure') || tags.includes('disclosure')) return 'info_disclosure';
  if (tags.includes('auth') || tags.includes('bypass')) return 'auth_bypass';
  if (tags.includes('misconfig')) return 'cloud_misconfiguration';
  if (tags.includes('cve')) return 'dependency_vulnerability';
  return 'other';
}
