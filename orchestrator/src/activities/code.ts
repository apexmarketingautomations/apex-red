import { heartbeat } from '@temporalio/activity';
import { execDocker } from '../utils/docker.js';
import { upsertEntity, upsertRelationship, addFinding, addEvidence, postEvent } from '../utils/graph.js';
import type { Entity } from '../../../shared/src/types/index.js';

export async function runCodeIntel(investigationId: string, seeds: Entity[]) {
  const repoSeeds = seeds.filter(e => e.type === 'repo');
  let discovered = 0;

  for (const seed of repoSeeds) {
    heartbeat(`Code Intel: ${seed.value}`);

    // 1. Secrets via trufflehog
    try {
      const tfOut = await execDocker('apex-red-code', [
        'trufflehog', 'git', seed.value, '--json', '--only-verified',
      ]);
      for (const line of tfOut.trim().split('\n').filter(Boolean)) {
        try {
          const secret = JSON.parse(line);
          const credE = await upsertEntity(investigationId, 'credential', secret.DetectorName + ':' + secret.Raw?.slice(0, 16), {
            discoveredBy: 'trufflehog', discoveredFrom: seed.id,
            metadata: { detector: secret.DetectorName, file: secret.SourceMetadata?.Data?.Git?.file,
                        commit: secret.SourceMetadata?.Data?.Git?.commit },
            confidence: 0.95,
          });
          await upsertRelationship(investigationId, seed.id, credE.id, 'leaked_from', 'trufflehog');
          await addFinding(investigationId, seed.id, {
            title: `Verified secret: ${secret.DetectorName}`,
            severity: 'critical', category: 'leaked_secret',
            description: `A verified ${secret.DetectorName} credential was found in commit history`,
            proof: `File: ${secret.SourceMetadata?.Data?.Git?.file}\nCommit: ${secret.SourceMetadata?.Data?.Git?.commit}`,
            remediation: 'Immediately revoke the credential and rotate. Remove from git history using git-filter-repo.',
            module: 'code_intel', tool: 'trufflehog',
          });
          await postEvent(investigationId, 'finding', {
            severity: 'critical', title: `Verified secret: ${secret.DetectorName}`, module: 'code_intel',
          });
          discovered++;
        } catch {}
      }
    } catch {}

    // 2. Semgrep SAST
    try {
      const semOut = await execDocker('apex-red-code', [
        'semgrep', '--config=auto', seed.value, '--json', '--quiet',
      ]);
      const results = JSON.parse(semOut || '{"results":[]}');
      for (const r of results.results?.slice(0, 50) ?? []) {
        const sev = r.extra?.severity === 'ERROR' ? 'high' : r.extra?.severity === 'WARNING' ? 'medium' : 'low';
        await addFinding(investigationId, seed.id, {
          title: r.check_id?.split('.').pop() ?? 'Code vulnerability',
          severity: sev as any, category: 'code_vulnerability',
          description: r.extra?.message ?? '',
          proof: `${r.path}:${r.start?.line}`,
          remediation: r.extra?.fix ?? undefined,
          module: 'code_intel', tool: 'semgrep',
          url: r.path,
        });
      }
      if (results.results?.length > 0) {
        await postEvent(investigationId, 'module_progress', {
          module: 'code_intel', message: `Semgrep: ${results.results.length} findings`,
        });
      }
    } catch {}

    // 3. Dependency vulns via trivy
    try {
      const trivyOut = await execDocker('apex-red-code', [
        'trivy', 'repo', seed.value, '--format', 'json', '--quiet',
      ]);
      const report = JSON.parse(trivyOut || '{"Results":[]}');
      for (const result of report.Results ?? []) {
        for (const vuln of result.Vulnerabilities?.slice(0, 30) ?? []) {
          const depE = await upsertEntity(investigationId, 'dependency', `${vuln.PkgName}@${vuln.InstalledVersion}`, {
            discoveredBy: 'trivy', discoveredFrom: seed.id,
            metadata: { fixedVersion: vuln.FixedVersion, cve: vuln.VulnerabilityID },
            confidence: 1.0,
          });
          await upsertRelationship(investigationId, seed.id, depE.id, 'contains', 'trivy');
          const sev = ({ CRITICAL:'critical', HIGH:'high', MEDIUM:'medium', LOW:'low' } as any)[vuln.Severity] ?? 'info';
          await addFinding(investigationId, depE.id, {
            title: `${vuln.VulnerabilityID} in ${vuln.PkgName}`,
            severity: sev, category: 'dependency_vulnerability',
            description: vuln.Description ?? '',
            proof: `Installed: ${vuln.InstalledVersion}, Fixed in: ${vuln.FixedVersion ?? 'N/A'}`,
            remediation: vuln.FixedVersion ? `Upgrade ${vuln.PkgName} to ${vuln.FixedVersion}` : 'No fix available — consider alternative package',
            module: 'code_intel', tool: 'trivy', cve: vuln.VulnerabilityID,
          });
          discovered++;
        }
      }
    } catch {}

    // 4. CI/CD config detection
    try {
      const ciFiles = ['.github/workflows', '.circleci', 'Jenkinsfile', '.travis.yml', '.gitlab-ci.yml'];
      for (const f of ciFiles) {
        const lsOut = await execDocker('apex-red-code', ['ls', `${seed.value}/${f}`]).catch(() => '');
        if (lsOut.trim()) {
          const ciE = await upsertEntity(investigationId, 'ci_cd_config', `${seed.value}/${f}`, {
            discoveredBy: 'code_intel', discoveredFrom: seed.id,
            metadata: { file: f }, confidence: 1.0,
          });
          await upsertRelationship(investigationId, seed.id, ciE.id, 'contains', 'code_intel');
          discovered++;
        }
      }
    } catch {}
  }

  return { discovered };
}
