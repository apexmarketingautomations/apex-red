import { heartbeat } from '@temporalio/activity';
import { execDocker } from '../utils/docker.js';
import { upsertEntity, upsertRelationship, addFinding, postEvent } from '../utils/graph.js';
import type { Entity } from '../../../shared/src/types/index.js';

export async function runCloud(investigationId: string, seeds: Entity[]) {
  let discovered = 0;

  for (const seed of seeds) {
    heartbeat(`Cloud: ${seed.type} ${seed.value}`);

    // ── S3 / Azure / GCP bucket discovery ─────────────────────────────────
    if (seed.type === 'company' || seed.type === 'domain') {
      const keyword = seed.value.replace(/\.[a-z]{2,}$/, '').toLowerCase();
      try {
        const cloudOut = await execDocker('apex-red-cloud', [
          'cloud_enum', '-k', keyword, '--disable-gcp', // start with S3/Azure
          '--threads', '10',
        ]);

        const bucketMatches = [...cloudOut.matchAll(/OPEN\s+(https?:\/\/[^\s]+)/g)];
        for (const m of bucketMatches) {
          const bucketE = await upsertEntity(investigationId, 'bucket', m[1], {
            discoveredBy: 'cloud_enum', discoveredFrom: seed.id,
            metadata: { url: m[1], status: 'open' }, confidence: 0.95,
          });
          await upsertRelationship(investigationId, seed.id, bucketE.id, 'owns', 'cloud_enum');
          await addFinding(investigationId, bucketE.id, {
            title: 'Public cloud storage bucket exposed',
            severity: 'high', category: 'cloud_misconfiguration',
            description: `Publicly accessible bucket found: ${m[1]}`,
            proof: m[1],
            remediation: 'Set bucket ACL to private. Enable server-side encryption. Enable access logging.',
            module: 'cloud', tool: 'cloud_enum', url: m[1],
          });
          await postEvent(investigationId, 'finding', {
            severity: 'high', title: 'Public bucket exposed', value: m[1], module: 'cloud',
          });
          discovered++;
        }
      } catch {}

      // GitHub org leak check via trufflehog
      try {
        const ghOut = await execDocker('apex-red-code', [
          'trufflehog', 'github', '--org', keyword, '--json', '--only-verified',
        ]);
        for (const line of ghOut.trim().split('\n').filter(Boolean)) {
          try {
            const secret = JSON.parse(line);
            const repoUrl = secret.SourceMetadata?.Data?.GitHub?.repository;
            if (repoUrl) {
              const repoE = await upsertEntity(investigationId, 'repo', repoUrl, {
                discoveredBy: 'trufflehog', discoveredFrom: seed.id, confidence: 1.0,
              });
              await upsertRelationship(investigationId, seed.id, repoE.id, 'owns', 'trufflehog');
              await addFinding(investigationId, repoE.id, {
                title: `Verified secret in GitHub org: ${secret.DetectorName}`,
                severity: 'critical', category: 'leaked_secret',
                description: `${secret.DetectorName} credential leaked in repo: ${repoUrl}`,
                proof: `Repo: ${repoUrl}\nFile: ${secret.SourceMetadata?.Data?.GitHub?.file}`,
                remediation: 'Revoke credential immediately. Run git-filter-repo to remove from history.',
                module: 'cloud', tool: 'trufflehog',
              });
              discovered++;
              await postEvent(investigationId, 'finding', {
                severity: 'critical', title: `GitHub secret: ${secret.DetectorName}`, module: 'cloud',
              });
            }
          } catch {}
        }
      } catch {}
    }

    // ── Known bucket: scan contents ────────────────────────────────────────
    if (seed.type === 'bucket') {
      try {
        const s3Out = await execDocker('apex-red-cloud', [
          's3scanner', 'scan', '--bucket-file', '-', '--format', 'json',
        ], seed.value);
        const result = JSON.parse(s3Out || '{}');
        if (result.exists && result.public) {
          await addFinding(investigationId, seed.id, {
            title: 'S3 bucket publicly readable',
            severity: 'high', category: 'cloud_misconfiguration',
            description: `Bucket ${seed.value} allows public read access`,
            proof: JSON.stringify(result, null, 2),
            remediation: 'Apply bucket policy to deny s3:GetObject for Principal: *',
            module: 'cloud', tool: 's3scanner', url: `https://${seed.value}.s3.amazonaws.com`,
          });
        }
      } catch {}
    }
  }

  return { discovered };
}
