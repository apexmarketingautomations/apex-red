import { heartbeat } from '@temporalio/activity';
import { execDocker } from '../utils/docker.js';
import { upsertEntity, upsertRelationship, addFinding, postEvent } from '../utils/graph.js';
import type { Entity } from '../../../shared/src/types/index.js';

export async function runOsint(investigationId: string, seeds: Entity[]) {
  let discovered = 0;

  for (const seed of seeds) {
    heartbeat(`OSINT: ${seed.type} ${seed.value}`);

    // ── Phone ─────────────────────────────────────────────────────────────
    if (seed.type === 'phone') {
      try {
        const out = await execDocker('apex-red-osint', [
          'phoneinfoga', 'scan', '-n', seed.value, '--format', 'json',
        ]);
        const data = JSON.parse(out || '{}');
        if (data.carrier) {
          await upsertEntity(investigationId, 'business_listing', data.carrier, {
            discoveredBy: 'phoneinfoga', discoveredFrom: seed.id,
            metadata: { lineType: data.line_type, country: data.country, local: data.local },
            confidence: 0.85,
          });
        }
        if (data.spam_score > 50) {
          await addFinding(investigationId, seed.id, {
            title: 'Phone flagged as spam/scam',
            severity: 'medium', category: 'osint',
            description: `Phone ${seed.value} has spam score ${data.spam_score}`,
            module: 'osint', tool: 'phoneinfoga',
          });
        }
        await postEvent(investigationId, 'entity_found', { type: 'phone_intel', value: seed.value, data });
      } catch {}
    }

    // ── Email ─────────────────────────────────────────────────────────────
    if (seed.type === 'email') {
      // Breach check via holehe (social reuse)
      try {
        const holeheOut = await execDocker('apex-red-osint', [
          'holehe', seed.value, '--only-used', '--no-color',
        ]);
        const lines = holeheOut.split('\n').filter(l => l.includes('[+]'));
        for (const line of lines) {
          const platform = line.replace('[+]', '').trim().split(' ')[0];
          const profileE = await upsertEntity(investigationId, 'social_profile', `${platform}:${seed.value}`, {
            discoveredBy: 'holehe', discoveredFrom: seed.id,
            metadata: { platform }, confidence: 0.8,
          });
          await upsertRelationship(investigationId, seed.id, profileE.id, 'linked_to', 'holehe');
          discovered++;
          await postEvent(investigationId, 'entity_found', { type: 'social_profile', value: `${platform}: ${seed.value}` });
        }
        if (lines.length > 3) {
          await addFinding(investigationId, seed.id, {
            title: `Email reused across ${lines.length} platforms`,
            severity: 'medium', category: 'social_exposure',
            description: `${seed.value} is registered on: ${lines.map(l => l.replace('[+]','').trim().split(' ')[0]).join(', ')}`,
            module: 'osint', tool: 'holehe',
          });
        }
      } catch {}

      // SPF/DKIM/DMARC check
      try {
        const domain = seed.value.split('@')[1];
        if (domain) {
          const dnsOut = await execDocker('apex-red-reconftw', [
            'dnsx', '-d', domain, '-txt', '-resp', '-json',
          ]);
          const hasSPF   = dnsOut.includes('v=spf1');
          const hasDMARC = dnsOut.includes('v=DMARC1');
          if (!hasSPF || !hasDMARC) {
            await addFinding(investigationId, seed.id, {
              title: `Email domain missing ${!hasSPF ? 'SPF' : ''}${!hasSPF && !hasDMARC ? ' and ' : ''}${!hasDMARC ? 'DMARC' : ''}`,
              severity: 'low', category: 'info_disclosure',
              description: `${domain} is missing email authentication records — susceptible to spoofing`,
              module: 'osint', tool: 'dnsx',
            });
          }
        }
      } catch {}
    }

    // ── Username ──────────────────────────────────────────────────────────
    if (seed.type === 'username') {
      try {
        const sherlockOut = await execDocker('apex-red-osint', [
          'python3', '-m', 'sherlock', seed.value, '--print-found', '--timeout', '5',
        ]);
        const found = sherlockOut.split('\n').filter(l => l.includes('[+]'));
        for (const line of found) {
          const urlMatch = line.match(/https?:\/\/[^\s]+/);
          if (!urlMatch) continue;
          const url = urlMatch[0];
          const platform = url.replace('https://', '').split('/')[0].replace('www.', '');
          const profileE = await upsertEntity(investigationId, 'social_profile', url, {
            discoveredBy: 'sherlock', discoveredFrom: seed.id,
            metadata: { platform, username: seed.value }, confidence: 0.85,
          });
          await upsertRelationship(investigationId, seed.id, profileE.id, 'uses', 'sherlock');
          discovered++;
          await postEvent(investigationId, 'entity_found', { type: 'social_profile', value: url });
        }
      } catch {}
    }

    // ── Company ───────────────────────────────────────────────────────────
    if (seed.type === 'company') {
      try {
        const harvOut = await execDocker('apex-red-osint', [
          'theHarvester', '-d', seed.value, '-b', 'bing,google,linkedin,twitter', '-l', '200',
        ]);

        // Extract emails
        const emailMatches = [...(harvOut.matchAll(/[\w.+-]+@[\w-]+\.[a-z]{2,}/gi))];
        for (const m of emailMatches) {
          const emailE = await upsertEntity(investigationId, 'email', m[0].toLowerCase(), {
            discoveredBy: 'theHarvester', discoveredFrom: seed.id, confidence: 0.75,
          });
          await upsertRelationship(investigationId, seed.id, emailE.id, 'owns', 'theHarvester');
          discovered++;
        }

        // Extract domains
        const domainMatches = [...(harvOut.matchAll(/(?:^|\s)((?:[a-z0-9-]+\.)+[a-z]{2,})/gim))];
        for (const m of domainMatches) {
          const domE = await upsertEntity(investigationId, 'domain', m[1].toLowerCase(), {
            discoveredBy: 'theHarvester', discoveredFrom: seed.id, confidence: 0.7,
          });
          await upsertRelationship(investigationId, seed.id, domE.id, 'owns', 'theHarvester');
          discovered++;
        }

        if (emailMatches.length > 0) {
          await postEvent(investigationId, 'module_progress', {
            module: 'osint', message: `Found ${emailMatches.length} emails for ${seed.value}`,
          });
        }
      } catch {}
    }
  }

  return { discovered };
}
