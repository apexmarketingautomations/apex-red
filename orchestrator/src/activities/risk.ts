import { heartbeat } from '@temporalio/activity';
import { db } from '../utils/db.js';
import { postEvent } from '../utils/graph.js';

export async function runRiskScoring(investigationId: string) {
  heartbeat('Computing risk scores');

  const entities = await db.query(
    `SELECT e.*, COUNT(f.id) AS finding_count,
       COUNT(f.id) FILTER (WHERE f.severity='critical') AS crit,
       COUNT(f.id) FILTER (WHERE f.severity='high') AS high,
       COUNT(f.id) FILTER (WHERE f.severity='medium') AS med
     FROM entities e
     LEFT JOIN findings f ON f.entity_id = e.id
     WHERE e.investigation_id = $1
     GROUP BY e.id`,
    [investigationId]
  );

  for (const entity of entities.rows) {
    heartbeat(`Scoring: ${entity.type} ${entity.value}`);

    const crit = parseInt(entity.crit ?? 0);
    const high = parseInt(entity.high ?? 0);
    const med  = parseInt(entity.med  ?? 0);
    const total = parseInt(entity.finding_count ?? 0);

    // Exposure: how publicly visible/reachable is this entity
    const exposureBase: Record<string, number> = {
      domain: 90, subdomain: 80, ip: 75, url: 85, email: 70,
      phone: 60, username: 65, social_profile: 60, bucket: 95,
      api_endpoint: 85, repo: 70, credential: 100, vulnerability: 100,
    };
    let exposure = exposureBase[entity.type] ?? 50;

    // Exploitability: driven by findings
    let exploitability = Math.min(100,
      crit * 30 + high * 15 + med * 5
    );

    // Business impact: entity type + seed status
    let businessImpact = entity.is_seed ? 80 : 50;
    if (entity.type === 'credential')   businessImpact = 100;
    if (entity.type === 'bucket')       businessImpact = 85;
    if (entity.type === 'api_endpoint') businessImpact = 80;
    if (entity.type === 'vulnerability') businessImpact = 90;

    // Confidence: based on how findings were detected
    const confidence = Math.min(100, 50 + total * 5);

    // Overall: weighted
    const overall = Math.round(
      exposure * 0.25 +
      exploitability * 0.35 +
      businessImpact * 0.30 +
      confidence * 0.10
    );

    const factors: string[] = [];
    if (crit > 0) factors.push(`${crit} critical finding${crit > 1 ? 's' : ''}`);
    if (high > 0) factors.push(`${high} high finding${high > 1 ? 's' : ''}`);
    if (entity.is_seed) factors.push('Primary target');
    if (entity.type === 'credential') factors.push('Leaked credential');
    if (entity.type === 'bucket') factors.push('Public cloud storage');
    if (total === 0) factors.push('No findings');

    await db.query(
      `INSERT INTO risk_scores
         (investigation_id, entity_id, exposure, exploitability, business_impact, confidence, overall, factors)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (entity_id) DO UPDATE SET
         exposure=EXCLUDED.exposure, exploitability=EXCLUDED.exploitability,
         business_impact=EXCLUDED.business_impact, confidence=EXCLUDED.confidence,
         overall=EXCLUDED.overall, factors=EXCLUDED.factors, computed_at=NOW()`,
      [investigationId, entity.id, exposure, exploitability, businessImpact,
       confidence, overall, JSON.stringify(factors)]
    );
  }

  await postEvent(investigationId, 'module_progress', {
    module: 'risk_scoring', message: `Scored ${entities.rows.length} entities`,
  });

  return { scored: entities.rows.length };
}
