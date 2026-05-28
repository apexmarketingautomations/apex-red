import { db } from './db.js';
import type { EntityType, RelationshipType, Severity, FindingCategory, ModuleId } from '../../../shared/src/types/index.js';

// ── Entity upsert ──────────────────────────────────────────────────────────

export async function upsertEntity(
  investigationId: string,
  type: EntityType,
  value: string,
  opts: {
    label?: string;
    metadata?: Record<string, unknown>;
    discoveredBy?: string;
    discoveredFrom?: string;
    confidence?: number;
    isSeed?: boolean;
  } = {}
) {
  const { rows } = await db.query(
    `INSERT INTO entities (investigation_id, type, value, label, metadata, discovered_by, discovered_from, confidence, is_seed)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     ON CONFLICT (investigation_id, type, value) DO UPDATE SET
       label = COALESCE(EXCLUDED.label, entities.label),
       metadata = entities.metadata || EXCLUDED.metadata,
       confidence = GREATEST(entities.confidence, EXCLUDED.confidence)
     RETURNING *`,
    [investigationId, type, value, opts.label ?? null,
     JSON.stringify(opts.metadata ?? {}), opts.discoveredBy ?? null,
     opts.discoveredFrom ?? null, opts.confidence ?? 0.8, opts.isSeed ?? false]
  );
  return rows[0];
}

// ── Relationship upsert ────────────────────────────────────────────────────

export async function upsertRelationship(
  investigationId: string,
  fromId: string,
  toId: string,
  type: RelationshipType,
  discoveredBy: string,
  confidence = 0.9
) {
  await db.query(
    `INSERT INTO relationships (investigation_id, from_entity_id, to_entity_id, type, discovered_by, confidence)
     VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (investigation_id, from_entity_id, to_entity_id, type) DO NOTHING`,
    [investigationId, fromId, toId, type, discoveredBy, confidence]
  );
}

// ── Finding insert ─────────────────────────────────────────────────────────

export async function addFinding(
  investigationId: string,
  entityId: string | null | undefined,
  f: {
    title: string;
    severity: Severity;
    category: FindingCategory;
    description: string;
    proof?: string;
    remediation?: string;
    module: ModuleId;
    tool: string;
    cve?: string;
    cwe?: string;
    url?: string;
    raw?: unknown;
  }
) {
  const { rows } = await db.query(
    `INSERT INTO findings (investigation_id, entity_id, title, severity, category, description,
       proof, remediation, module, tool, cve, cwe, url, raw)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
     RETURNING id`,
    [investigationId, entityId ?? null, f.title, f.severity, f.category, f.description,
     f.proof ?? null, f.remediation ?? null, f.module, f.tool,
     f.cve ?? null, f.cwe ?? null, f.url ?? null, f.raw ? JSON.stringify(f.raw) : null]
  );
  return rows[0]?.id;
}

// ── Evidence insert ────────────────────────────────────────────────────────

export async function addEvidence(
  investigationId: string,
  opts: {
    entityId?: string;
    findingId?: string;
    type: string;
    title: string;
    content?: string;
    filePath?: string;
    sourceUrl?: string;
    tool: string;
  }
) {
  await db.query(
    `INSERT INTO evidence (investigation_id, entity_id, finding_id, type, title, content, file_path, source_url, tool)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [investigationId, opts.entityId ?? null, opts.findingId ?? null, opts.type,
     opts.title, opts.content ?? null, opts.filePath ?? null, opts.sourceUrl ?? null, opts.tool]
  );
}

// ── Module status ──────────────────────────────────────────────────────────

export async function updateModuleStatus(
  investigationId: string,
  module: string,
  status: string,
  counts?: { entities?: number; findings?: number }
) {
  await db.query(
    `INSERT INTO module_runs (investigation_id, module, status, started_at, completed_at,
       entities_discovered, findings_count)
     VALUES ($1,$2,$3,
       CASE WHEN $3='running' THEN NOW() END,
       CASE WHEN $3='completed' OR $3='failed' THEN NOW() END,
       $4, $5)
     ON CONFLICT (investigation_id, module) DO UPDATE SET
       status=EXCLUDED.status,
       started_at=COALESCE(module_runs.started_at, EXCLUDED.started_at),
       completed_at=EXCLUDED.completed_at,
       entities_discovered=EXCLUDED.entities_discovered,
       findings_count=EXCLUDED.findings_count`,
    [investigationId, module, status, counts?.entities ?? 0, counts?.findings ?? 0]
  );
}

// ── SSE event push ─────────────────────────────────────────────────────────

export async function postEvent(investigationId: string, event: string, data: unknown) {
  try {
    await fetch(`http://localhost:4000/internal/events/${investigationId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event, data }),
    });
  } catch {
    // API may not be reachable from worker container — log and continue
    console.log(`[event] ${investigationId} ${event}`, data);
  }
}
