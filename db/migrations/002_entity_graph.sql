-- Drop old tables, replace with entity graph model
DROP TABLE IF EXISTS phases CASCADE;
DROP TABLE IF EXISTS hosts CASCADE;
DROP TABLE IF EXISTS targets CASCADE;
DROP TABLE IF EXISTS findings CASCADE;
DROP TABLE IF EXISTS scans CASCADE;

-- ── Investigations (replaces scans) ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS investigations (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name         TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending',
  config       JSONB NOT NULL DEFAULT '{}',
  ai_report    TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at   TIMESTAMPTZ,
  completed_at TIMESTAMPTZ
);

-- ── Entities (graph nodes) ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS entities (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  investigation_id  UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  type              TEXT NOT NULL,
  value             TEXT NOT NULL,
  label             TEXT,
  metadata          JSONB NOT NULL DEFAULT '{}',
  is_seed           BOOLEAN NOT NULL DEFAULT false,
  discovered_by     TEXT,
  discovered_from   UUID REFERENCES entities(id),
  confidence        NUMERIC(3,2) NOT NULL DEFAULT 1.0,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (investigation_id, type, value)
);

-- ── Relationships (graph edges) ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS relationships (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  from_entity_id   UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  to_entity_id     UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  type             TEXT NOT NULL,
  label            TEXT,
  confidence       NUMERIC(3,2) NOT NULL DEFAULT 1.0,
  discovered_by    TEXT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (investigation_id, from_entity_id, to_entity_id, type)
);

-- ── Findings ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  entity_id        UUID REFERENCES entities(id) ON DELETE SET NULL,
  title            TEXT NOT NULL,
  severity         TEXT NOT NULL,
  category         TEXT NOT NULL,
  description      TEXT NOT NULL,
  proof            TEXT,
  remediation      TEXT,
  module           TEXT NOT NULL,
  tool             TEXT NOT NULL,
  cve              TEXT,
  cwe              TEXT,
  url              TEXT,
  raw              JSONB,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Evidence locker ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS evidence (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  entity_id        UUID REFERENCES entities(id) ON DELETE SET NULL,
  finding_id       UUID REFERENCES findings(id) ON DELETE SET NULL,
  type             TEXT NOT NULL,
  title            TEXT NOT NULL,
  content          TEXT,
  file_path        TEXT,
  source_url       TEXT,
  tool             TEXT NOT NULL,
  timestamp        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Risk scores (per entity) ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS risk_scores (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  entity_id        UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  exposure         NUMERIC(5,2) NOT NULL DEFAULT 0,
  exploitability   NUMERIC(5,2) NOT NULL DEFAULT 0,
  business_impact  NUMERIC(5,2) NOT NULL DEFAULT 0,
  confidence       NUMERIC(5,2) NOT NULL DEFAULT 0,
  overall          NUMERIC(5,2) NOT NULL DEFAULT 0,
  factors          JSONB NOT NULL DEFAULT '[]',
  computed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (entity_id)
);

-- ── Module status tracking ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS module_runs (
  id                   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  investigation_id     UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
  module               TEXT NOT NULL,
  status               TEXT NOT NULL DEFAULT 'pending',
  entities_discovered  INTEGER NOT NULL DEFAULT 0,
  findings_count       INTEGER NOT NULL DEFAULT 0,
  started_at           TIMESTAMPTZ,
  completed_at         TIMESTAMPTZ,
  error                TEXT,
  UNIQUE (investigation_id, module)
);

-- ── Indexes ───────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_entities_inv     ON entities(investigation_id);
CREATE INDEX IF NOT EXISTS idx_entities_type    ON entities(type);
CREATE INDEX IF NOT EXISTS idx_relationships_inv ON relationships(investigation_id);
CREATE INDEX IF NOT EXISTS idx_relationships_from ON relationships(from_entity_id);
CREATE INDEX IF NOT EXISTS idx_relationships_to   ON relationships(to_entity_id);
CREATE INDEX IF NOT EXISTS idx_findings_inv      ON findings(investigation_id);
CREATE INDEX IF NOT EXISTS idx_findings_entity   ON findings(entity_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_evidence_inv      ON evidence(investigation_id);
CREATE INDEX IF NOT EXISTS idx_risk_entity       ON risk_scores(entity_id);
