CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Scans
CREATE TABLE IF NOT EXISTS scans (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name        TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'pending',
  config      JSONB NOT NULL DEFAULT '{}',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at  TIMESTAMPTZ,
  completed_at TIMESTAMPTZ
);

-- Targets (seed targets + everything discovered)
CREATE TABLE IF NOT EXISTS targets (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  type            TEXT NOT NULL,
  value           TEXT NOT NULL,
  label           TEXT,
  scope           TEXT NOT NULL DEFAULT 'in',
  discovered_from UUID REFERENCES targets(id),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Discovered hosts
CREATE TABLE IF NOT EXISTS hosts (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  target_id       UUID REFERENCES targets(id),
  hostname        TEXT,
  ip              TEXT,
  ports           JSONB NOT NULL DEFAULT '[]',
  technologies    JSONB NOT NULL DEFAULT '[]',
  discovered_by   TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Phase tracking
CREATE TABLE IF NOT EXISTS phases (
  id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id             UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  phase               TEXT NOT NULL,
  status              TEXT NOT NULL DEFAULT 'pending',
  tools_used          JSONB NOT NULL DEFAULT '[]',
  targets_discovered  INTEGER NOT NULL DEFAULT 0,
  findings_count      INTEGER NOT NULL DEFAULT 0,
  started_at          TIMESTAMPTZ,
  completed_at        TIMESTAMPTZ
);

-- Findings (all tools write here)
CREATE TABLE IF NOT EXISTS findings (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scan_id       UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  target_id     UUID REFERENCES targets(id),
  host_id       UUID REFERENCES hosts(id),
  title         TEXT NOT NULL,
  severity      TEXT NOT NULL,
  category      TEXT NOT NULL,
  description   TEXT NOT NULL,
  proof         TEXT,
  remediation   TEXT,
  tool          TEXT NOT NULL,
  cve           TEXT,
  cwe           TEXT,
  url           TEXT,
  raw           JSONB,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_targets_scan ON targets(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
