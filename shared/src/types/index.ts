// ─── Entity Types ──────────────────────────────────────────────────────────
// Every node in the identity graph is an Entity

export type EntityType =
  | 'person'
  | 'phone'
  | 'email'
  | 'username'
  | 'company'
  | 'domain'
  | 'subdomain'
  | 'ip'
  | 'cidr'
  | 'asn'
  | 'url'
  | 'app'
  | 'repo'
  | 'cloud_account'
  | 'bucket'
  | 'api_endpoint'
  | 'credential'
  | 'certificate'
  | 'social_profile'
  | 'business_listing'
  | 'port'
  | 'vulnerability'
  | 'breach'
  | 'ci_cd_config'
  | 'dependency'
  | 'employee'
  | 'dns_record';

// Seed entity types — what a user can start with
export type SeedEntityType =
  | 'person'
  | 'phone'
  | 'email'
  | 'username'
  | 'company'
  | 'domain'
  | 'ip'
  | 'cidr'
  | 'app'
  | 'repo'
  | 'cloud_account';

export interface Entity {
  id: string;
  investigationId: string;
  type: EntityType;
  value: string;          // canonical identifier (domain, phone E.164, email, etc.)
  label?: string;         // human-readable name
  metadata: Record<string, unknown>;
  riskScore?: RiskScore;
  isSeed: boolean;        // true = user provided, false = discovered
  discoveredBy?: string;  // module that found it
  discoveredFrom?: string; // parent entity id
  confidence: number;     // 0–1 how confident we are this is real/accurate
  createdAt: Date;
}

// ─── Relationship (Graph Edge) ─────────────────────────────────────────────

export type RelationshipType =
  | 'owns'
  | 'hosts'
  | 'resolves_to'
  | 'registered_by'
  | 'works_at'
  | 'uses'
  | 'exposed_in'
  | 'linked_to'
  | 'certificate_for'
  | 'subdomain_of'
  | 'contains'
  | 'leaked_from'
  | 'connects_to'
  | 'derived_from';

export interface Relationship {
  id: string;
  investigationId: string;
  fromEntityId: string;
  toEntityId: string;
  type: RelationshipType;
  label?: string;
  confidence: number;
  discoveredBy: string;
  createdAt: Date;
}

// ─── Risk Scoring ──────────────────────────────────────────────────────────

export interface RiskScore {
  exposure: number;       // 0–100: how exposed is this entity publicly
  exploitability: number; // 0–100: how easy to exploit
  businessImpact: number; // 0–100: damage if compromised
  confidence: number;     // 0–100: how certain is this score
  overall: number;        // weighted composite
  factors: string[];      // reasons driving the score
}

// ─── Evidence ──────────────────────────────────────────────────────────────

export type EvidenceType =
  | 'screenshot'
  | 'raw_output'
  | 'api_response'
  | 'file'
  | 'log'
  | 'proof_of_concept';

export interface Evidence {
  id: string;
  investigationId: string;
  entityId?: string;
  findingId?: string;
  type: EvidenceType;
  title: string;
  content?: string;       // text/JSON content
  filePath?: string;      // local path for binaries/screenshots
  sourceUrl?: string;
  tool: string;
  timestamp: Date;
}

// ─── Finding ───────────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingCategory =
  | 'injection'
  | 'xss'
  | 'ssrf'
  | 'auth_bypass'
  | 'idor'
  | 'privilege_escalation'
  | 'info_disclosure'
  | 'exposed_asset'
  | 'leaked_secret'
  | 'open_port'
  | 'subdomain_takeover'
  | 'cloud_misconfiguration'
  | 'breach_exposure'
  | 'social_exposure'
  | 'code_vulnerability'
  | 'dependency_vulnerability'
  | 'default_creds'
  | 'wifi'
  | 'osint'
  | 'other';

export interface Finding {
  id: string;
  investigationId: string;
  entityId?: string;
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
  createdAt: Date;
}

// ─── Modules ───────────────────────────────────────────────────────────────

export type ModuleId =
  | 'recon'
  | 'osint'
  | 'code_intel'
  | 'vuln_engine'
  | 'cloud'
  | 'identity_graph'
  | 'risk_scoring'
  | 'evidence_locker'
  | 'ai_analyst';

export interface ModuleConfig {
  id: ModuleId;
  enabled: boolean;
}

// Which modules apply to which entity types
export const MODULE_ENTITY_MAP: Record<ModuleId, EntityType[]> = {
  recon:          ['domain', 'subdomain', 'ip', 'cidr', 'asn', 'url', 'app'],
  osint:          ['person', 'phone', 'email', 'username', 'company', 'domain'],
  code_intel:     ['repo', 'app', 'domain'],
  vuln_engine:    ['domain', 'subdomain', 'ip', 'url', 'app', 'api_endpoint'],
  cloud:          ['cloud_account', 'domain', 'company', 'bucket'],
  identity_graph: ['person', 'email', 'phone', 'username', 'company', 'domain'],
  risk_scoring:   ['person', 'phone', 'email', 'username', 'company', 'domain', 'ip', 'repo', 'cloud_account'],
  evidence_locker:['domain', 'ip', 'url', 'api_endpoint', 'bucket'],
  ai_analyst:     ['domain', 'company', 'person', 'repo'],
};

// ─── Investigation (replaces Scan) ─────────────────────────────────────────

export type InvestigationStatus =
  | 'pending'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed';

export interface ModuleStatus {
  module: ModuleId;
  status: 'pending' | 'running' | 'completed' | 'skipped' | 'failed';
  entitiesDiscovered: number;
  findingsCount: number;
  startedAt?: Date;
  completedAt?: Date;
}

export interface Investigation {
  id: string;
  name: string;
  status: InvestigationStatus;
  seeds: Array<{ type: SeedEntityType; value: string }>;
  modules: ModuleConfig[];
  depth: 'surface' | 'standard' | 'deep';
  entities: Entity[];
  relationships: Relationship[];
  findings: Finding[];
  evidence: Evidence[];
  moduleStatuses: ModuleStatus[];
  aiReport?: string;
  createdAt: Date;
  startedAt?: Date;
  completedAt?: Date;
}

// ─── Tool Registry ─────────────────────────────────────────────────────────

export interface ToolAssignment {
  entityType: EntityType;
  module: ModuleId;
  tool: string;
  description: string;
}

export const TOOL_REGISTRY: ToolAssignment[] = [
  // Recon
  { entityType: 'domain',   module: 'recon', tool: 'subfinder',   description: 'Subdomain enumeration' },
  { entityType: 'domain',   module: 'recon', tool: 'amass',       description: 'ASN / IP range discovery' },
  { entityType: 'domain',   module: 'recon', tool: 'httpx',       description: 'Live host + tech fingerprint' },
  { entityType: 'domain',   module: 'recon', tool: 'nmap',        description: 'Port scanning' },
  { entityType: 'domain',   module: 'recon', tool: 'dnsx',        description: 'DNS records (A/MX/TXT/CNAME/NS)' },
  { entityType: 'domain',   module: 'recon', tool: 'crtsh',       description: 'Certificate transparency logs' },
  { entityType: 'ip',       module: 'recon', tool: 'nmap',        description: 'Port + service scan' },
  { entityType: 'cidr',     module: 'recon', tool: 'masscan',     description: 'Fast CIDR port sweep' },
  // OSINT
  { entityType: 'phone',    module: 'osint', tool: 'phoneinfoga', description: 'Carrier, line type, reputation' },
  { entityType: 'email',    module: 'osint', tool: 'holehe',      description: 'Social profile reuse check' },
  { entityType: 'email',    module: 'osint', tool: 'emailrep',    description: 'Breach exposure + reputation' },
  { entityType: 'email',    module: 'osint', tool: 'mxtoolbox',   description: 'SPF/DKIM/DMARC/MX check' },
  { entityType: 'username', module: 'osint', tool: 'sherlock',    description: 'Cross-platform username reuse' },
  { entityType: 'username', module: 'osint', tool: 'maigret',     description: 'Deep username OSINT' },
  { entityType: 'company',  module: 'osint', tool: 'theHarvester',description: 'Employee emails + subdomains' },
  { entityType: 'person',   module: 'osint', tool: 'maigret',     description: 'Person identity graph' },
  // Code Intel
  { entityType: 'repo',     module: 'code_intel', tool: 'trufflehog', description: 'Secrets scanning' },
  { entityType: 'repo',     module: 'code_intel', tool: 'gitleaks',   description: 'Hardcoded credentials' },
  { entityType: 'repo',     module: 'code_intel', tool: 'semgrep',    description: 'Static code analysis' },
  { entityType: 'repo',     module: 'code_intel', tool: 'trivy',      description: 'Dependency CVEs' },
  { entityType: 'repo',     module: 'code_intel', tool: 'shannon',    description: 'AI pentest (white-box)' },
  // Vuln Engine
  { entityType: 'domain',   module: 'vuln_engine', tool: 'nuclei', description: '10k+ vulnerability templates' },
  { entityType: 'url',      module: 'vuln_engine', tool: 'zap',    description: 'Web app scanner' },
  { entityType: 'domain',   module: 'vuln_engine', tool: 'nikto',  description: 'Web server misconfigs' },
  // Cloud
  { entityType: 'company',  module: 'cloud', tool: 'cloud_enum',  description: 'S3/Azure/GCP bucket discovery' },
  { entityType: 'company',  module: 'cloud', tool: 'prowler',     description: 'Cloud misconfiguration audit' },
  { entityType: 'bucket',   module: 'cloud', tool: 's3scanner',   description: 'Public bucket content scan' },
];
