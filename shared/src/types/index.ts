// Core target types — anything can be a starting point
export type TargetType =
  | 'domain'
  | 'ip'
  | 'cidr'
  | 'asn'
  | 'email'
  | 'phone'
  | 'url'
  | 'company'
  | 'github_org'
  | 'wifi_ssid'
  | 'file'
  | 'person';

export interface Target {
  id: string;
  type: TargetType;
  value: string;
  label?: string;
  scope: 'in' | 'out'; // in = authorized, out = discovered but excluded
  discoveredFrom?: string; // parent target id
  createdAt: Date;
}

export interface Scan {
  id: string;
  name: string;
  targets: Target[];
  status: ScanStatus;
  phases: PhaseStatus[];
  findings: Finding[];
  createdAt: Date;
  startedAt?: Date;
  completedAt?: Date;
}

export type ScanStatus =
  | 'pending'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed';

export type PhaseType =
  | 'recon'
  | 'surface_mapping'
  | 'vuln_scan'
  | 'pentest'
  | 'post_exploit'
  | 'ad_mapping'
  | 'report';

export interface PhaseStatus {
  phase: PhaseType;
  status: 'pending' | 'running' | 'completed' | 'skipped' | 'failed';
  startedAt?: Date;
  completedAt?: Date;
  toolsUsed: string[];
  targetsDiscovered: number;
  findingsCount: number;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  scanId: string;
  targetId: string;
  title: string;
  severity: Severity;
  category: FindingCategory;
  description: string;
  proof?: string; // PoC exploit or evidence
  remediation?: string;
  tool: string;
  cve?: string;
  cwe?: string;
  url?: string;
  raw?: unknown;
  createdAt: Date;
}

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
  | 'wifi'
  | 'osint'
  | 'default_creds'
  | 'other';

export interface DiscoveredHost {
  scanId: string;
  hostname?: string;
  ip?: string;
  ports: OpenPort[];
  technologies: string[];
  discoveredBy: string;
  createdAt: Date;
}

export interface OpenPort {
  port: number;
  protocol: 'tcp' | 'udp';
  service?: string;
  version?: string;
  banner?: string;
}

export interface ScanConfig {
  name: string;
  targets: Array<{ type: TargetType; value: string }>;
  phases: {
    recon: boolean;
    vulnScan: boolean;
    pentest: boolean;
    postExploit: boolean;
    adMapping: boolean;
    wifi: boolean;
  };
  depth: 'surface' | 'standard' | 'deep';
  maxHosts: number;
  maxDuration: number; // minutes
  anthropicApiKey?: string;
  reportFormat: 'pdf' | 'html' | 'json' | 'all';
}
