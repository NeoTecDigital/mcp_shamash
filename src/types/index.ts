export interface ProjectScope {
  projectRoot: string;
  networks: NetworkDefinition[];
  services: ServiceDefinition[];
  containers: ContainerDefinition[];
  allowedPaths: string[];
  deniedPaths: string[];
  excludedRanges: string[];
  allowedPorts: number[];
}

export interface NetworkDefinition {
  name: string;
  subnet: string;
  gateway?: string;
  type: 'docker' | 'kubernetes' | 'local';
  internal?: boolean;
}

export interface ServiceDefinition {
  name: string;
  network: string;
  ports: number[];
  internal: boolean;
  protocol?: 'tcp' | 'udp';
}

export interface ContainerDefinition {
  id: string;
  name: string;
  image: string;
  networks: Record<string, any>;
  ports: number[];
}

export interface BoundaryValidation {
  allowed: boolean;
  reason?: string;
  scope?: NetworkDefinition;
  violations?: string[];
}

export interface ScanRequest {
  type: 'project' | 'network' | 'application' | 'container' | 'api';
  target: string;
  profile?: 'quick' | 'standard' | 'thorough';
  tools?: string[];
  options?: ScanOptions;
}

export interface ScanOptions {
  incremental?: boolean;
  parallel?: boolean;
  maxTokens?: number;
  maxDuration?: number;
  depth?: number;
}

export interface ScanResult {
  scanId: string;
  status: 'success' | 'failed' | 'partial';
  summary: {
    vulnerabilities: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
  findings: Finding[];
  tokenUsage: number;
  scanTimeMs: number;
  errors?: string[];
}

export interface Finding {
  id: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  title: string;
  description: string;
  location?: {
    file?: string;
    line?: number;
    column?: number;
    endpoint?: string;
  };
  remediation?: string;
  cve?: string;
  cvssScore?: number;
  proofOfConcept?: string;
}

export interface ComplianceFramework {
  name: 'OWASP' | 'CIS' | 'NIST' | 'ISO27001' | 'PCI-DSS';
  version: string;
  controls: Control[];
}

export interface Control {
  id: string;
  title: string;
  description: string;
  severity: string;
  passed: boolean;
  evidence?: string;
}

export interface TokenBudget {
  maxPerScan: number;
  maxPerMinute: number;
  maxPerHour: number;
  currentUsage: {
    scan: number;
    minute: number;
    hour: number;
  };
}

export interface AuditEntry {
  timestamp: string;
  operation: {
    type: string;
    target: string;
    scanner?: string;
    duration?: number;
  };
  boundaries: {
    validated: boolean;
    networks?: string[];
    violations?: string[];
  };
  results?: {
    findings: number;
    tokensUsed: number;
  };
  user?: string;
  sessionId?: string;
}