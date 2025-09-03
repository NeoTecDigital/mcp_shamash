import type { Finding } from '../types/index.js';

export interface ComplianceMapping {
  framework: string;
  control: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface ComplianceControl {
  id: string;
  title: string;
  description: string;
  category?: string;
  findingTypes: string[];
  severities: string[];
  keywords: string[];
}

export interface FrameworkResult {
  framework: string;
  version: string;
  totalControls: number;
  passed: number;
  failed: number;
  partial: number;
  notApplicable: number;
  coverage: number;
  controls: ControlResult[];
}

export interface ControlResult {
  id: string;
  title: string;
  status: 'passed' | 'failed' | 'partial' | 'not_applicable';
  findings: Finding[];
  evidence: string[];
  recommendation?: string;
}

export class ComplianceMapper {
  private owaspControls: Map<string, ComplianceControl>;
  private cisControls: Map<string, ComplianceControl>;
  private nistControls: Map<string, ComplianceControl>;
  private isoControls: Map<string, ComplianceControl>;

  constructor() {
    this.owaspControls = this.initializeOWASPControls();
    this.cisControls = this.initializeCISControls();
    this.nistControls = this.initializeNISTControls();
    this.isoControls = this.initializeISOControls();
  }

  private initializeOWASPControls(): Map<string, ComplianceControl> {
    const controls = new Map<string, ComplianceControl>();

    controls.set('A01', {
      id: 'A01',
      title: 'Broken Access Control',
      description: 'Access control enforces policy such that users cannot act outside of their intended permissions',
      findingTypes: ['sast', 'dast'],
      severities: ['critical', 'high'],
      keywords: ['access', 'authorization', 'permission', 'role', 'privilege', 'bypass'],
    });

    controls.set('A02', {
      id: 'A02',
      title: 'Cryptographic Failures',
      description: 'Protection of data in transit and at rest using appropriate cryptographic methods',
      findingTypes: ['sast', 'dependency'],
      severities: ['critical', 'high'],
      keywords: ['crypto', 'encryption', 'hash', 'tls', 'ssl', 'certificate', 'weak'],
    });

    controls.set('A03', {
      id: 'A03',
      title: 'Injection',
      description: 'User-supplied data is not validated, filtered, or sanitized by the application',
      findingTypes: ['sast', 'dast'],
      severities: ['critical', 'high'],
      keywords: ['injection', 'sql', 'xss', 'command', 'ldap', 'xpath', 'nosql', 'sanitize'],
    });

    controls.set('A04', {
      id: 'A04',
      title: 'Insecure Design',
      description: 'Missing or ineffective control design and architecture',
      findingTypes: ['sast', 'infrastructure'],
      severities: ['high', 'medium'],
      keywords: ['design', 'architecture', 'threat', 'model', 'pattern', 'secure'],
    });

    controls.set('A05', {
      id: 'A05',
      title: 'Security Misconfiguration',
      description: 'Missing appropriate security hardening or improperly configured permissions',
      findingTypes: ['infrastructure', 'sast'],
      severities: ['high', 'medium'],
      keywords: ['config', 'misconfiguration', 'default', 'hardening', 'permission'],
    });

    controls.set('A06', {
      id: 'A06',
      title: 'Vulnerable and Outdated Components',
      description: 'Using components with known vulnerabilities',
      findingTypes: ['dependency'],
      severities: ['critical', 'high', 'medium'],
      keywords: ['cve', 'vulnerability', 'outdated', 'dependency', 'component', 'library'],
    });

    controls.set('A07', {
      id: 'A07',
      title: 'Identification and Authentication Failures',
      description: 'Failure to properly identify and authenticate users',
      findingTypes: ['sast', 'dast'],
      severities: ['critical', 'high'],
      keywords: ['auth', 'authentication', 'session', 'password', 'credential', 'identity'],
    });

    controls.set('A08', {
      id: 'A08',
      title: 'Software and Data Integrity Failures',
      description: 'Code and infrastructure that does not protect against integrity violations',
      findingTypes: ['sast', 'dependency', 'infrastructure'],
      severities: ['high', 'medium'],
      keywords: ['integrity', 'signature', 'verification', 'supply chain', 'update'],
    });

    controls.set('A09', {
      id: 'A09',
      title: 'Security Logging and Monitoring Failures',
      description: 'Insufficient logging, detection, monitoring and response',
      findingTypes: ['sast', 'infrastructure'],
      severities: ['medium', 'low'],
      keywords: ['logging', 'monitoring', 'audit', 'detection', 'alert', 'event'],
    });

    controls.set('A10', {
      id: 'A10',
      title: 'Server-Side Request Forgery (SSRF)',
      description: 'Fetching remote resources without validating user-supplied URLs',
      findingTypes: ['sast', 'dast'],
      severities: ['high', 'medium'],
      keywords: ['ssrf', 'request', 'url', 'forgery', 'remote', 'fetch'],
    });

    return controls;
  }

  private initializeCISControls(): Map<string, ComplianceControl> {
    const controls = new Map<string, ComplianceControl>();

    controls.set('CIS-1', {
      id: 'CIS-1',
      title: 'Inventory and Control of Enterprise Assets',
      description: 'Actively manage all enterprise assets',
      category: 'Basic',
      findingTypes: ['sast', 'infrastructure'],
      severities: ['medium', 'low'],
      keywords: ['inventory', 'asset', 'discovery', 'catalog'],
    });

    controls.set('CIS-2', {
      id: 'CIS-2',
      title: 'Inventory and Control of Software Assets',
      description: 'Actively manage all software on the network',
      category: 'Basic',
      findingTypes: ['dependency', 'sast'],
      severities: ['high', 'medium'],
      keywords: ['software', 'dependency', 'package', 'library', 'version'],
    });

    controls.set('CIS-3', {
      id: 'CIS-3',
      title: 'Data Protection',
      description: 'Identify and protect enterprise data',
      category: 'Basic',
      findingTypes: ['secret', 'sast'],
      severities: ['critical', 'high'],
      keywords: ['data', 'sensitive', 'pii', 'secret', 'confidential', 'encryption'],
    });

    controls.set('CIS-4', {
      id: 'CIS-4',
      title: 'Secure Configuration of Enterprise Assets',
      description: 'Establish and maintain secure configurations',
      category: 'Basic',
      findingTypes: ['infrastructure', 'sast'],
      severities: ['high', 'medium'],
      keywords: ['configuration', 'hardening', 'baseline', 'secure'],
    });

    controls.set('CIS-16', {
      id: 'CIS-16',
      title: 'Application Software Security',
      description: 'Manage the security lifecycle of in-house developed software',
      category: 'Organizational',
      findingTypes: ['sast', 'dast', 'dependency'],
      severities: ['critical', 'high', 'medium'],
      keywords: ['application', 'secure', 'development', 'sdlc', 'vulnerability'],
    });

    return controls;
  }

  private initializeNISTControls(): Map<string, ComplianceControl> {
    const controls = new Map<string, ComplianceControl>();

    // NIST CSF Core Functions
    controls.set('ID.AM', {
      id: 'ID.AM',
      title: 'Asset Management',
      description: 'Identify - Asset Management',
      category: 'Identify',
      findingTypes: ['sast', 'dependency', 'infrastructure'],
      severities: ['medium', 'low'],
      keywords: ['asset', 'inventory', 'resource', 'component'],
    });

    controls.set('ID.RA', {
      id: 'ID.RA',
      title: 'Risk Assessment',
      description: 'Identify - Risk Assessment',
      category: 'Identify',
      findingTypes: ['sast', 'dast', 'dependency', 'secret'],
      severities: ['critical', 'high', 'medium'],
      keywords: ['risk', 'vulnerability', 'threat', 'assessment'],
    });

    controls.set('PR.AC', {
      id: 'PR.AC',
      title: 'Identity Management and Access Control',
      description: 'Protect - Access Control',
      category: 'Protect',
      findingTypes: ['sast', 'dast'],
      severities: ['critical', 'high'],
      keywords: ['access', 'identity', 'authentication', 'authorization'],
    });

    controls.set('PR.DS', {
      id: 'PR.DS',
      title: 'Data Security',
      description: 'Protect - Data Security',
      category: 'Protect',
      findingTypes: ['secret', 'sast'],
      severities: ['critical', 'high'],
      keywords: ['data', 'encryption', 'protection', 'confidentiality'],
    });

    controls.set('DE.CM', {
      id: 'DE.CM',
      title: 'Security Continuous Monitoring',
      description: 'Detect - Continuous Monitoring',
      category: 'Detect',
      findingTypes: ['sast', 'infrastructure'],
      severities: ['medium', 'low'],
      keywords: ['monitoring', 'logging', 'detection', 'audit'],
    });

    return controls;
  }

  private initializeISOControls(): Map<string, ComplianceControl> {
    const controls = new Map<string, ComplianceControl>();

    controls.set('A.8', {
      id: 'A.8',
      title: 'Asset Management',
      description: 'Identification and management of organizational assets',
      findingTypes: ['sast', 'dependency', 'infrastructure'],
      severities: ['medium', 'low'],
      keywords: ['asset', 'inventory', 'ownership', 'classification'],
    });

    controls.set('A.9', {
      id: 'A.9',
      title: 'Access Control',
      description: 'Limit access to information and information processing facilities',
      findingTypes: ['sast', 'dast'],
      severities: ['critical', 'high'],
      keywords: ['access', 'control', 'authorization', 'authentication', 'privilege'],
    });

    controls.set('A.10', {
      id: 'A.10',
      title: 'Cryptography',
      description: 'Proper and effective use of cryptography',
      findingTypes: ['sast', 'dependency'],
      severities: ['critical', 'high'],
      keywords: ['crypto', 'encryption', 'key', 'certificate', 'hash'],
    });

    controls.set('A.12', {
      id: 'A.12',
      title: 'Operations Security',
      description: 'Ensure correct and secure operations',
      findingTypes: ['infrastructure', 'sast'],
      severities: ['high', 'medium'],
      keywords: ['operations', 'logging', 'monitoring', 'vulnerability', 'configuration'],
    });

    controls.set('A.14', {
      id: 'A.14',
      title: 'System Acquisition, Development and Maintenance',
      description: 'Security in development and support processes',
      findingTypes: ['sast', 'dast', 'dependency'],
      severities: ['critical', 'high', 'medium'],
      keywords: ['development', 'secure', 'testing', 'code', 'review'],
    });

    controls.set('A.16', {
      id: 'A.16',
      title: 'Information Security Incident Management',
      description: 'Consistent and effective approach to incident management',
      findingTypes: ['sast', 'infrastructure'],
      severities: ['high', 'medium'],
      keywords: ['incident', 'response', 'detection', 'reporting', 'management'],
    });

    return controls;
  }

  public mapFindingsToFramework(
    findings: Finding[],
    framework: 'OWASP' | 'CIS' | 'NIST' | 'ISO27001'
  ): FrameworkResult {
    let controls: Map<string, ComplianceControl>;
    let frameworkName: string;
    let version: string;

    switch (framework) {
      case 'OWASP':
        controls = this.owaspControls;
        frameworkName = 'OWASP Top 10';
        version = '2021';
        break;
      case 'CIS':
        controls = this.cisControls;
        frameworkName = 'CIS Controls';
        version = 'v8';
        break;
      case 'NIST':
        controls = this.nistControls;
        frameworkName = 'NIST Cybersecurity Framework';
        version = '1.1';
        break;
      case 'ISO27001':
        controls = this.isoControls;
        frameworkName = 'ISO 27001';
        version = '2022';
        break;
    }

    const controlResults: ControlResult[] = [];
    let passed = 0;
    let failed = 0;
    let partial = 0;
    let notApplicable = 0;

    for (const [controlId, control] of controls) {
      const relevantFindings = this.findRelevantFindings(findings, control);
      
      let status: 'passed' | 'failed' | 'partial' | 'not_applicable';
      
      if (relevantFindings.length === 0) {
        // No findings related to this control
        status = 'passed';
        passed++;
      } else {
        const criticalFindings = relevantFindings.filter(f => f.severity === 'critical');
        const highFindings = relevantFindings.filter(f => f.severity === 'high');
        
        if (criticalFindings.length > 0) {
          status = 'failed';
          failed++;
        } else if (highFindings.length > 0) {
          status = 'partial';
          partial++;
        } else {
          status = 'partial';
          partial++;
        }
      }

      controlResults.push({
        id: controlId,
        title: control.title,
        status,
        findings: relevantFindings,
        evidence: this.generateEvidence(relevantFindings),
        recommendation: this.generateRecommendation(control, relevantFindings),
      });
    }

    const totalControls = controls.size;
    const coverage = Math.round(((passed + partial) / totalControls) * 100);

    return {
      framework: frameworkName,
      version,
      totalControls,
      passed,
      failed,
      partial,
      notApplicable,
      coverage,
      controls: controlResults,
    };
  }

  private findRelevantFindings(findings: Finding[], control: ComplianceControl): Finding[] {
    return findings.filter(finding => {
      // Check if finding type matches
      if (control.findingTypes.includes(finding.type)) {
        return true;
      }

      // Check if severity matches
      if (control.severities.includes(finding.severity)) {
        // Check keywords in title and description
        const findingText = `${finding.title} ${finding.description}`.toLowerCase();
        return control.keywords.some(keyword => findingText.includes(keyword.toLowerCase()));
      }

      return false;
    });
  }

  private generateEvidence(findings: Finding[]): string[] {
    const evidence: string[] = [];
    
    for (const finding of findings.slice(0, 5)) { // Limit to first 5 findings
      if (finding.location?.file) {
        evidence.push(`${finding.type}: ${finding.title} in ${finding.location.file}`);
      } else {
        evidence.push(`${finding.type}: ${finding.title}`);
      }
    }

    if (findings.length > 5) {
      evidence.push(`... and ${findings.length - 5} more findings`);
    }

    return evidence;
  }

  private generateRecommendation(control: ComplianceControl, findings: Finding[]): string {
    if (findings.length === 0) {
      return `Control ${control.id} is currently compliant. Continue monitoring.`;
    }

    const criticalCount = findings.filter(f => f.severity === 'critical').length;
    const highCount = findings.filter(f => f.severity === 'high').length;

    let recommendation = `Address ${findings.length} findings for ${control.title}. `;
    
    if (criticalCount > 0) {
      recommendation += `Priority: Fix ${criticalCount} critical issues immediately. `;
    }
    if (highCount > 0) {
      recommendation += `Fix ${highCount} high severity issues. `;
    }

    // Add specific recommendations based on finding types
    const findingTypes = [...new Set(findings.map(f => f.type))];
    if (findingTypes.includes('dependency')) {
      recommendation += 'Update vulnerable dependencies. ';
    }
    if (findingTypes.includes('secret')) {
      recommendation += 'Remove exposed secrets and rotate credentials. ';
    }
    if (findingTypes.includes('infrastructure')) {
      recommendation += 'Review and harden infrastructure configurations. ';
    }

    return recommendation;
  }

  public generateComplianceProfile(profile: 'minimal' | 'standard' | 'comprehensive'): string[] {
    switch (profile) {
      case 'minimal':
        return ['OWASP'];
      case 'standard':
        return ['OWASP', 'CIS'];
      case 'comprehensive':
        return ['OWASP', 'CIS', 'NIST', 'ISO27001'];
      default:
        return ['OWASP'];
    }
  }
}