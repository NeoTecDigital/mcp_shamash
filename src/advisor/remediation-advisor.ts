import type { Finding } from '../types/index.js';

export interface RemediationAdvice {
  findingId: string;
  priority: 'immediate' | 'high' | 'medium' | 'low';
  effort: 'trivial' | 'small' | 'medium' | 'large';
  automaticFix?: string;
  manualSteps?: string[];
  codeExample?: {
    before: string;
    after: string;
  };
  references?: string[];
  estimatedTime?: string;
  tools?: string[];
  preventionTips?: string[];
}

export interface RemediationPlan {
  findings: Finding[];
  remediations: RemediationAdvice[];
  summary: {
    totalFindings: number;
    autoFixable: number;
    immediateActions: number;
    estimatedEffort: string;
  };
  prioritizedActions: {
    immediate: RemediationAdvice[];
    high: RemediationAdvice[];
    medium: RemediationAdvice[];
    low: RemediationAdvice[];
  };
}

export class RemediationAdvisor {
  private remediationDatabase: Map<string, any>;

  constructor() {
    this.remediationDatabase = this.initializeRemediationDatabase();
  }

  private initializeRemediationDatabase(): Map<string, any> {
    const db = new Map<string, any>();

    // SQL Injection remediations
    db.set('sql_injection', {
      automaticFix: 'Use parameterized queries or prepared statements',
      manualSteps: [
        'Replace string concatenation with parameterized queries',
        'Use ORM query builders instead of raw SQL',
        'Validate and sanitize all user inputs',
        'Apply principle of least privilege to database users',
      ],
      codeExample: {
        before: `query = "SELECT * FROM users WHERE id = " + userId;`,
        after: `query = "SELECT * FROM users WHERE id = ?";
preparedStatement.setString(1, userId);`,
      },
      references: [
        'https://owasp.org/www-community/attacks/SQL_Injection',
        'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
      ],
      effort: 'small',
      estimatedTime: '30 minutes per query',
      tools: ['SQLMap', 'parameterized query libraries'],
    });

    // XSS remediations
    db.set('xss', {
      automaticFix: 'Encode output and validate input',
      manualSteps: [
        'HTML encode all user-supplied data before rendering',
        'Use Content Security Policy (CSP) headers',
        'Validate input on server side',
        'Use template engines with automatic escaping',
      ],
      codeExample: {
        before: `<div>\${userInput}</div>`,
        after: `<div>\${escapeHtml(userInput)}</div>`,
      },
      references: [
        'https://owasp.org/www-community/attacks/xss/',
        'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
      ],
      effort: 'medium',
      estimatedTime: '1-2 hours per component',
    });

    // Vulnerable dependency remediations
    db.set('vulnerable_dependency', {
      automaticFix: 'Update to patched version',
      manualSteps: [
        'Check for breaking changes in changelog',
        'Update package version in manifest file',
        'Run tests to ensure compatibility',
        'Consider using automated dependency updates',
      ],
      tools: ['npm audit fix', 'pip-audit', 'cargo audit', 'Dependabot'],
      effort: 'trivial',
      estimatedTime: '5-15 minutes per dependency',
    });

    // Hardcoded secrets remediations
    db.set('hardcoded_secret', {
      automaticFix: 'Move to environment variables or secret management',
      manualSteps: [
        'Remove secret from code immediately',
        'Rotate the exposed credential',
        'Use environment variables or secret management service',
        'Add secret scanning to CI/CD pipeline',
      ],
      codeExample: {
        before: `const apiKey = "sk-1234567890abcdef";`,
        after: `const apiKey = process.env.API_KEY;`,
      },
      tools: ['HashiCorp Vault', 'AWS Secrets Manager', 'Azure Key Vault', 'dotenv'],
      effort: 'small',
      estimatedTime: '30 minutes per secret',
      priority: 'immediate',
    });

    // Weak cryptography remediations
    db.set('weak_crypto', {
      automaticFix: 'Use strong cryptographic algorithms',
      manualSteps: [
        'Replace MD5/SHA1 with SHA-256 or SHA-3',
        'Use AES-256 for symmetric encryption',
        'Implement proper key management',
        'Use cryptographic libraries instead of custom implementations',
      ],
      codeExample: {
        before: `crypto.createHash('md5').update(password).digest('hex');`,
        after: `await bcrypt.hash(password, 10);`,
      },
      references: [
        'https://owasp.org/www-project-cryptographic-storage-cheat-sheet/',
      ],
      effort: 'medium',
      estimatedTime: '2-4 hours',
    });

    // Missing authentication remediations
    db.set('missing_auth', {
      automaticFix: 'Implement authentication middleware',
      manualSteps: [
        'Add authentication middleware to routes',
        'Implement proper session management',
        'Use OAuth2/JWT for API authentication',
        'Add rate limiting to prevent brute force',
      ],
      codeExample: {
        before: `app.get('/api/admin', (req, res) => { /* ... */ });`,
        after: `app.get('/api/admin', requireAuth, requireRole('admin'), (req, res) => { /* ... */ });`,
      },
      effort: 'large',
      estimatedTime: '4-8 hours',
    });

    // Insecure configuration remediations
    db.set('insecure_config', {
      automaticFix: 'Apply security hardening configurations',
      manualSteps: [
        'Disable debug mode in production',
        'Configure secure headers (HSTS, CSP, X-Frame-Options)',
        'Enable HTTPS/TLS with strong ciphers',
        'Disable unnecessary services and ports',
      ],
      tools: ['Security Headers scanner', 'TLS configuration generators'],
      effort: 'small',
      estimatedTime: '1-2 hours',
    });

    return db;
  }

  async generateRemediationPlan(findings: Finding[]): Promise<RemediationPlan> {
    const remediations: RemediationAdvice[] = [];
    
    for (const finding of findings) {
      const advice = await this.generateRemediationAdvice(finding);
      remediations.push(advice);
    }

    // Categorize by priority
    const prioritizedActions = {
      immediate: remediations.filter(r => r.priority === 'immediate'),
      high: remediations.filter(r => r.priority === 'high'),
      medium: remediations.filter(r => r.priority === 'medium'),
      low: remediations.filter(r => r.priority === 'low'),
    };

    // Calculate summary
    const autoFixable = remediations.filter(r => r.effort === 'trivial').length;
    const immediateActions = prioritizedActions.immediate.length;
    const totalEffort = this.calculateTotalEffort(remediations);

    return {
      findings,
      remediations,
      summary: {
        totalFindings: findings.length,
        autoFixable,
        immediateActions,
        estimatedEffort: totalEffort,
      },
      prioritizedActions,
    };
  }

  private async generateRemediationAdvice(finding: Finding): Promise<RemediationAdvice> {
    // Determine remediation type based on finding
    const remediationType = this.determineRemediationType(finding);
    const baseRemediation = this.remediationDatabase.get(remediationType);

    // Determine priority based on severity
    const priority = this.determinePriority(finding);

    // Build customized advice
    const advice: RemediationAdvice = {
      findingId: finding.id,
      priority,
      effort: baseRemediation?.effort || this.estimateEffort(finding),
      automaticFix: baseRemediation?.automaticFix,
      manualSteps: baseRemediation?.manualSteps,
      codeExample: baseRemediation?.codeExample,
      references: baseRemediation?.references || this.getDefaultReferences(finding.type),
      estimatedTime: baseRemediation?.estimatedTime || this.estimateTime(finding),
      tools: baseRemediation?.tools,
      preventionTips: this.generatePreventionTips(finding),
    };

    // Customize advice based on specific finding details
    if (finding.type === 'dependency' && finding.cve) {
      advice.automaticFix = `Update to version that patches ${finding.cve}`;
      advice.references = [
        `https://nvd.nist.gov/vuln/detail/${finding.cve}`,
        ...advice.references || [],
      ];
    }

    if (finding.type === 'secret') {
      advice.priority = 'immediate'; // Secrets are always immediate priority
      advice.manualSteps = [
        `Immediately rotate the exposed ${this.identifySecretType(finding.title)}`,
        ...advice.manualSteps || [],
      ];
    }

    return advice;
  }

  private determineRemediationType(finding: Finding): string {
    const title = finding.title.toLowerCase();
    const description = finding.description.toLowerCase();
    const combined = `${title} ${description}`;

    if (combined.includes('sql') && combined.includes('injection')) {
      return 'sql_injection';
    }
    if (combined.includes('xss') || combined.includes('cross-site scripting')) {
      return 'xss';
    }
    if (finding.type === 'dependency' || combined.includes('vulnerable') || combined.includes('cve')) {
      return 'vulnerable_dependency';
    }
    if (finding.type === 'secret' || combined.includes('hardcoded') || combined.includes('api key')) {
      return 'hardcoded_secret';
    }
    if (combined.includes('weak') && (combined.includes('crypto') || combined.includes('hash'))) {
      return 'weak_crypto';
    }
    if (combined.includes('authentication') || combined.includes('authorization')) {
      return 'missing_auth';
    }
    if (finding.type === 'infrastructure' || combined.includes('configuration')) {
      return 'insecure_config';
    }

    return 'generic';
  }

  private determinePriority(finding: Finding): 'immediate' | 'high' | 'medium' | 'low' {
    switch (finding.severity) {
      case 'critical':
        return 'immediate';
      case 'high':
        return 'high';
      case 'medium':
        return 'medium';
      case 'low':
      case 'informational':
        return 'low';
      default:
        return 'medium';
    }
  }

  private estimateEffort(finding: Finding): 'trivial' | 'small' | 'medium' | 'large' {
    if (finding.type === 'dependency') return 'trivial';
    if (finding.type === 'secret') return 'small';
    if (finding.type === 'infrastructure') return 'small';
    if (finding.severity === 'critical') return 'large';
    if (finding.severity === 'high') return 'medium';
    return 'small';
  }

  private estimateTime(finding: Finding): string {
    const effort = this.estimateEffort(finding);
    switch (effort) {
      case 'trivial':
        return '5-15 minutes';
      case 'small':
        return '30-60 minutes';
      case 'medium':
        return '2-4 hours';
      case 'large':
        return '4-8 hours';
      default:
        return '1-2 hours';
    }
  }

  private calculateTotalEffort(remediations: RemediationAdvice[]): string {
    const effortMap = {
      trivial: 0.25,
      small: 1,
      medium: 3,
      large: 6,
    };

    const totalHours = remediations.reduce((sum, r) => {
      return sum + (effortMap[r.effort] || 1);
    }, 0);

    if (totalHours < 8) {
      return `${Math.ceil(totalHours)} hours`;
    } else {
      return `${Math.ceil(totalHours / 8)} days`;
    }
  }

  private identifySecretType(title: string): string {
    const lower = title.toLowerCase();
    if (lower.includes('api')) return 'API key';
    if (lower.includes('token')) return 'token';
    if (lower.includes('password')) return 'password';
    if (lower.includes('credential')) return 'credential';
    if (lower.includes('secret')) return 'secret';
    return 'credential';
  }

  private getDefaultReferences(findingType: string): string[] {
    const references: Record<string, string[]> = {
      sast: ['https://owasp.org/www-project-top-ten/'],
      dependency: ['https://owasp.org/www-project-dependency-check/'],
      secret: ['https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password'],
      infrastructure: ['https://www.cisecurity.org/cis-benchmarks/'],
      dast: ['https://owasp.org/www-project-web-security-testing-guide/'],
    };

    return references[findingType] || ['https://owasp.org/'];
  }

  private generatePreventionTips(finding: Finding): string[] {
    const tips: string[] = [];

    switch (finding.type) {
      case 'sast':
        tips.push('Implement secure coding practices');
        tips.push('Use static analysis in CI/CD pipeline');
        tips.push('Conduct regular code reviews');
        break;
      case 'dependency':
        tips.push('Enable automated dependency updates');
        tips.push('Monitor security advisories');
        tips.push('Use dependency scanning in CI/CD');
        break;
      case 'secret':
        tips.push('Use secret management systems');
        tips.push('Implement pre-commit hooks for secret scanning');
        tips.push('Regular credential rotation policy');
        break;
      case 'infrastructure':
        tips.push('Use Infrastructure as Code (IaC) scanning');
        tips.push('Implement configuration baselines');
        tips.push('Regular security audits');
        break;
    }

    return tips;
  }

  generateMarkdownReport(plan: RemediationPlan): string {
    const md: string[] = [];

    md.push('# Security Remediation Plan\n');
    md.push(`Generated: ${new Date().toISOString()}\n`);
    
    md.push('## Summary\n');
    md.push(`- **Total Findings**: ${plan.summary.totalFindings}`);
    md.push(`- **Auto-fixable**: ${plan.summary.autoFixable}`);
    md.push(`- **Immediate Actions Required**: ${plan.summary.immediateActions}`);
    md.push(`- **Estimated Total Effort**: ${plan.summary.estimatedEffort}\n`);

    // Immediate actions
    if (plan.prioritizedActions.immediate.length > 0) {
      md.push('## 🚨 Immediate Actions Required\n');
      for (const action of plan.prioritizedActions.immediate) {
        md.push(`### Finding: ${action.findingId}`);
        if (action.automaticFix) {
          md.push(`**Quick Fix**: ${action.automaticFix}`);
        }
        if (action.manualSteps) {
          md.push('**Steps**:');
          action.manualSteps.forEach(step => md.push(`1. ${step}`));
        }
        md.push(`**Estimated Time**: ${action.estimatedTime}\n`);
      }
    }

    // High priority
    if (plan.prioritizedActions.high.length > 0) {
      md.push('## ⚠️ High Priority\n');
      for (const action of plan.prioritizedActions.high) {
        md.push(`- **${action.findingId}**: ${action.automaticFix || 'Manual fix required'} (${action.estimatedTime})`);
      }
      md.push('');
    }

    // Code examples
    const withExamples = plan.remediations.filter(r => r.codeExample);
    if (withExamples.length > 0) {
      md.push('## Code Examples\n');
      for (const action of withExamples.slice(0, 3)) {
        md.push(`### ${action.findingId}\n`);
        md.push('**Before**:');
        md.push('```javascript');
        md.push(action.codeExample!.before);
        md.push('```\n');
        md.push('**After**:');
        md.push('```javascript');
        md.push(action.codeExample!.after);
        md.push('```\n');
      }
    }

    // Useful tools
    const allTools = new Set<string>();
    plan.remediations.forEach(r => r.tools?.forEach(t => allTools.add(t)));
    if (allTools.size > 0) {
      md.push('## Recommended Tools\n');
      Array.from(allTools).forEach(tool => md.push(`- ${tool}`));
    }

    return md.join('\n');
  }
}