import type { Finding, ScanRequest } from '../types/index.js';
import { ComplianceMapper, type FrameworkResult } from './mapper.js';
import type { ProjectScanner } from '../scanners/project-scanner.js';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface ComplianceReport {
  timestamp: string;
  projectPath: string;
  profile: 'minimal' | 'standard' | 'comprehensive';
  frameworks: FrameworkResult[];
  summary: {
    overallCompliance: number;
    totalFindings: number;
    criticalFindings: number;
    highFindings: number;
    recommendations: string[];
  };
  scanResults?: {
    findings: Finding[];
    scanTimeMs: number;
    tokenUsage: number;
  };
}

export class ComplianceValidator {
  private mapper: ComplianceMapper;
  private projectScanner: ProjectScanner | null = null;
  private reportsDir: string;

  constructor() {
    this.mapper = new ComplianceMapper();
    this.reportsDir = path.join(process.cwd(), 'compliance_reports');
  }

  setProjectScanner(scanner: ProjectScanner): void {
    this.projectScanner = scanner;
  }

  async validate(
    projectPath: string, 
    frameworks: string[],
    profile: 'minimal' | 'standard' | 'comprehensive' = 'standard'
  ): Promise<ComplianceReport> {
    // Run security scans first if scanner is available
    let findings: Finding[] = [];
    let scanTimeMs = 0;
    let tokenUsage = 0;

    if (this.projectScanner) {
      console.error('Running security scans for compliance validation...');
      
      const scanRequest: ScanRequest = {
        type: 'project',
        target: projectPath,
        profile: profile === 'minimal' ? 'quick' : profile === 'comprehensive' ? 'thorough' : 'standard',
        options: {
          parallel: true,
        },
      };

      const scanResult = await this.projectScanner.scan(scanRequest);
      findings = scanResult.findings;
      scanTimeMs = scanResult.scanTimeMs;
      tokenUsage = scanResult.tokenUsage;
      
      console.error(`Found ${findings.length} findings to map to compliance frameworks`);
    } else {
      console.warn('No project scanner available, using empty findings list');
    }

    // Map findings to each framework
    const frameworkResults: FrameworkResult[] = [];
    
    for (const framework of frameworks) {
      const frameworkType = framework.toUpperCase() as 'OWASP' | 'CIS' | 'NIST' | 'ISO27001';
      
      if (['OWASP', 'CIS', 'NIST', 'ISO27001'].includes(frameworkType)) {
        const result = this.mapper.mapFindingsToFramework(findings, frameworkType);
        frameworkResults.push(result);
      } else {
        console.warn(`Unknown compliance framework: ${framework}`);
      }
    }

    // Calculate summary
    const criticalFindings = findings.filter(f => f.severity === 'critical').length;
    const highFindings = findings.filter(f => f.severity === 'high').length;
    
    const overallCompliance = frameworkResults.length > 0
      ? Math.round(frameworkResults.reduce((sum, r) => sum + r.coverage, 0) / frameworkResults.length)
      : 0;

    const recommendations = this.generateRecommendations(frameworkResults, findings);

    const report: ComplianceReport = {
      timestamp: new Date().toISOString(),
      projectPath,
      profile,
      frameworks: frameworkResults,
      summary: {
        overallCompliance,
        totalFindings: findings.length,
        criticalFindings,
        highFindings,
        recommendations,
      },
      scanResults: {
        findings,
        scanTimeMs,
        tokenUsage,
      },
    };

    // Save report to file
    await this.saveReport(report);

    return report;
  }

  private generateRecommendations(frameworks: FrameworkResult[], findings: Finding[]): string[] {
    const recommendations: string[] = [];
    
    // Priority recommendations based on severity
    const criticalCount = findings.filter(f => f.severity === 'critical').length;
    const highCount = findings.filter(f => f.severity === 'high').length;
    
    if (criticalCount > 0) {
      recommendations.push(`URGENT: Address ${criticalCount} critical security findings immediately`);
    }
    if (highCount > 0) {
      recommendations.push(`HIGH PRIORITY: Fix ${highCount} high severity vulnerabilities`);
    }

    // Framework-specific recommendations
    for (const framework of frameworks) {
      if (framework.coverage < 50) {
        recommendations.push(`${framework.framework}: Critical compliance gaps (${framework.coverage}% coverage)`);
      } else if (framework.coverage < 80) {
        recommendations.push(`${framework.framework}: Improve compliance (currently ${framework.coverage}%)`);
      }

      // Find the most failed controls
      const failedControls = framework.controls.filter(c => c.status === 'failed');
      if (failedControls.length > 0) {
        const topFailed = failedControls.slice(0, 3).map(c => c.title).join(', ');
        recommendations.push(`Focus on: ${topFailed}`);
      }
    }

    // Finding type recommendations
    const findingTypes = [...new Set(findings.map(f => f.type))];
    if (findingTypes.includes('secret')) {
      recommendations.push('Implement secret scanning in CI/CD pipeline');
    }
    if (findingTypes.includes('dependency')) {
      recommendations.push('Enable automated dependency updates');
    }
    if (findingTypes.includes('infrastructure')) {
      recommendations.push('Review and harden infrastructure configurations');
    }

    return recommendations.slice(0, 10); // Limit to top 10 recommendations
  }

  private async saveReport(report: ComplianceReport): Promise<string> {
    try {
      // Ensure reports directory exists
      await fs.mkdir(this.reportsDir, { recursive: true });
      
      // Generate filename
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `compliance_report_${timestamp}.json`;
      const filepath = path.join(this.reportsDir, filename);
      
      // Save report
      await fs.writeFile(filepath, JSON.stringify(report, null, 2), 'utf-8');
      
      console.error(`Compliance report saved to: ${filepath}`);
      return filepath;
    } catch (error) {
      console.error('Failed to save compliance report:', error);
      throw error;
    }
  }

  public async generateHTMLReport(report: ComplianceReport): Promise<string> {
    const html = `
<!DOCTYPE html>
<html>
<head>
  <title>Compliance Report - ${new Date(report.timestamp).toLocaleDateString()}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
    .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
    .summary { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .framework { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .metric { display: inline-block; margin: 10px 20px; }
    .metric-value { font-size: 2em; font-weight: bold; }
    .metric-label { color: #666; font-size: 0.9em; }
    .progress-bar { width: 100%; height: 30px; background: #e0e0e0; border-radius: 15px; overflow: hidden; }
    .progress-fill { height: 100%; background: linear-gradient(90deg, #4caf50, #8bc34a); transition: width 0.3s; }
    .control { padding: 10px; margin: 5px 0; border-left: 4px solid #ccc; background: #fafafa; }
    .control.passed { border-color: #4caf50; }
    .control.failed { border-color: #f44336; }
    .control.partial { border-color: #ff9800; }
    .recommendations { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 5px; }
    .critical { color: #d32f2f; font-weight: bold; }
    .high { color: #f57c00; font-weight: bold; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Security Compliance Report</h1>
    <p>Generated: ${new Date(report.timestamp).toLocaleString()}</p>
    <p>Project: ${report.projectPath}</p>
    <p>Profile: ${report.profile.toUpperCase()}</p>
  </div>

  <div class="summary">
    <h2>Executive Summary</h2>
    <div class="metric">
      <div class="metric-value">${report.summary.overallCompliance}%</div>
      <div class="metric-label">Overall Compliance</div>
    </div>
    <div class="metric">
      <div class="metric-value">${report.summary.totalFindings}</div>
      <div class="metric-label">Total Findings</div>
    </div>
    <div class="metric">
      <div class="metric-value critical">${report.summary.criticalFindings}</div>
      <div class="metric-label">Critical Issues</div>
    </div>
    <div class="metric">
      <div class="metric-value high">${report.summary.highFindings}</div>
      <div class="metric-label">High Severity</div>
    </div>
  </div>

  ${report.summary.recommendations.length > 0 ? `
  <div class="recommendations">
    <h3>Key Recommendations</h3>
    <ul>
      ${report.summary.recommendations.map(rec => `<li>${rec}</li>`).join('')}
    </ul>
  </div>
  ` : ''}

  ${report.frameworks.map(framework => `
  <div class="framework">
    <h2>${framework.framework} ${framework.version}</h2>
    <div class="progress-bar">
      <div class="progress-fill" style="width: ${framework.coverage}%"></div>
    </div>
    <p>Coverage: ${framework.coverage}% | Passed: ${framework.passed}/${framework.totalControls} | Failed: ${framework.failed}</p>
    
    <h3>Control Status</h3>
    ${framework.controls.slice(0, 10).map(control => `
    <div class="control ${control.status}">
      <strong>${control.id}: ${control.title}</strong> - ${control.status.toUpperCase()}
      ${control.findings.length > 0 ? `<br><small>${control.findings.length} findings</small>` : ''}
      ${control.recommendation ? `<br><em>${control.recommendation}</em>` : ''}
    </div>
    `).join('')}
  </div>
  `).join('')}

  <div class="summary">
    <h3>Scan Metrics</h3>
    <p>Scan Time: ${report.scanResults?.scanTimeMs ? (report.scanResults.scanTimeMs / 1000).toFixed(2) : 0}s</p>
    <p>Token Usage: ${report.scanResults?.tokenUsage || 0}</p>
  </div>
</body>
</html>
    `;

    // Save HTML report
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `compliance_report_${timestamp}.html`;
    const filepath = path.join(this.reportsDir, filename);
    
    await fs.writeFile(filepath, html, 'utf-8');
    console.error(`HTML report saved to: ${filepath}`);
    
    return filepath;
  }

  public getComplianceProfiles() {
    return {
      minimal: {
        name: 'Minimal',
        description: 'Basic security compliance check',
        frameworks: ['OWASP'],
        scanProfile: 'quick',
      },
      standard: {
        name: 'Standard',
        description: 'Comprehensive compliance validation',
        frameworks: ['OWASP', 'CIS'],
        scanProfile: 'standard',
      },
      comprehensive: {
        name: 'Comprehensive',
        description: 'Full compliance audit',
        frameworks: ['OWASP', 'CIS', 'NIST', 'ISO27001'],
        scanProfile: 'thorough',
      },
    };
  }
}