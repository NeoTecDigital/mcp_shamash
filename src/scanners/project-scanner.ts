// import * as path from 'path'; // Uncomment if path operations needed
// import * as fs from 'fs/promises'; // Uncomment if file operations needed
import type { ScanRequest, ScanResult, Finding } from '../types/index.js';
import type { BoundaryEnforcer } from '../boundaries/enforcer.js';
import { DockerOrchestrator, type ScannerConfig } from './docker-orchestrator.js';
import { ResultCache } from '../cache/result-cache.js';
import { ScannerExecutor } from '../utils/parallel-executor.js';
import { CustomRuleEngine } from '../rules/custom-rule-engine.js';

export class ProjectScanner {
  private orchestrator: DockerOrchestrator;
  private cache: ResultCache;
  private customRuleEngine: CustomRuleEngine;

  constructor(private boundaryEnforcer: BoundaryEnforcer) {
    const projectScope = this.boundaryEnforcer.getProjectScope();
    if (!projectScope) {
      throw new Error('Project scope not initialized');
    }
    this.orchestrator = new DockerOrchestrator(projectScope);
    this.cache = new ResultCache();
    this.customRuleEngine = new CustomRuleEngine(projectScope.projectRoot);
  }

  async initialize(): Promise<void> {
    await this.cache.initialize();
    await this.customRuleEngine.loadRules();
  }

  async scan(request: ScanRequest): Promise<ScanResult> {
    const scanId = this.generateScanId();
    const startTime = Date.now();

    // Validate boundaries
    const validation = await this.boundaryEnforcer.validatePath(request.target);
    if (!validation.allowed) {
      throw new Error(`Boundary violation: ${validation.reason}`);
    }

    // Determine which tools to run
    const tools = request.tools || this.getDefaultTools(request.profile);
    
    // Check cache first
    const cachedResult = await this.cache.get('project', request.target, tools, request.profile);
    if (cachedResult) {
      console.error(`Cache hit for project scan: ${scanId}`);
      // Update scan ID and timing for the cached result
      cachedResult.scanId = scanId;
      cachedResult.scanTimeMs = Date.now() - startTime;
      return cachedResult;
    }

    console.error(`Starting project scan: ${scanId} with tools: ${tools.join(', ')}`);

    const allFindings: Finding[] = [];
    const errors: string[] = [];
    let tokenUsage = 0;

    // Determine execution strategy
    const useParallel = request.options?.parallel !== false && tools.length > 1;
    
    if (useParallel) {
      // Run scanners in parallel
      const scanResults = await this.runScannersInParallel(request.target, tools);
      
      // Aggregate results
      for (const result of scanResults.results) {
        if (result.status === 'success' && result.result) {
          allFindings.push(...result.result.findings);
          tokenUsage += result.result.tokenUsage;
        } else if (result.status === 'error') {
          const errorMsg = `${result.id} failed: ${result.error?.message}`;
          console.error(errorMsg);
          errors.push(errorMsg);
        }
      }
    } else {
      // Run scanners sequentially
      for (const tool of tools) {
        try {
          console.error(`Running ${tool} scanner...`);
          
          const scanResult = await this.runSingleScanner(tool, request.target);
          allFindings.push(...scanResult.findings);
          tokenUsage += scanResult.tokenUsage;
          
        } catch (error) {
          const errorMsg = `${tool} failed: ${error instanceof Error ? error.message : 'Unknown error'}`;
          console.error(errorMsg);
          errors.push(errorMsg);
        }
      }
    }

    // Calculate summary
    const summary = this.calculateSummary(allFindings);

    const result: ScanResult = {
      scanId,
      status: errors.length === 0 ? 'success' : (allFindings.length > 0 ? 'partial' : 'failed'),
      summary,
      findings: allFindings,
      tokenUsage,
      scanTimeMs: Date.now() - startTime,
      errors: errors.length > 0 ? errors : undefined,
    };

    // Cache successful results
    if (result.status === 'success') {
      await this.cache.set('project', request.target, tools, result, request.profile);
    }

    console.error(`Project scan completed: ${result.status}, ${allFindings.length} findings`);
    return result;
  }

  private async runSemgrep(targetPath: string): Promise<{ findings: Finding[]; tokenUsage: number }> {
    const config: ScannerConfig = {
      image: 'returntocorp/semgrep:latest',
      command: [
        'semgrep',
        '--config=auto',
        '--json',
        '--no-git-ignore',
        '--disable-version-check',
        '--metrics=off',
        '--timeout=300',
        '/scan/target'
      ],
      environment: {
        SEMGREP_SEND_METRICS: 'off',
        SEMGREP_VERSION_CHECK: 'off'
      },
      volumes: [],
      resourceLimits: {
        memory: 2 * 1024 * 1024 * 1024, // 2GB
        cpus: 2,
        pidsLimit: 200,
      },
      timeout: 300000, // 5 minutes
    };

    const result = await this.orchestrator.runScanner('semgrep', config, targetPath);
    
    if (result.exitCode !== 0 && result.exitCode !== 1) { // Semgrep returns 1 when findings found
      throw new Error(`Semgrep failed with exit code ${result.exitCode}: ${result.stderr}`);
    }

    return this.parseSemgrepOutput(result.stdout);
  }

  private async runTrivy(targetPath: string): Promise<{ findings: Finding[]; tokenUsage: number }> {
    const config: ScannerConfig = {
      image: 'aquasec/trivy:latest',
      command: [
        'trivy',
        'filesystem',
        '--format=json',
        '--quiet',
        '--no-progress',
        '/scan/target'
      ],
      environment: {
        TRIVY_NO_PROGRESS: 'true',
        TRIVY_QUIET: 'true'
      },
      volumes: [],
      resourceLimits: {
        memory: 1 * 1024 * 1024 * 1024, // 1GB
        cpus: 1,
        pidsLimit: 100,
      },
      timeout: 600000, // 10 minutes
    };

    const result = await this.orchestrator.runScanner('trivy', config, targetPath);
    
    if (result.exitCode !== 0) {
      throw new Error(`Trivy failed with exit code ${result.exitCode}: ${result.stderr}`);
    }

    return this.parseTrivyOutput(result.stdout);
  }

  private async runGitleaks(targetPath: string): Promise<{ findings: Finding[]; tokenUsage: number }> {
    const config: ScannerConfig = {
      image: 'zricethezav/gitleaks:latest',
      command: [
        'gitleaks',
        'detect',
        '--source=/scan/target',
        '--format=json',
        '--no-git'
      ],
      environment: {},
      volumes: [],
      resourceLimits: {
        memory: 512 * 1024 * 1024, // 512MB
        cpus: 1,
        pidsLimit: 50,
      },
      timeout: 300000, // 5 minutes
    };

    const result = await this.orchestrator.runScanner('gitleaks', config, targetPath);
    
    // Gitleaks returns 1 when secrets found, 0 when none found
    if (result.exitCode !== 0 && result.exitCode !== 1) {
      throw new Error(`Gitleaks failed with exit code ${result.exitCode}: ${result.stderr}`);
    }

    return this.parseGitleaksOutput(result.stdout);
  }

  private parseSemgrepOutput(output: string): { findings: Finding[]; tokenUsage: number } {
    const findings: Finding[] = [];
    
    try {
      const semgrepResults = JSON.parse(output);
      
      if (semgrepResults.results) {
        for (const result of semgrepResults.results) {
          findings.push({
            id: `semgrep_${result.check_id}_${Date.now()}`,
            type: 'sast',
            severity: this.mapSemgrepSeverity(result.extra?.severity || 'INFO'),
            title: result.extra?.message || result.check_id,
            description: result.extra?.metadata?.description || result.extra?.message || 'SAST finding',
            location: {
              file: result.path,
              line: result.start?.line,
              column: result.start?.col,
            },
            remediation: result.extra?.metadata?.fix || 'Review and fix the identified security issue',
          });
        }
      }
    } catch (error) {
      console.error('Failed to parse Semgrep output:', error);
    }

    return {
      findings,
      tokenUsage: Math.min(findings.length * 10 + 50, 300) // Estimate token usage
    };
  }

  private parseTrivyOutput(output: string): { findings: Finding[]; tokenUsage: number } {
    const findings: Finding[] = [];
    
    try {
      const trivyResults = JSON.parse(output);
      
      if (trivyResults.Results) {
        for (const result of trivyResults.Results) {
          if (result.Vulnerabilities) {
            for (const vuln of result.Vulnerabilities) {
              findings.push({
                id: `trivy_${vuln.VulnerabilityID}_${Date.now()}`,
                type: 'dependency',
                severity: this.mapTrivySeverity(vuln.Severity),
                title: `${vuln.VulnerabilityID}: ${vuln.Title || vuln.Description}`,
                description: vuln.Description || vuln.Title || 'Dependency vulnerability',
                location: {
                  file: result.Target,
                },
                cve: vuln.VulnerabilityID,
                cvssScore: vuln.CVSS?.nvd?.V3Score || vuln.CVSS?.redhat?.V3Score,
                remediation: vuln.FixedVersion ? `Update to version ${vuln.FixedVersion}` : 'Update to a patched version',
              });
            }
          }
        }
      }
    } catch (error) {
      console.error('Failed to parse Trivy output:', error);
    }

    return {
      findings,
      tokenUsage: Math.min(findings.length * 15 + 75, 400) // Estimate token usage
    };
  }

  private parseGitleaksOutput(output: string): { findings: Finding[]; tokenUsage: number } {
    const findings: Finding[] = [];
    
    try {
      const gitleaksResults = JSON.parse(output);
      
      if (Array.isArray(gitleaksResults)) {
        for (const result of gitleaksResults) {
          findings.push({
            id: `gitleaks_${result.RuleID}_${Date.now()}`,
            type: 'secret',
            severity: 'high', // All secrets are high severity
            title: `Exposed Secret: ${result.Description}`,
            description: `Found ${result.Description} in code`,
            location: {
              file: result.File,
              line: result.StartLine,
            },
            remediation: 'Remove the exposed secret and rotate credentials',
          });
        }
      }
    } catch (error) {
      console.error('Failed to parse Gitleaks output:', error);
    }

    return {
      findings,
      tokenUsage: Math.min(findings.length * 20 + 25, 200) // Estimate token usage
    };
  }

  private async runNuclei(targetPath: string): Promise<{ findings: Finding[]; tokenUsage: number }> {
    const config: ScannerConfig = {
      image: 'projectdiscovery/nuclei:latest',
      command: [
        'nuclei',
        '-target', '/scan/target',
        '-json',
        '-silent',
        '-severity', 'critical,high,medium',
        '-type', 'file',
        '-disable-update-check'
      ],
      environment: {
        HOME: '/tmp'
      },
      volumes: [],
      resourceLimits: {
        memory: 2 * 1024 * 1024 * 1024, // 2GB
        cpus: 2,
        pidsLimit: 150,
      },
      timeout: 600000, // 10 minutes
    };

    const result = await this.orchestrator.runScanner('nuclei', config, targetPath);
    
    if (result.exitCode !== 0 && result.exitCode !== 1) {
      throw new Error(`Nuclei failed with exit code ${result.exitCode}: ${result.stderr}`);
    }

    return this.parseNucleiOutput(result.stdout);
  }

  private parseNucleiOutput(output: string): { findings: Finding[]; tokenUsage: number } {
    const findings: Finding[] = [];
    
    try {
      const lines = output.trim().split('\n').filter(line => line);
      
      for (const line of lines) {
        try {
          const nucleiResult = JSON.parse(line);
          
          findings.push({
            id: `nuclei_${nucleiResult.template_id}_${Date.now()}`,
            type: 'vulnerability',
            severity: this.mapNucleiSeverity(nucleiResult.info?.severity || 'medium'),
            title: nucleiResult.info?.name || nucleiResult.template_id,
            description: nucleiResult.info?.description || 'Vulnerability detected by Nuclei',
            location: {
              file: nucleiResult.matched_at || nucleiResult.host,
            },
            cve: nucleiResult.info?.cve?.join(', '),
            cvssScore: nucleiResult.info?.cvss_score,
            remediation: nucleiResult.info?.remediation || 'Review and fix the identified vulnerability',
          });
        } catch (err) {
          // Skip malformed lines
        }
      }
    } catch (error) {
      console.error('Failed to parse Nuclei output:', error);
    }

    return {
      findings,
      tokenUsage: Math.min(findings.length * 12 + 60, 350)
    };
  }

  private mapNucleiSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' | 'informational' {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'critical';
      case 'high': return 'high';
      case 'medium': return 'medium';
      case 'low': return 'low';
      case 'info': return 'informational';
      default: return 'medium';
    }
  }

  private async runBandit(targetPath: string): Promise<{ findings: Finding[]; tokenUsage: number }> {
    const config: ScannerConfig = {
      image: 'secfigo/bandit:latest',
      command: [
        'bandit',
        '-r', '/scan/target',
        '-f', 'json',
        '--severity-level', 'low',
        '--confidence-level', 'low'
      ],
      environment: {},
      volumes: [],
      resourceLimits: {
        memory: 1 * 1024 * 1024 * 1024, // 1GB
        cpus: 1,
        pidsLimit: 100,
      },
      timeout: 300000, // 5 minutes
    };

    const result = await this.orchestrator.runScanner('bandit', config, targetPath);
    
    if (result.exitCode !== 0 && result.exitCode !== 1) {
      throw new Error(`Bandit failed with exit code ${result.exitCode}: ${result.stderr}`);
    }

    return this.parseBanditOutput(result.stdout);
  }

  private parseBanditOutput(output: string): { findings: Finding[]; tokenUsage: number } {
    const findings: Finding[] = [];
    
    try {
      const banditResults = JSON.parse(output);
      
      if (banditResults.results) {
        for (const result of banditResults.results) {
          findings.push({
            id: `bandit_${result.test_id}_${Date.now()}`,
            type: 'sast',
            severity: this.mapBanditSeverity(result.issue_severity),
            title: `${result.test_name}: ${result.issue_text}`,
            description: result.issue_text,
            location: {
              file: result.filename,
              line: result.line_number,
              column: result.col_offset,
            },
            remediation: result.issue_cwe ? `Review CWE-${result.issue_cwe.id}` : 'Review and fix the security issue',
          });
        }
      }
    } catch (error) {
      console.error('Failed to parse Bandit output:', error);
    }

    return {
      findings,
      tokenUsage: Math.min(findings.length * 10 + 40, 250)
    };
  }

  private mapBanditSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' | 'informational' {
    switch (severity?.toUpperCase()) {
      case 'HIGH': return 'high';
      case 'MEDIUM': return 'medium';
      case 'LOW': return 'low';
      default: return 'informational';
    }
  }

  private async runGrype(targetPath: string): Promise<{ findings: Finding[]; tokenUsage: number }> {
    const config: ScannerConfig = {
      image: 'anchore/grype:latest',
      command: [
        'grype',
        'dir:/scan/target',
        '-o', 'json',
        '--quiet'
      ],
      environment: {
        GRYPE_DB_AUTO_UPDATE: 'false'
      },
      volumes: [],
      resourceLimits: {
        memory: 2 * 1024 * 1024 * 1024, // 2GB
        cpus: 2,
        pidsLimit: 100,
      },
      timeout: 600000, // 10 minutes
    };

    const result = await this.orchestrator.runScanner('grype', config, targetPath);
    
    if (result.exitCode !== 0 && result.exitCode !== 1) {
      throw new Error(`Grype failed with exit code ${result.exitCode}: ${result.stderr}`);
    }

    return this.parseGrypeOutput(result.stdout);
  }

  private parseGrypeOutput(output: string): { findings: Finding[]; tokenUsage: number } {
    const findings: Finding[] = [];
    
    try {
      const grypeResults = JSON.parse(output);
      
      if (grypeResults.matches) {
        for (const match of grypeResults.matches) {
          const vuln = match.vulnerability;
          findings.push({
            id: `grype_${vuln.id}_${Date.now()}`,
            type: 'dependency',
            severity: this.mapGrypeSeverity(vuln.severity),
            title: `${vuln.id}: ${match.artifact.name}@${match.artifact.version}`,
            description: vuln.description || `Vulnerability in ${match.artifact.name}`,
            location: {
              file: match.artifact.locations?.[0]?.path,
            },
            cve: vuln.id,
            cvssScore: vuln.cvss?.[0]?.metrics?.baseScore,
            remediation: vuln.fix?.versions ? `Update to version ${vuln.fix.versions[0]}` : 'Update to a patched version',
          });
        }
      }
    } catch (error) {
      console.error('Failed to parse Grype output:', error);
    }

    return {
      findings,
      tokenUsage: Math.min(findings.length * 15 + 70, 400)
    };
  }

  private mapGrypeSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' | 'informational' {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'critical';
      case 'high': return 'high';
      case 'medium': return 'medium';
      case 'low': return 'low';
      case 'negligible': return 'informational';
      default: return 'medium';
    }
  }

  private async runCustomRules(targetPath: string): Promise<{ findings: Finding[]; tokenUsage: number }> {
    console.error('Running custom rules scan...');
    
    try {
      const result = await this.customRuleEngine.scanWithCustomRules(targetPath);
      console.error(`Custom rules scan completed: ${result.findings.length} findings`);
      return result;
    } catch (error) {
      console.error('Custom rules scan failed:', error);
      return {
        findings: [],
        tokenUsage: 10
      };
    }
  }

  private async runOwaspDependencyCheck(targetPath: string): Promise<{ findings: Finding[]; tokenUsage: number }> {
    console.error('Running OWASP Dependency-Check scan...');
    
    const config: ScannerConfig = {
      image: 'owasp/dependency-check:latest',
      command: [
        '/usr/share/dependency-check/bin/dependency-check.sh',
        '--scan', '/scan/target',
        '--out', '/scan/target',
        '--format', 'JSON',
        '--enableRetired',
        '--enableExperimental',
        '--disableAssembly',
        '--disableAutoconf',
        '--disableBundleAudit',
        '--disableCmake'
      ],
      environment: {},
      volumes: [],
      resourceLimits: {
        memory: 4 * 1024 * 1024 * 1024, // 4GB
        cpus: 2,
        pidsLimit: 100,
      },
      timeout: 1800000, // 30 minutes
    };

    const result = await this.orchestrator.runScanner('owasp_dependency_check', config, targetPath);
    
    if (result.exitCode !== 0) {
      console.error(`OWASP Dependency-Check failed with exit code ${result.exitCode}: ${result.stderr}`);
      return {
        findings: [],
        tokenUsage: 25
      };
    }

    return this.parseOwaspDependencyCheckOutput(result.stdout, targetPath);
  }

  private parseOwaspDependencyCheckOutput(output: string, _targetPath: string): { findings: Finding[]; tokenUsage: number } {
    const findings: Finding[] = [];
    
    try {
      // Since we can't read from the container, parse stdout if it contains JSON
      let reportData;
      
      if (output.trim().startsWith('{')) {
        reportData = JSON.parse(output);
      } else {
        // No JSON output available
        console.error('No JSON report available from OWASP Dependency-Check');
        return { findings, tokenUsage: 25 };
      }
      
      if (reportData.dependencies) {
        for (const dependency of reportData.dependencies) {
          if (dependency.vulnerabilities) {
            for (const vuln of dependency.vulnerabilities) {
              findings.push({
                id: `owasp_dep_check_${vuln.name}_${Date.now()}`,
                type: 'dependency',
                severity: this.mapOwaspDcSeverity(vuln.severity),
                title: `${vuln.name}: ${dependency.fileName}`,
                description: vuln.description || `Vulnerability in dependency ${dependency.fileName}`,
                location: {
                  file: dependency.filePath || dependency.fileName,
                },
                cve: vuln.name,
                cvssScore: vuln.cvssv3?.baseScore || vuln.cvssv2?.score,
                remediation: vuln.notes || 'Update to a patched version of this dependency',
              });
            }
          }
        }
      }
    } catch (error) {
      console.error('Failed to parse OWASP Dependency-Check output:', error);
    }

    return {
      findings,
      tokenUsage: Math.min(findings.length * 20 + 50, 500)
    };
  }

  private mapOwaspDcSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' | 'informational' {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'critical';
      case 'high': return 'high';
      case 'medium': return 'medium';
      case 'low': return 'low';
      default: return 'medium';
    }
  }

  private async runCheckov(targetPath: string): Promise<{ findings: Finding[]; tokenUsage: number }> {
    const config: ScannerConfig = {
      image: 'bridgecrew/checkov:latest',
      command: [
        'checkov',
        '--directory=/scan/target',
        '--output=json',
        '--quiet',
        '--framework=dockerfile,docker_compose,kubernetes',
        '--skip-check=CKV_DOCKER_2', // Skip healthcheck requirement for security scanners
        '--compact',
        '--no-guide'
      ],
      environment: {
        CHECKOV_LOG_LEVEL: 'ERROR'
      },
      volumes: [],
      resourceLimits: {
        memory: 1 * 1024 * 1024 * 1024, // 1GB
        cpus: 1,
        pidsLimit: 100,
      },
      timeout: 300000, // 5 minutes
    };

    const result = await this.orchestrator.runScanner('checkov', config, targetPath);
    
    // Checkov returns 1 when findings found, 0 when none found
    if (result.exitCode !== 0 && result.exitCode !== 1) {
      throw new Error(`Checkov failed with exit code ${result.exitCode}: ${result.stderr}`);
    }

    return this.parseCheckovOutput(result.stdout);
  }

  private parseCheckovOutput(output: string): { findings: Finding[]; tokenUsage: number } {
    const findings: Finding[] = [];
    
    try {
      const checkovResults = JSON.parse(output);
      
      if (checkovResults.results && checkovResults.results.failed_checks) {
        for (const check of checkovResults.results.failed_checks) {
          findings.push({
            id: `checkov_${check.check_id}_${Date.now()}`,
            type: 'infrastructure',
            severity: this.mapCheckovSeverity(check.severity || 'MEDIUM'),
            title: `${check.check_id}: ${check.check_name}`,
            description: check.description || check.check_name,
            location: {
              file: check.file_path,
              line: check.file_line_range ? check.file_line_range[0] : undefined,
            },
            remediation: check.guideline || 'Review and fix the infrastructure security issue',
          });
        }
      }
    } catch (error) {
      console.error('Failed to parse Checkov output:', error);
    }

    return {
      findings,
      tokenUsage: Math.min(findings.length * 15 + 50, 300) // Estimate token usage
    };
  }

  private mapCheckovSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' | 'informational' {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 'critical';
      case 'HIGH':
        return 'high';
      case 'MEDIUM':
        return 'medium';
      case 'LOW':
        return 'low';
      default:
        return 'medium'; // Default IaC issues to medium
    }
  }

  private mapSemgrepSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' | 'informational' {
    switch (severity?.toUpperCase()) {
      case 'ERROR':
        return 'high';
      case 'WARNING':
        return 'medium';
      case 'INFO':
        return 'low';
      default:
        return 'informational';
    }
  }

  private mapTrivySeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' | 'informational' {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 'critical';
      case 'HIGH':
        return 'high';
      case 'MEDIUM':
        return 'medium';
      case 'LOW':
        return 'low';
      default:
        return 'informational';
    }
  }

  private calculateSummary(findings: Finding[]) {
    const summary = {
      vulnerabilities: findings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
    };

    for (const finding of findings) {
      summary[finding.severity]++;
    }

    return summary;
  }

  private getDefaultTools(profile?: string): string[] {
    switch (profile) {
      case 'quick':
        return ['gitleaks', 'custom_rules'];
      case 'thorough':
        return ['semgrep', 'trivy', 'gitleaks', 'checkov', 'nuclei', 'bandit', 'grype', 'owasp_dependency_check', 'custom_rules'];
      case 'comprehensive':
        return ['semgrep', 'trivy', 'gitleaks', 'checkov', 'nuclei', 'grype', 'owasp_dependency_check', 'custom_rules'];
      default: // standard
        return ['semgrep', 'trivy', 'checkov', 'custom_rules'];
    }
  }

  private generateScanId(): string {
    return `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private async runScannersInParallel(targetPath: string, tools: string[]) {
    const executor = new ScannerExecutor({
      maxConcurrency: 3,
      defaultTimeout: 600000, // 10 minutes
    });

    const scanners = tools.map(tool => ({
      id: tool,
      scanner: () => this.runSingleScanner(tool, targetPath),
      priority: this.getScannerPriority(tool),
      timeout: this.getScannerTimeout(tool),
    }));

    return await executor.executeScanners(scanners);
  }

  private async runSingleScanner(tool: string, targetPath: string): Promise<{ findings: Finding[]; tokenUsage: number }> {
    switch (tool) {
      case 'semgrep':
        return await this.runSemgrep(targetPath);
      case 'trivy':
        return await this.runTrivy(targetPath);
      case 'gitleaks':
        return await this.runGitleaks(targetPath);
      case 'checkov':
        return await this.runCheckov(targetPath);
      case 'nuclei':
        return await this.runNuclei(targetPath);
      case 'bandit':
        return await this.runBandit(targetPath);
      case 'grype':
        return await this.runGrype(targetPath);
      case 'custom_rules':
        return await this.runCustomRules(targetPath);
      case 'owasp_dependency_check':
        return await this.runOwaspDependencyCheck(targetPath);
      default:
        throw new Error(`Unknown scanner tool: ${tool}`);
    }
  }

  private getScannerPriority(tool: string): number {
    // Higher priority for faster scanners
    switch (tool) {
      case 'gitleaks':
        return 6; // Fastest - secrets scanning
      case 'checkov':
        return 5; // Fast - IaC scanning
      case 'bandit':
        return 4; // Fast - Python SAST
      case 'semgrep':
        return 3; // Fast - SAST
      case 'trivy':
        return 2; // Slower - dependency scanning
      case 'grype':
        return 1; // Slow - comprehensive dependency scanning
      case 'nuclei':
        return 0; // Slowest - vulnerability scanning
      case 'custom_rules':
        return 4; // Fast - local pattern matching
      case 'owasp_dependency_check':
        return 1; // Slow - comprehensive dependency analysis
      default:
        return 0;
    }
  }

  private getScannerTimeout(tool: string): number {
    // Different timeouts based on scanner characteristics
    switch (tool) {
      case 'gitleaks':
        return 300000; // 5 minutes
      case 'checkov':
        return 300000; // 5 minutes - IaC scanning is usually fast
      case 'bandit':
        return 300000; // 5 minutes - Python SAST is fast
      case 'semgrep':
        return 600000; // 10 minutes
      case 'trivy':
        return 900000; // 15 minutes (can be slow for large projects)
      case 'grype':
        return 900000; // 15 minutes - comprehensive scanning
      case 'nuclei':
        return 1200000; // 20 minutes - extensive template scanning
      case 'custom_rules':
        return 120000; // 2 minutes - fast local scanning
      case 'owasp_dependency_check':
        return 1800000; // 30 minutes - thorough dependency analysis
      default:
        return 600000;
    }
  }

  async invalidateCache(targetPath?: string, tools?: string[], profile?: string): Promise<number> {
    return await this.cache.invalidate('project', targetPath, tools, profile);
  }

  async getCacheStats() {
    return await this.cache.getStats();
  }

  async cleanup(): Promise<void> {
    await this.orchestrator.cleanup();
  }
}