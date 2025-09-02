// import * as path from 'path'; // Uncomment if path operations needed
// import * as fs from 'fs/promises'; // Uncomment if file operations needed
import type { ScanRequest, ScanResult, Finding } from '../types/index.js';
import type { BoundaryEnforcer } from '../boundaries/enforcer.js';
import { DockerOrchestrator, type ScannerConfig } from './docker-orchestrator.js';
import { ResultCache } from '../cache/result-cache.js';
import { ScannerExecutor } from '../utils/parallel-executor.js';

export class ProjectScanner {
  private orchestrator: DockerOrchestrator;
  private cache: ResultCache;

  constructor(private boundaryEnforcer: BoundaryEnforcer) {
    const projectScope = this.boundaryEnforcer.getProjectScope();
    if (!projectScope) {
      throw new Error('Project scope not initialized');
    }
    this.orchestrator = new DockerOrchestrator(projectScope);
    this.cache = new ResultCache();
  }

  async initialize(): Promise<void> {
    await this.cache.initialize();
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
        return ['gitleaks'];
      case 'thorough':
        return ['semgrep', 'trivy', 'gitleaks'];
      default: // standard
        return ['semgrep', 'trivy'];
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
      default:
        throw new Error(`Unknown scanner tool: ${tool}`);
    }
  }

  private getScannerPriority(tool: string): number {
    // Higher priority for faster scanners
    switch (tool) {
      case 'gitleaks':
        return 3; // Fastest - secrets scanning
      case 'semgrep':
        return 2; // Fast - SAST
      case 'trivy':
        return 1; // Slower - dependency scanning
      default:
        return 0;
    }
  }

  private getScannerTimeout(tool: string): number {
    // Different timeouts based on scanner characteristics
    switch (tool) {
      case 'gitleaks':
        return 300000; // 5 minutes
      case 'semgrep':
        return 600000; // 10 minutes
      case 'trivy':
        return 900000; // 15 minutes (can be slow for large projects)
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