import type { ScanRequest, ScanResult, Finding } from '../types/index.js';
import type { ProjectScanner } from './project-scanner.js';
import { GitAnalyzer } from '../utils/git-analyzer.js';
import { ResultCache } from '../cache/result-cache.js';
import * as path from 'path';

export interface IncrementalScanResult extends ScanResult {
  incrementalMode: boolean;
  filesScanned: number;
  filesFromCache: number;
  totalFiles: number;
  gitCommit?: string;
}

export class IncrementalScanner {
  private gitAnalyzer: GitAnalyzer;
  private cache: ResultCache;
  private projectScanner: ProjectScanner;

  constructor(
    projectRoot: string,
    projectScanner: ProjectScanner,
    cache?: ResultCache
  ) {
    this.gitAnalyzer = new GitAnalyzer(projectRoot);
    this.projectScanner = projectScanner;
    this.cache = cache || new ResultCache();
  }

  async scan(request: ScanRequest): Promise<IncrementalScanResult> {
    const startTime = Date.now();
    
    // Check if incremental scan is possible
    const shouldIncremental = await this.gitAnalyzer.shouldRunIncrementalScan();
    
    if (!shouldIncremental || request.options?.incremental === false) {
      // Run full scan
      console.error('Running full scan (incremental not applicable)');
      const fullResult = await this.projectScanner.scan(request);
      
      // Save current commit for next incremental scan
      const currentCommit = await this.gitAnalyzer.getCurrentCommit();
      if (currentCommit) {
        await this.gitAnalyzer.saveLastScanCommit(currentCommit);
      }
      
      return {
        ...fullResult,
        incrementalMode: false,
        filesScanned: -1, // All files
        filesFromCache: 0,
        totalFiles: -1,
        gitCommit: currentCommit,
      };
    }

    // Get incremental scan scope
    const scope = await this.gitAnalyzer.getIncrementalScanScope();
    
    if (scope.fullScanRequired) {
      console.error(`Full scan required: ${scope.reason}`);
      const fullResult = await this.projectScanner.scan(request);
      
      const currentCommit = await this.gitAnalyzer.getCurrentCommit();
      if (currentCommit) {
        await this.gitAnalyzer.saveLastScanCommit(currentCommit);
      }
      
      return {
        ...fullResult,
        incrementalMode: false,
        filesScanned: -1,
        filesFromCache: 0,
        totalFiles: -1,
        gitCommit: currentCommit,
        errors: fullResult.errors ? [...fullResult.errors, scope.reason!] : [scope.reason!],
      };
    }

    // Perform incremental scan
    console.error(`Running incremental scan on ${scope.files.length} changed files`);
    
    const allFindings: Finding[] = [];
    const errors: string[] = [];
    let tokenUsage = 0;
    let filesFromCache = 0;

    // Get cached results for unchanged files
    const cachedResults = await this.getCachedResults(request);
    if (cachedResults) {
      allFindings.push(...cachedResults.findings);
      filesFromCache = cachedResults.fileCount;
      tokenUsage += cachedResults.tokenUsage;
    }

    // Scan only changed files
    if (scope.files.length > 0) {
      const incrementalRequest: ScanRequest = {
        ...request,
        options: {
          ...request.options,
          incremental: true,
        },
      };

      try {
        const scanResult = await this.scanChangedFiles(incrementalRequest, scope.files);
        allFindings.push(...scanResult.findings);
        tokenUsage += scanResult.tokenUsage;
        
        if (scanResult.errors) {
          errors.push(...scanResult.errors);
        }
      } catch (error) {
        const errorMsg = `Incremental scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`;
        console.error(errorMsg);
        errors.push(errorMsg);
      }
    }

    // Update last scan commit
    const currentCommit = await this.gitAnalyzer.getCurrentCommit();
    if (currentCommit) {
      await this.gitAnalyzer.saveLastScanCommit(currentCommit);
    }

    // Calculate summary
    const summary = this.calculateSummary(allFindings);

    const result: IncrementalScanResult = {
      scanId: this.generateScanId(),
      status: errors.length === 0 ? 'success' : 'partial',
      summary,
      findings: allFindings,
      tokenUsage,
      scanTimeMs: Date.now() - startTime,
      incrementalMode: true,
      filesScanned: scope.files.length,
      filesFromCache,
      totalFiles: scope.files.length + filesFromCache,
      gitCommit: currentCommit,
      errors: errors.length > 0 ? errors : undefined,
    };

    // Cache the incremental results
    await this.cacheIncrementalResults(result, scope.files);

    console.error(`Incremental scan completed: ${scope.files.length} files scanned, ${filesFromCache} from cache`);
    return result;
  }

  private async scanChangedFiles(request: ScanRequest, files: string[]): Promise<ScanResult> {
    // Create a temporary scan request for just the changed files
    const tempRequest: ScanRequest = {
      ...request,
      target: request.target,
      options: {
        ...request.options,
        incremental: true,
      },
    };

    // Use the project scanner but limit to specific files
    // This would require modifying the scanner to accept file lists
    // For now, we'll scan the whole project but filter results
    const fullScan = await this.projectScanner.scan(tempRequest);
    
    // Filter findings to only those in changed files
    const relevantFindings = fullScan.findings.filter(finding => {
      if (!finding.location?.file) return false;
      
      const absolutePath = path.isAbsolute(finding.location.file)
        ? finding.location.file
        : path.join(request.target, finding.location.file);
      
      return files.some(file => absolutePath.includes(file) || file.includes(absolutePath));
    });

    return {
      ...fullScan,
      findings: relevantFindings,
      tokenUsage: Math.ceil(fullScan.tokenUsage * (relevantFindings.length / Math.max(fullScan.findings.length, 1))),
    };
  }

  private async getCachedResults(request: ScanRequest): Promise<{
    findings: Finding[];
    fileCount: number;
    tokenUsage: number;
  } | null> {
    try {
      // Get the last full scan from cache
      const lastCommit = await this.gitAnalyzer.getLastScanCommit();
      if (!lastCommit) return null;

      // Try to get cached results for the last commit
      const cachedData = await this.cache.get('project', request.target, request.tools || [], request.profile);
      
      if (cachedData && cachedData.findings) {
        // Filter out findings from changed files
        const scope = await this.gitAnalyzer.getIncrementalScanScope();
        const changedFiles = new Set(scope.files);
        
        const unchangedFindings = cachedData.findings.filter(finding => {
          if (!finding.location?.file) return true;
          
          const absolutePath = path.isAbsolute(finding.location.file)
            ? finding.location.file
            : path.join(request.target, finding.location.file);
          
          return !changedFiles.has(absolutePath);
        });

        return {
          findings: unchangedFindings,
          fileCount: -1, // Unknown from cache
          tokenUsage: 0, // No new tokens used for cached results
        };
      }
    } catch (error) {
      console.error('Failed to get cached results:', error);
    }

    return null;
  }

  private async cacheIncrementalResults(result: IncrementalScanResult, changedFiles: string[]): Promise<void> {
    try {
      // Create a cache entry for this incremental scan
      const cacheData = {
        ...result,
        changedFiles,
        timestamp: new Date().toISOString(),
      };

      // Store with git commit as part of the key
      if (result.gitCommit) {
        await this.cache.set(
          'incremental',
          result.gitCommit,
          result.findings.map(f => f.type),
          cacheData,
          'incremental'
        );
      }
    } catch (error) {
      console.error('Failed to cache incremental results:', error);
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

  private generateScanId(): string {
    return `incremental_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  async getIncrementalStats(): Promise<{
    lastScanCommit: string | null;
    currentCommit: string;
    changesPending: number;
    incrementalPossible: boolean;
  }> {
    const status = await this.gitAnalyzer.getGitStatus();
    const incrementalPossible = await this.gitAnalyzer.shouldRunIncrementalScan();
    
    return {
      lastScanCommit: status.lastScanCommit || null,
      currentCommit: status.commit,
      changesPending: status.changes.length + status.uncommittedChanges.length,
      incrementalPossible,
    };
  }
}