import { exec } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';
import * as fs from 'fs/promises';

const execAsync = promisify(exec);

export interface GitChange {
  file: string;
  changeType: 'added' | 'modified' | 'deleted' | 'renamed';
  additions: number;
  deletions: number;
  binary: boolean;
}

export interface GitStatus {
  branch: string;
  commit: string;
  changes: GitChange[];
  uncommittedChanges: GitChange[];
  lastScanCommit?: string;
}

export class GitAnalyzer {
  private projectRoot: string;
  private lastScanFile: string;

  constructor(projectRoot: string) {
    this.projectRoot = projectRoot;
    this.lastScanFile = path.join(projectRoot, '.shamash', 'last-scan.json');
  }

  async isGitRepository(): Promise<boolean> {
    try {
      await execAsync('git rev-parse --git-dir', { cwd: this.projectRoot });
      return true;
    } catch {
      return false;
    }
  }

  async getCurrentCommit(): Promise<string> {
    try {
      const { stdout } = await execAsync('git rev-parse HEAD', { cwd: this.projectRoot });
      return stdout.trim();
    } catch (error) {
      console.error('Failed to get current commit:', error);
      return '';
    }
  }

  async getCurrentBranch(): Promise<string> {
    try {
      const { stdout } = await execAsync('git branch --show-current', { cwd: this.projectRoot });
      return stdout.trim() || 'HEAD';
    } catch {
      return 'HEAD';
    }
  }

  async getLastScanCommit(): Promise<string | null> {
    try {
      const data = await fs.readFile(this.lastScanFile, 'utf-8');
      const lastScan = JSON.parse(data);
      return lastScan.commit || null;
    } catch {
      return null;
    }
  }

  async saveLastScanCommit(commit: string): Promise<void> {
    try {
      const dir = path.dirname(this.lastScanFile);
      await fs.mkdir(dir, { recursive: true });
      
      const data = {
        commit,
        timestamp: new Date().toISOString(),
        branch: await this.getCurrentBranch(),
      };
      
      await fs.writeFile(this.lastScanFile, JSON.stringify(data, null, 2));
    } catch (error) {
      console.error('Failed to save last scan commit:', error);
    }
  }

  async getChangedFiles(fromCommit?: string): Promise<GitChange[]> {
    const changes: GitChange[] = [];
    
    try {
      // Get the base commit for comparison
      const baseCommit = fromCommit || await this.getLastScanCommit() || 'HEAD~10';
      const currentCommit = await this.getCurrentCommit();
      
      if (baseCommit === currentCommit) {
        console.log('No changes since last scan');
        return [];
      }

      // Get diff between commits
      const diffCommand = `git diff --numstat --name-status ${baseCommit}..${currentCommit}`;
      const { stdout: statusOutput } = await execAsync(diffCommand, { cwd: this.projectRoot });
      
      // Parse name-status output
      const statusLines = statusOutput.trim().split('\n').filter(line => line);
      for (const line of statusLines) {
        const [status, ...fileParts] = line.split('\t');
        const file = fileParts.join('\t');
        
        if (!file) continue;

        let changeType: 'added' | 'modified' | 'deleted' | 'renamed' = 'modified';
        switch (status[0]) {
          case 'A': changeType = 'added'; break;
          case 'M': changeType = 'modified'; break;
          case 'D': changeType = 'deleted'; break;
          case 'R': changeType = 'renamed'; break;
        }

        // Get detailed stats for non-deleted files
        if (changeType !== 'deleted') {
          try {
            const { stdout: numstatOutput } = await execAsync(
              `git diff --numstat ${baseCommit}..${currentCommit} -- "${file}"`,
              { cwd: this.projectRoot }
            );
            
            const stats = numstatOutput.trim().split('\t');
            const additions = stats[0] === '-' ? 0 : parseInt(stats[0], 10);
            const deletions = stats[1] === '-' ? 0 : parseInt(stats[1], 10);
            const binary = stats[0] === '-' && stats[1] === '-';

            changes.push({
              file,
              changeType,
              additions,
              deletions,
              binary,
            });
          } catch {
            // File might not exist in current state
            changes.push({
              file,
              changeType,
              additions: 0,
              deletions: 0,
              binary: false,
            });
          }
        } else {
          changes.push({
            file,
            changeType,
            additions: 0,
            deletions: 0,
            binary: false,
          });
        }
      }
    } catch (error) {
      console.error('Failed to get changed files:', error);
    }

    return changes;
  }

  async getUncommittedChanges(): Promise<GitChange[]> {
    const changes: GitChange[] = [];
    
    try {
      // Get uncommitted changes
      const { stdout } = await execAsync('git status --porcelain', { cwd: this.projectRoot });
      const lines = stdout.trim().split('\n').filter(line => line);
      
      for (const line of lines) {
        const status = line.substring(0, 2);
        const file = line.substring(3);
        
        let changeType: 'added' | 'modified' | 'deleted' | 'renamed' = 'modified';
        
        if (status.includes('A')) changeType = 'added';
        else if (status.includes('M')) changeType = 'modified';
        else if (status.includes('D')) changeType = 'deleted';
        else if (status.includes('R')) changeType = 'renamed';

        // Get diff stats for uncommitted changes
        if (changeType !== 'deleted') {
          try {
            const { stdout: diffOutput } = await execAsync(
              `git diff --numstat HEAD -- "${file}"`,
              { cwd: this.projectRoot }
            );
            
            if (diffOutput) {
              const stats = diffOutput.trim().split('\t');
              changes.push({
                file,
                changeType,
                additions: stats[0] === '-' ? 0 : parseInt(stats[0], 10),
                deletions: stats[1] === '-' ? 0 : parseInt(stats[1], 10),
                binary: stats[0] === '-' && stats[1] === '-',
              });
            } else {
              // File might be staged
              changes.push({
                file,
                changeType,
                additions: 0,
                deletions: 0,
                binary: false,
              });
            }
          } catch {
            changes.push({
              file,
              changeType,
              additions: 0,
              deletions: 0,
              binary: false,
            });
          }
        } else {
          changes.push({
            file,
            changeType,
            additions: 0,
            deletions: 0,
            binary: false,
          });
        }
      }
    } catch (error) {
      console.error('Failed to get uncommitted changes:', error);
    }

    return changes;
  }

  async getGitStatus(): Promise<GitStatus> {
    const [branch, commit, changes, uncommittedChanges, lastScanCommit] = await Promise.all([
      this.getCurrentBranch(),
      this.getCurrentCommit(),
      this.getChangedFiles(),
      this.getUncommittedChanges(),
      this.getLastScanCommit(),
    ]);

    return {
      branch,
      commit,
      changes,
      uncommittedChanges,
      lastScanCommit: lastScanCommit || undefined,
    };
  }

  filterRelevantFiles(changes: GitChange[]): GitChange[] {
    // Filter for files that should be scanned
    const relevantExtensions = [
      '.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.go', '.rs', '.c', '.cpp',
      '.php', '.rb', '.swift', '.kt', '.scala', '.sh', '.yaml', '.yml', '.json',
      '.xml', '.tf', '.hcl', 'Dockerfile', 'docker-compose'
    ];

    const ignorePaths = [
      'node_modules/', 'vendor/', 'dist/', 'build/', 'target/', '.git/',
      'coverage/', '.nyc_output/', '__pycache__/', '.pytest_cache/'
    ];

    return changes.filter(change => {
      // Skip deleted files
      if (change.changeType === 'deleted') return false;
      
      // Skip binary files
      if (change.binary) return false;
      
      // Check if file should be ignored
      if (ignorePaths.some(path => change.file.includes(path))) return false;
      
      // Check if file has relevant extension
      const hasRelevantExt = relevantExtensions.some(ext => 
        change.file.endsWith(ext) || change.file.includes(ext)
      );
      
      return hasRelevantExt;
    });
  }

  async shouldRunIncrementalScan(): Promise<boolean> {
    if (!await this.isGitRepository()) {
      return false;
    }

    const lastScanCommit = await this.getLastScanCommit();
    if (!lastScanCommit) {
      // No previous scan, run full scan
      return false;
    }

    const currentCommit = await this.getCurrentCommit();
    if (lastScanCommit === currentCommit) {
      // Check for uncommitted changes
      const uncommitted = await this.getUncommittedChanges();
      return uncommitted.length > 0;
    }

    return true;
  }

  async getIncrementalScanScope(): Promise<{
    files: string[];
    fullScanRequired: boolean;
    reason?: string;
  }> {
    if (!await this.isGitRepository()) {
      return {
        files: [],
        fullScanRequired: true,
        reason: 'Not a git repository',
      };
    }

    const status = await this.getGitStatus();
    
    // Combine committed and uncommitted changes
    const allChanges = [...status.changes, ...status.uncommittedChanges];
    
    // Remove duplicates
    const uniqueChanges = Array.from(
      new Map(allChanges.map(c => [c.file, c])).values()
    );

    // Filter for relevant files
    const relevantChanges = this.filterRelevantFiles(uniqueChanges);

    // Check if too many files changed (threshold for full scan)
    if (relevantChanges.length > 100) {
      return {
        files: [],
        fullScanRequired: true,
        reason: `Too many files changed (${relevantChanges.length}), running full scan`,
      };
    }

    // Check for critical file changes that require full scan
    const criticalFiles = ['package.json', 'requirements.txt', 'go.mod', 'Cargo.toml', 'pom.xml'];
    const hasCriticalChanges = relevantChanges.some(change =>
      criticalFiles.some(critical => change.file.endsWith(critical))
    );

    if (hasCriticalChanges) {
      return {
        files: [],
        fullScanRequired: true,
        reason: 'Critical dependency files changed, running full scan',
      };
    }

    // Return files for incremental scan
    const filePaths = relevantChanges.map(c => path.join(this.projectRoot, c.file));
    
    return {
      files: filePaths,
      fullScanRequired: false,
    };
  }
}