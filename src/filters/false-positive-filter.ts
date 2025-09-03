import type { Finding } from '../types/index.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';

export interface FalsePositiveRule {
  id: string;
  pattern?: string;
  findingType?: string;
  file?: string;
  line?: number;
  hash?: string;
  reason: string;
  expires?: string;
  addedBy?: string;
  addedAt: string;
}

export interface FilterResult {
  finding: Finding;
  filtered: boolean;
  reason?: string;
  confidence: number;
}

export interface FilterStats {
  totalFindings: number;
  filtered: number;
  passed: number;
  filterRate: number;
  rules: {
    total: number;
    active: number;
    expired: number;
  };
}

export class FalsePositiveFilter {
  private rules: FalsePositiveRule[] = [];
  private ignoreFilePath: string;
  private mlPatterns: Map<string, number>;

  constructor(projectRoot: string) {
    this.ignoreFilePath = path.join(projectRoot, '.shamash-ignore');
    this.mlPatterns = this.initializeMLPatterns();
  }

  private initializeMLPatterns(): Map<string, number> {
    // Common false positive patterns with confidence scores
    const patterns = new Map<string, number>();
    
    // Test file patterns
    patterns.set('test/', 0.8);
    patterns.set('spec/', 0.8);
    patterns.set('__tests__/', 0.9);
    patterns.set('.test.', 0.85);
    patterns.set('.spec.', 0.85);
    patterns.set('mock', 0.7);
    patterns.set('fixture', 0.75);
    patterns.set('example', 0.6);
    
    // Documentation patterns
    patterns.set('README', 0.9);
    patterns.set('.md', 0.85);
    patterns.set('docs/', 0.8);
    patterns.set('documentation/', 0.8);
    
    // Build artifacts
    patterns.set('dist/', 0.95);
    patterns.set('build/', 0.95);
    patterns.set('.min.js', 0.9);
    patterns.set('bundle.', 0.85);
    
    // Third-party code
    patterns.set('vendor/', 0.95);
    patterns.set('node_modules/', 1.0);
    patterns.set('dependencies/', 0.9);
    
    // Common false positive finding patterns
    patterns.set('TODO', 0.6);
    patterns.set('FIXME', 0.6);
    patterns.set('localhost', 0.7);
    patterns.set('127.0.0.1', 0.7);
    patterns.set('example.com', 0.9);
    patterns.set('test-', 0.75);
    patterns.set('demo-', 0.8);
    
    return patterns;
  }

  async loadRules(): Promise<void> {
    try {
      const content = await fs.readFile(this.ignoreFilePath, 'utf-8');
      this.rules = this.parseIgnoreFile(content);
      console.error(`Loaded ${this.rules.length} false positive rules`);
    } catch (error) {
      // File doesn't exist yet, start with empty rules
      this.rules = [];
    }
  }

  private parseIgnoreFile(content: string): FalsePositiveRule[] {
    const rules: FalsePositiveRule[] = [];
    const lines = content.split('\n');
    
    let currentRule: Partial<FalsePositiveRule> = {};
    
    for (const line of lines) {
      const trimmed = line.trim();
      
      // Skip comments and empty lines
      if (!trimmed || trimmed.startsWith('#')) continue;
      
      // Parse rule lines
      if (trimmed.startsWith('rule:')) {
        if (currentRule.id) {
          rules.push(currentRule as FalsePositiveRule);
        }
        currentRule = {
          id: trimmed.substring(5).trim(),
          addedAt: new Date().toISOString(),
        };
      } else if (trimmed.startsWith('pattern:')) {
        currentRule.pattern = trimmed.substring(8).trim();
      } else if (trimmed.startsWith('type:')) {
        currentRule.findingType = trimmed.substring(5).trim();
      } else if (trimmed.startsWith('file:')) {
        currentRule.file = trimmed.substring(5).trim();
      } else if (trimmed.startsWith('line:')) {
        currentRule.line = parseInt(trimmed.substring(5).trim(), 10);
      } else if (trimmed.startsWith('hash:')) {
        currentRule.hash = trimmed.substring(5).trim();
      } else if (trimmed.startsWith('reason:')) {
        currentRule.reason = trimmed.substring(7).trim();
      } else if (trimmed.startsWith('expires:')) {
        currentRule.expires = trimmed.substring(8).trim();
      } else if (trimmed.startsWith('added-by:')) {
        currentRule.addedBy = trimmed.substring(9).trim();
      }
    }
    
    // Add last rule
    if (currentRule.id && currentRule.reason) {
      rules.push(currentRule as FalsePositiveRule);
    }
    
    return rules;
  }

  async saveRules(): Promise<void> {
    const content = this.generateIgnoreFile();
    await fs.writeFile(this.ignoreFilePath, content, 'utf-8');
  }

  private generateIgnoreFile(): string {
    const lines: string[] = [];
    
    lines.push('# Shamash False Positive Suppression File');
    lines.push('# This file contains rules to suppress known false positives');
    lines.push('# Generated: ' + new Date().toISOString());
    lines.push('');
    
    for (const rule of this.rules) {
      lines.push(`rule: ${rule.id}`);
      if (rule.pattern) lines.push(`pattern: ${rule.pattern}`);
      if (rule.findingType) lines.push(`type: ${rule.findingType}`);
      if (rule.file) lines.push(`file: ${rule.file}`);
      if (rule.line !== undefined) lines.push(`line: ${rule.line}`);
      if (rule.hash) lines.push(`hash: ${rule.hash}`);
      lines.push(`reason: ${rule.reason}`);
      if (rule.expires) lines.push(`expires: ${rule.expires}`);
      if (rule.addedBy) lines.push(`added-by: ${rule.addedBy}`);
      lines.push(`added-at: ${rule.addedAt}`);
      lines.push('');
    }
    
    return lines.join('\n');
  }

  async filterFindings(findings: Finding[]): Promise<FilterResult[]> {
    await this.loadRules();
    
    const results: FilterResult[] = [];
    
    for (const finding of findings) {
      const result = await this.evaluateFinding(finding);
      results.push(result);
    }
    
    return results;
  }

  private async evaluateFinding(finding: Finding): Promise<FilterResult> {
    // Check against manual rules first
    const manualRule = this.checkManualRules(finding);
    if (manualRule) {
      return {
        finding,
        filtered: true,
        reason: manualRule.reason,
        confidence: 1.0,
      };
    }
    
    // Check ML-based patterns
    const mlResult = this.checkMLPatterns(finding);
    if (mlResult.confidence > 0.7) {
      return {
        finding,
        filtered: true,
        reason: `ML pattern match: ${mlResult.reason}`,
        confidence: mlResult.confidence,
      };
    }
    
    // Check heuristics
    const heuristicResult = this.checkHeuristics(finding);
    if (heuristicResult.shouldFilter) {
      return {
        finding,
        filtered: true,
        reason: heuristicResult.reason,
        confidence: heuristicResult.confidence,
      };
    }
    
    // Finding passes all filters
    return {
      finding,
      filtered: false,
      confidence: 0,
    };
  }

  private checkManualRules(finding: Finding): FalsePositiveRule | null {
    for (const rule of this.rules) {
      // Check if rule is expired
      if (rule.expires && new Date(rule.expires) < new Date()) {
        continue;
      }
      
      // Check finding type match
      if (rule.findingType && rule.findingType !== finding.type) {
        continue;
      }
      
      // Check file match
      if (rule.file && finding.location?.file) {
        if (!finding.location.file.includes(rule.file)) {
          continue;
        }
      }
      
      // Check line match
      if (rule.line !== undefined && finding.location?.line) {
        if (Math.abs(rule.line - finding.location.line) > 5) {
          continue;
        }
      }
      
      // Check pattern match
      if (rule.pattern) {
        const regex = new RegExp(rule.pattern, 'i');
        const searchText = `${finding.title} ${finding.description}`;
        if (!regex.test(searchText)) {
          continue;
        }
      }
      
      // Check hash match (exact finding match)
      if (rule.hash) {
        const findingHash = this.hashFinding(finding);
        if (rule.hash !== findingHash) {
          continue;
        }
      }
      
      // Rule matches
      return rule;
    }
    
    return null;
  }

  private checkMLPatterns(finding: Finding): { confidence: number; reason: string } {
    let maxConfidence = 0;
    let matchedPattern = '';
    
    const searchText = `${finding.location?.file || ''} ${finding.title} ${finding.description}`.toLowerCase();
    
    for (const [pattern, confidence] of this.mlPatterns) {
      if (searchText.includes(pattern.toLowerCase())) {
        if (confidence > maxConfidence) {
          maxConfidence = confidence;
          matchedPattern = pattern;
        }
      }
    }
    
    // Additional ML checks for specific finding types
    if (finding.type === 'secret' && finding.location?.file) {
      // Check if it's in a test file
      if (finding.location.file.includes('test') || finding.location.file.includes('spec')) {
        maxConfidence = Math.max(maxConfidence, 0.85);
        matchedPattern = 'test file secret';
      }
      
      // Check for example/demo patterns
      if (finding.title.toLowerCase().includes('example') || 
          finding.title.toLowerCase().includes('demo')) {
        maxConfidence = Math.max(maxConfidence, 0.9);
        matchedPattern = 'example credential';
      }
    }
    
    if (finding.severity === 'informational' && maxConfidence < 0.5) {
      // Informational findings in certain contexts are often FPs
      if (searchText.includes('todo') || searchText.includes('fixme')) {
        maxConfidence = 0.75;
        matchedPattern = 'code comment';
      }
    }
    
    return {
      confidence: maxConfidence,
      reason: matchedPattern,
    };
  }

  private checkHeuristics(finding: Finding): { 
    shouldFilter: boolean; 
    confidence: number; 
    reason: string;
  } {
    // Heuristic 1: Localhost/development URLs
    if (finding.type === 'dast' || finding.type === 'sast') {
      const devPatterns = ['localhost', '127.0.0.1', '0.0.0.0', 'example.com', 'test.com'];
      const text = `${finding.title} ${finding.description}`.toLowerCase();
      
      for (const pattern of devPatterns) {
        if (text.includes(pattern)) {
          return {
            shouldFilter: true,
            confidence: 0.8,
            reason: 'Development/test URL',
          };
        }
      }
    }
    
    // Heuristic 2: Known test frameworks
    if (finding.location?.file) {
      const testFrameworks = ['jest', 'mocha', 'jasmine', 'pytest', 'unittest', 'rspec'];
      const file = finding.location.file.toLowerCase();
      
      for (const framework of testFrameworks) {
        if (file.includes(framework)) {
          return {
            shouldFilter: true,
            confidence: 0.85,
            reason: `Test framework file (${framework})`,
          };
        }
      }
    }
    
    // Heuristic 3: Low severity in generated code
    if (finding.severity === 'low' || finding.severity === 'informational') {
      if (finding.location?.file) {
        const generatedPatterns = ['.min.', '-min.', '.bundle.', 'generated', 'compiled'];
        const file = finding.location.file.toLowerCase();
        
        for (const pattern of generatedPatterns) {
          if (file.includes(pattern)) {
            return {
              shouldFilter: true,
              confidence: 0.9,
              reason: 'Generated/minified code',
            };
          }
        }
      }
    }
    
    // Heuristic 4: Duplicate findings (same issue, different locations)
    // This would need access to all findings to detect duplicates
    // For now, we'll skip this heuristic
    
    return {
      shouldFilter: false,
      confidence: 0,
      reason: '',
    };
  }

  private hashFinding(finding: Finding): string {
    const data = `${finding.type}:${finding.title}:${finding.location?.file}:${finding.location?.line}`;
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
  }

  async addRule(rule: Omit<FalsePositiveRule, 'id' | 'addedAt'>): Promise<void> {
    const newRule: FalsePositiveRule = {
      ...rule,
      id: `fp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      addedAt: new Date().toISOString(),
    };
    
    this.rules.push(newRule);
    await this.saveRules();
  }

  async removeRule(ruleId: string): Promise<boolean> {
    const initialLength = this.rules.length;
    this.rules = this.rules.filter(r => r.id !== ruleId);
    
    if (this.rules.length < initialLength) {
      await this.saveRules();
      return true;
    }
    
    return false;
  }

  async addFindingToIgnore(finding: Finding, reason: string): Promise<void> {
    const rule: Omit<FalsePositiveRule, 'id' | 'addedAt'> = {
      findingType: finding.type,
      file: finding.location?.file,
      line: finding.location?.line,
      hash: this.hashFinding(finding),
      reason,
      pattern: finding.title,
    };
    
    await this.addRule(rule);
  }

  getStatistics(results: FilterResult[]): FilterStats {
    const filtered = results.filter(r => r.filtered).length;
    const passed = results.filter(r => !r.filtered).length;
    
    const activeRules = this.rules.filter(r => 
      !r.expires || new Date(r.expires) > new Date()
    );
    
    const expiredRules = this.rules.filter(r => 
      r.expires && new Date(r.expires) <= new Date()
    );
    
    return {
      totalFindings: results.length,
      filtered,
      passed,
      filterRate: results.length > 0 ? (filtered / results.length) * 100 : 0,
      rules: {
        total: this.rules.length,
        active: activeRules.length,
        expired: expiredRules.length,
      },
    };
  }

  async cleanupExpiredRules(): Promise<number> {
    const initialLength = this.rules.length;
    
    this.rules = this.rules.filter(r => 
      !r.expires || new Date(r.expires) > new Date()
    );
    
    const removed = initialLength - this.rules.length;
    
    if (removed > 0) {
      await this.saveRules();
    }
    
    return removed;
  }
}