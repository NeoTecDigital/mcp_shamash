import type { Finding } from '../types/index.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';

export interface CustomRule {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  category: 'security' | 'performance' | 'maintainability' | 'style';
  pattern: string;
  filePatterns?: string[];
  excludePatterns?: string[];
  messageTemplate: string;
  remediation?: string;
  references?: string[];
  enabled: boolean;
  createdBy?: string;
  createdAt: string;
  lastModified: string;
}

export interface RuleMatch {
  rule: CustomRule;
  file: string;
  line: number;
  column?: number;
  matchedText: string;
  context?: string;
}

export interface RuleEngineStats {
  totalRules: number;
  enabledRules: number;
  disabledRules: number;
  categoryCounts: Record<string, number>;
  severityCounts: Record<string, number>;
}

export class CustomRuleEngine {
  private rules: Map<string, CustomRule>;
  private rulesFilePath: string;

  constructor(projectRoot: string) {
    this.rules = new Map();
    this.rulesFilePath = path.join(projectRoot, '.shamash', 'custom-rules.json');
  }

  async loadRules(): Promise<void> {
    try {
      const content = await fs.readFile(this.rulesFilePath, 'utf-8');
      const rulesData = JSON.parse(content);
      
      this.rules.clear();
      if (rulesData.rules && Array.isArray(rulesData.rules)) {
        for (const rule of rulesData.rules) {
          this.rules.set(rule.id, rule);
        }
      }
      
      console.error(`Loaded ${this.rules.size} custom security rules`);
    } catch (error) {
      // File doesn't exist or is invalid, start with default rules
      await this.initializeDefaultRules();
    }
  }

  private async initializeDefaultRules(): Promise<void> {
    const defaultRules: CustomRule[] = [
      {
        id: 'hardcoded-api-key',
        name: 'Hardcoded API Key',
        description: 'Detects hardcoded API keys in source code',
        severity: 'high',
        category: 'security',
        pattern: '(api[_-]?key|apikey)\\s*[=:]\\s*["\'][a-zA-Z0-9]{20,}["\']',
        filePatterns: ['*.js', '*.ts', '*.py', '*.java', '*.go'],
        excludePatterns: ['test/**', 'tests/**', '**/*.test.*', '**/*.spec.*'],
        messageTemplate: 'Hardcoded API key detected: {matchedText}',
        remediation: 'Move API keys to environment variables or a secure configuration service',
        references: [
          'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
        ],
        enabled: true,
        createdAt: new Date().toISOString(),
        lastModified: new Date().toISOString(),
      },
      {
        id: 'weak-password-hash',
        name: 'Weak Password Hashing',
        description: 'Detects use of weak password hashing algorithms',
        severity: 'high',
        category: 'security',
        pattern: '(md5|sha1)\\s*\\(',
        filePatterns: ['*.js', '*.ts', '*.py', '*.java', '*.php'],
        messageTemplate: 'Weak password hashing algorithm detected: {matchedText}',
        remediation: 'Use bcrypt, scrypt, or Argon2 for password hashing',
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html',
        ],
        enabled: true,
        createdAt: new Date().toISOString(),
        lastModified: new Date().toISOString(),
      },
      {
        id: 'console-log-production',
        name: 'Console Log in Production',
        description: 'Detects console.log statements that should not be in production',
        severity: 'low',
        category: 'maintainability',
        pattern: 'console\\.(log|debug|info)\\s*\\(',
        filePatterns: ['*.js', '*.ts'],
        excludePatterns: ['test/**', 'tests/**', 'dev/**'],
        messageTemplate: 'Console statement detected: {matchedText}',
        remediation: 'Use proper logging library or remove console statements from production code',
        enabled: true,
        createdAt: new Date().toISOString(),
        lastModified: new Date().toISOString(),
      },
      {
        id: 'sql-injection-risk',
        name: 'SQL Injection Risk',
        description: 'Detects potential SQL injection vulnerabilities',
        severity: 'critical',
        category: 'security',
        pattern: '(query|execute)\\s*\\(\\s*["\'][^"\']*\\+',
        filePatterns: ['*.js', '*.ts', '*.py', '*.java', '*.php'],
        messageTemplate: 'Potential SQL injection vulnerability: {matchedText}',
        remediation: 'Use parameterized queries or prepared statements',
        references: [
          'https://owasp.org/www-community/attacks/SQL_Injection',
        ],
        enabled: true,
        createdAt: new Date().toISOString(),
        lastModified: new Date().toISOString(),
      },
      {
        id: 'insecure-random',
        name: 'Insecure Random Number Generation',
        description: 'Detects use of insecure random number generators',
        severity: 'medium',
        category: 'security',
        pattern: '(Math\\.random|random\\.randint|rand\\()',
        filePatterns: ['*.js', '*.ts', '*.py', '*.java'],
        messageTemplate: 'Insecure random number generation: {matchedText}',
        remediation: 'Use cryptographically secure random number generators',
        enabled: true,
        createdAt: new Date().toISOString(),
        lastModified: new Date().toISOString(),
      },
    ];

    for (const rule of defaultRules) {
      this.rules.set(rule.id, rule);
    }

    await this.saveRules();
    console.error(`Initialized ${defaultRules.length} default custom rules`);
  }

  async saveRules(): Promise<void> {
    try {
      const rulesDir = path.dirname(this.rulesFilePath);
      await fs.mkdir(rulesDir, { recursive: true });

      const rulesData = {
        version: '1.0',
        lastUpdated: new Date().toISOString(),
        rules: Array.from(this.rules.values()),
      };

      await fs.writeFile(this.rulesFilePath, JSON.stringify(rulesData, null, 2), 'utf-8');
    } catch (error) {
      console.error('Failed to save custom rules:', error);
      throw error;
    }
  }

  async scanWithCustomRules(targetPath: string): Promise<{ findings: Finding[]; tokenUsage: number }> {
    const findings: Finding[] = [];
    const enabledRules = Array.from(this.rules.values()).filter(r => r.enabled);

    if (enabledRules.length === 0) {
      return { findings, tokenUsage: 0 };
    }

    console.error(`Running custom rule scan with ${enabledRules.length} rules`);

    try {
      // Get all files in the target path
      const files = await this.getTargetFiles(targetPath);
      
      // Scan each file with all rules
      for (const file of files) {
        const matches = await this.scanFile(file, enabledRules);
        
        for (const match of matches) {
          findings.push(this.convertMatchToFinding(match));
        }
      }
    } catch (error) {
      console.error('Custom rule scan failed:', error);
    }

    return {
      findings,
      tokenUsage: Math.min(findings.length * 8 + 30, 200), // Minimal token usage for custom rules
    };
  }

  private async getTargetFiles(targetPath: string): Promise<string[]> {
    const files: string[] = [];
    
    try {
      const entries = await fs.readdir(targetPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(targetPath, entry.name);
        
        // Skip common ignore patterns
        if (this.shouldSkipPath(entry.name)) {
          continue;
        }
        
        if (entry.isDirectory()) {
          const subFiles = await this.getTargetFiles(fullPath);
          files.push(...subFiles);
        } else if (entry.isFile()) {
          files.push(fullPath);
        }
      }
    } catch (error) {
      console.error(`Failed to read directory ${targetPath}:`, error);
    }
    
    return files;
  }

  private shouldSkipPath(name: string): boolean {
    const skipPatterns = [
      'node_modules', '.git', 'dist', 'build', 'target', 'coverage',
      '__pycache__', '.pytest_cache', '.nyc_output', 'vendor',
      '.venv', 'venv', '.env'
    ];
    
    return skipPatterns.some(pattern => name.includes(pattern));
  }

  private async scanFile(filePath: string, rules: CustomRule[]): Promise<RuleMatch[]> {
    const matches: RuleMatch[] = [];
    
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const lines = content.split('\n');
      
      for (const rule of rules) {
        // Check if file matches rule patterns
        if (!this.fileMatchesRule(filePath, rule)) {
          continue;
        }
        
        // Apply rule to file content
        const ruleMatches = this.applyRuleToContent(rule, content, lines, filePath);
        matches.push(...ruleMatches);
      }
    } catch (error) {
      // Skip files that can't be read (binary, permission issues, etc.)
    }
    
    return matches;
  }

  private fileMatchesRule(filePath: string, rule: CustomRule): boolean {
    const fileName = path.basename(filePath);
    const relativePath = filePath;
    
    // Check file patterns
    if (rule.filePatterns && rule.filePatterns.length > 0) {
      const matchesPattern = rule.filePatterns.some(pattern => {
        const regex = new RegExp(pattern.replace(/\*/g, '.*').replace(/\?/g, '.'));
        return regex.test(fileName);
      });
      
      if (!matchesPattern) {
        return false;
      }
    }
    
    // Check exclude patterns
    if (rule.excludePatterns && rule.excludePatterns.length > 0) {
      const matchesExclude = rule.excludePatterns.some(pattern => {
        const regex = new RegExp(pattern.replace(/\*/g, '.*').replace(/\?/g, '.'));
        return regex.test(relativePath);
      });
      
      if (matchesExclude) {
        return false;
      }
    }
    
    return true;
  }

  private applyRuleToContent(rule: CustomRule, content: string, lines: string[], filePath: string): RuleMatch[] {
    const matches: RuleMatch[] = [];
    
    try {
      // Check for ReDoS patterns before executing
      if (!this.isPatternSafe(rule.pattern)) {
        console.error(`Potentially dangerous ReDoS pattern detected in rule ${rule.id}: ${rule.pattern}`);
        return matches;
      }

      const regex = new RegExp(rule.pattern, 'gi');
      let match;
      const startTime = Date.now();
      const timeout = 5000; // 5 second timeout
      let iterationCount = 0;
      const maxIterations = 10000; // Prevent infinite loops
      
      while ((match = regex.exec(content)) !== null) {
        // Timeout protection
        if (Date.now() - startTime > timeout) {
          console.error(`Regex timeout for rule ${rule.id}: Pattern took longer than ${timeout}ms`);
          break;
        }

        // Iteration limit protection
        if (++iterationCount > maxIterations) {
          console.error(`Regex iteration limit exceeded for rule ${rule.id}: More than ${maxIterations} matches`);
          break;
        }

        // Prevent infinite loops with global flag
        if (match.index === regex.lastIndex) {
          regex.lastIndex++;
        }

        // Find line number
        const beforeMatch = content.substring(0, match.index);
        const lineNumber = beforeMatch.split('\n').length;
        const line = lines[lineNumber - 1];
        const column = match.index - beforeMatch.lastIndexOf('\n') - 1;
        
        matches.push({
          rule,
          file: filePath,
          line: lineNumber,
          column: Math.max(0, column),
          matchedText: match[0],
          context: line?.trim(),
        });
      }
    } catch (error) {
      console.error(`Failed to apply rule ${rule.id}:`, error);
    }
    
    return matches;
  }

  private isPatternSafe(pattern: string): boolean {
    // Detect common ReDoS patterns that can cause exponential backtracking
    const dangerousPatterns = [
      /\([^)]*\+[^)]*\)\+/,           // (a+)+ - nested quantifiers
      /\([^)]*\*[^)]*\)\+/,           // (a*)+ - nested quantifiers  
      /\([^)]*\+[^)]*\)\*/,           // (a+)* - nested quantifiers
      /\([^)]*\|[^)]*\)\+/,           // (a|b)+ - alternation with quantifier (but not simple alternation)
      /\([^)]*\+[^)]*\)\{2,\}/,       // (a+){2,} - nested quantifier ranges
      /\.\*\.\*\.\*/,                  // .*.*.*  - triple wildcards pattern
      /\+\.\+\+/,                     // +.+ with additional + - triple plus quantifiers
    ];
    
    // Check pattern length - very long patterns can be suspicious
    if (pattern.length > 1000) {
      return false;
    }

    // Check for nested quantifiers and other ReDoS patterns
    for (const dangerousPattern of dangerousPatterns) {
      if (dangerousPattern.test(pattern)) {
        return false;
      }
    }

    // Additional complexity checks - be more lenient
    const quantifierCount = (pattern.match(/[+*?{]/g) || []).length;
    const groupCount = (pattern.match(/\(/g) || []).length;
    
    // Too many quantifiers or groups can indicate complexity - increased limits
    if (quantifierCount > 15 || groupCount > 8) {
      return false;
    }
    
    // Check for specific dangerous nested quantifier combinations
    // Look for patterns like (.*)+, (.*)*, (+.*)+, etc.
    const reallyDangerousPatterns = [
      /\(\.\*\)\+/,                   // (.*)+ 
      /\(\.\*\)\*/,                   // (.*)* 
      /\(\.\+\)\+/,                   // (.+)+
      /\(\.\+\)\*/,                   // (.+)*
    ];
    
    for (const dangerousPattern of reallyDangerousPatterns) {
      if (dangerousPattern.test(pattern)) {
        return false;
      }
    }
    
    return true;
  }

  private convertMatchToFinding(match: RuleMatch): Finding {
    const messageWithContext = match.rule.messageTemplate.replace(
      '{matchedText}',
      match.matchedText
    );
    
    return {
      id: `custom_${match.rule.id}_${this.hashMatch(match)}`,
      type: 'custom',
      severity: match.rule.severity,
      title: `${match.rule.name}: ${messageWithContext}`,
      description: match.rule.description,
      location: {
        file: match.file,
        line: match.line,
        column: match.column,
      },
      remediation: match.rule.remediation,
    };
  }

  private hashMatch(match: RuleMatch): string {
    const data = `${match.rule.id}:${match.file}:${match.line}:${match.matchedText}`;
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 8);
  }

  async addRule(rule: Omit<CustomRule, 'id' | 'createdAt' | 'lastModified'>): Promise<string> {
    const id = `custom_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const timestamp = new Date().toISOString();
    
    const newRule: CustomRule = {
      ...rule,
      id,
      createdAt: timestamp,
      lastModified: timestamp,
    };
    
    this.rules.set(id, newRule);
    await this.saveRules();
    
    return id;
  }

  async updateRule(id: string, updates: Partial<Omit<CustomRule, 'id' | 'createdAt'>>): Promise<boolean> {
    const existingRule = this.rules.get(id);
    if (!existingRule) {
      return false;
    }
    
    const updatedRule: CustomRule = {
      ...existingRule,
      ...updates,
      lastModified: new Date().toISOString(),
    };
    
    this.rules.set(id, updatedRule);
    await this.saveRules();
    
    return true;
  }

  async removeRule(id: string): Promise<boolean> {
    const deleted = this.rules.delete(id);
    if (deleted) {
      await this.saveRules();
    }
    return deleted;
  }

  async enableRule(id: string): Promise<boolean> {
    return await this.updateRule(id, { enabled: true });
  }

  async disableRule(id: string): Promise<boolean> {
    return await this.updateRule(id, { enabled: false });
  }

  getRules(): CustomRule[] {
    return Array.from(this.rules.values());
  }

  getRule(id: string): CustomRule | undefined {
    return this.rules.get(id);
  }

  getStats(): RuleEngineStats {
    const rules = Array.from(this.rules.values());
    const enabled = rules.filter(r => r.enabled);
    
    const categoryCounts: Record<string, number> = {};
    const severityCounts: Record<string, number> = {};
    
    for (const rule of rules) {
      categoryCounts[rule.category] = (categoryCounts[rule.category] || 0) + 1;
      severityCounts[rule.severity] = (severityCounts[rule.severity] || 0) + 1;
    }
    
    return {
      totalRules: rules.length,
      enabledRules: enabled.length,
      disabledRules: rules.length - enabled.length,
      categoryCounts,
      severityCounts,
    };
  }

  async validateRule(rule: Partial<CustomRule>): Promise<{ valid: boolean; errors: string[] }> {
    const errors: string[] = [];
    
    if (!rule.name || rule.name.trim().length === 0) {
      errors.push('Rule name is required');
    }
    
    if (!rule.pattern || rule.pattern.trim().length === 0) {
      errors.push('Rule pattern is required');
    } else {
      try {
        new RegExp(rule.pattern);
      } catch {
        errors.push('Invalid regex pattern');
      }
      
      // Check for ReDoS patterns
      if (!this.isPatternSafe(rule.pattern)) {
        errors.push('Potentially dangerous ReDoS pattern detected - pattern may cause performance issues');
      }
    }
    
    if (!rule.messageTemplate || rule.messageTemplate.trim().length === 0) {
      errors.push('Message template is required');
    }
    
    if (!['critical', 'high', 'medium', 'low', 'informational'].includes(rule.severity as string)) {
      errors.push('Invalid severity level');
    }
    
    if (!['security', 'performance', 'maintainability', 'style'].includes(rule.category as string)) {
      errors.push('Invalid category');
    }
    
    return {
      valid: errors.length === 0,
      errors,
    };
  }
}