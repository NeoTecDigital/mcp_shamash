import * as fs from 'fs/promises';
import * as path from 'path';
import type { AuditEntry } from '../types/index.js';

export class AuditLogger {
  private auditPath: string;
  private sessions: Map<string, Partial<AuditEntry>> = new Map();

  constructor(auditPath = './audit.log') {
    this.auditPath = path.resolve(auditPath);
  }

  async startOperation(operationType: string, args: any): Promise<string> {
    const sessionId = this.generateSessionId();
    const session: Partial<AuditEntry> = {
      timestamp: new Date().toISOString(),
      operation: {
        type: operationType,
        target: args.target || args.path || 'unknown',
      },
      boundaries: {
        validated: false,
      },
      sessionId,
    };

    this.sessions.set(sessionId, session);
    return sessionId;
  }

  async completeOperation(sessionId: string, result: any): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session ${sessionId} not found`);
    }

    session.boundaries!.validated = true;
    session.results = {
      findings: result.summary?.vulnerabilities || 0,
      tokensUsed: result.tokenUsage || 0,
    };

    const auditEntry: AuditEntry = session as AuditEntry;
    await this.writeAuditEntry(auditEntry);

    this.sessions.delete(sessionId);
  }

  async failOperation(sessionId: string, error: any): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session ${sessionId} not found`);
    }

    session.boundaries!.violations = [
      error instanceof Error ? error.message : 'Unknown error',
    ];

    const auditEntry: AuditEntry = session as AuditEntry;
    await this.writeAuditEntry(auditEntry);

    this.sessions.delete(sessionId);
  }

  async logViolation(
    type: string,
    target: string,
    _details?: any
  ): Promise<void> {
    const auditEntry: AuditEntry = {
      timestamp: new Date().toISOString(),
      operation: {
        type: 'BOUNDARY_VIOLATION',
        target,
      },
      boundaries: {
        validated: false,
        violations: [type],
      },
      sessionId: this.generateSessionId(),
    };

    await this.writeAuditEntry(auditEntry);
  }

  private async writeAuditEntry(entry: AuditEntry): Promise<void> {
    const logLine = JSON.stringify(entry) + '\n';
    
    try {
      // Ensure audit directory exists
      await fs.mkdir(path.dirname(this.auditPath), { recursive: true });
      
      // Append to audit log
      await fs.appendFile(this.auditPath, logLine, 'utf-8');
      
      // Also log to stderr for monitoring
      console.error('AUDIT:', JSON.stringify(entry, null, 2));
    } catch (error) {
      console.error('Failed to write audit log:', error);
      // Don't throw - audit failure shouldn't stop operations
    }
  }

  private generateSessionId(): string {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  async getAuditEntries(
    startDate?: Date,
    endDate?: Date
  ): Promise<AuditEntry[]> {
    try {
      const content = await fs.readFile(this.auditPath, 'utf-8');
      const lines = content.trim().split('\n').filter(Boolean);
      
      const entries = lines.map(line => JSON.parse(line) as AuditEntry);
      
      if (startDate || endDate) {
        return entries.filter(entry => {
          const entryDate = new Date(entry.timestamp);
          if (startDate && entryDate < startDate) return false;
          if (endDate && entryDate > endDate) return false;
          return true;
        });
      }
      
      return entries;
    } catch (error) {
      if ((error as any).code === 'ENOENT') {
        return []; // Audit file doesn't exist yet
      }
      throw error;
    }
  }
}