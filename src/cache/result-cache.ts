import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import type { ScanResult } from '../types/index.js';

export interface CacheEntry {
  key: string;
  result: ScanResult;
  timestamp: number;
  ttlMs: number;
  projectPath: string;
  scanType: string;
  tools: string[];
  profile?: string;
}

export interface CacheStats {
  totalEntries: number;
  hitRate: number;
  totalHits: number;
  totalMisses: number;
  cacheSize: number; // in bytes
  oldestEntry: number;
  newestEntry: number;
}

export class ResultCache {
  private cacheDir: string;
  private maxEntries: number;
  private defaultTTL: number;
  private stats = {
    hits: 0,
    misses: 0,
  };

  constructor(cacheDir = './scanner_cache', maxEntries = 1000, defaultTTLMs = 3600000) {
    this.cacheDir = path.resolve(cacheDir);
    this.maxEntries = maxEntries;
    this.defaultTTL = defaultTTLMs; // 1 hour default
  }

  async initialize(): Promise<void> {
    try {
      await fs.mkdir(this.cacheDir, { recursive: true });
      
      // Clean up expired entries on startup
      await this.cleanup();
      
      console.error(`Cache initialized at: ${this.cacheDir}`);
    } catch (error) {
      console.error('Failed to initialize cache:', error);
      throw error;
    }
  }

  async get(
    scanType: string,
    targetPath: string,
    tools: string[],
    profile?: string
  ): Promise<ScanResult | null> {
    const key = this.generateKey(scanType, targetPath, tools, profile);
    const entryPath = this.getEntryPath(key);

    try {
      // Check if file exists
      await fs.access(entryPath);
      
      // Read and validate entry
      const content = await fs.readFile(entryPath, 'utf-8');
      const entry: CacheEntry = JSON.parse(content);
      
      // Check if entry is expired
      if (Date.now() - entry.timestamp > entry.ttlMs) {
        // Remove expired entry
        await fs.unlink(entryPath).catch(() => {});
        this.stats.misses++;
        return null;
      }
      
      // Check if project path has changed
      const targetStat = await fs.stat(targetPath).catch(() => null);
      if (targetStat) {
        // If project has been modified after cache entry, invalidate
        if (targetStat.mtimeMs > entry.timestamp) {
          await fs.unlink(entryPath).catch(() => {});
          this.stats.misses++;
          return null;
        }
      }
      
      this.stats.hits++;
      console.error(`Cache HIT: ${key}`);
      return entry.result;
      
    } catch (error) {
      this.stats.misses++;
      return null;
    }
  }

  async set(
    scanType: string,
    targetPath: string,
    tools: string[],
    result: ScanResult,
    profile?: string,
    ttlMs?: number
  ): Promise<void> {
    const key = this.generateKey(scanType, targetPath, tools, profile);
    const entryPath = this.getEntryPath(key);

    const entry: CacheEntry = {
      key,
      result,
      timestamp: Date.now(),
      ttlMs: ttlMs || this.defaultTTL,
      projectPath: targetPath,
      scanType,
      tools: [...tools].sort(), // Sort for consistency
      profile,
    };

    try {
      // Ensure we don't exceed max entries
      await this.enforceMaxEntries();
      
      // Write entry to cache
      await fs.writeFile(entryPath, JSON.stringify(entry, null, 2), 'utf-8');
      
      console.error(`Cache SET: ${key}`);
    } catch (error) {
      console.error(`Failed to cache result: ${error}`);
      // Don't throw - caching failures shouldn't break scanning
    }
  }

  async invalidate(
    scanType?: string,
    targetPath?: string,
    tools?: string[],
    profile?: string
  ): Promise<number> {
    let invalidatedCount = 0;

    try {
      const entries = await fs.readdir(this.cacheDir);
      
      for (const entryFile of entries) {
        if (!entryFile.endsWith('.json')) continue;
        
        const entryPath = path.join(this.cacheDir, entryFile);
        
        try {
          const content = await fs.readFile(entryPath, 'utf-8');
          const entry: CacheEntry = JSON.parse(content);
          
          let shouldInvalidate = false;
          
          // Check criteria for invalidation
          if (!scanType || entry.scanType === scanType) {
            if (!targetPath || entry.projectPath === targetPath) {
              if (!tools || this.arraysEqual(entry.tools, [...tools].sort())) {
                if (!profile || entry.profile === profile) {
                  shouldInvalidate = true;
                }
              }
            }
          }
          
          if (shouldInvalidate) {
            await fs.unlink(entryPath);
            invalidatedCount++;
          }
        } catch (error) {
          // Skip invalid entries
          continue;
        }
      }
      
      console.error(`Invalidated ${invalidatedCount} cache entries`);
    } catch (error) {
      console.error('Failed to invalidate cache:', error);
    }

    return invalidatedCount;
  }

  async cleanup(): Promise<number> {
    let cleanedCount = 0;

    try {
      const entries = await fs.readdir(this.cacheDir);
      const now = Date.now();
      
      for (const entryFile of entries) {
        if (!entryFile.endsWith('.json')) continue;
        
        const entryPath = path.join(this.cacheDir, entryFile);
        
        try {
          const content = await fs.readFile(entryPath, 'utf-8');
          const entry: CacheEntry = JSON.parse(content);
          
          // Check if expired
          if (now - entry.timestamp > entry.ttlMs) {
            await fs.unlink(entryPath);
            cleanedCount++;
          }
        } catch (error) {
          // Remove corrupted entries
          await fs.unlink(entryPath).catch(() => {});
          cleanedCount++;
        }
      }
      
      if (cleanedCount > 0) {
        console.error(`Cleaned up ${cleanedCount} cache entries`);
      }
    } catch (error) {
      console.error('Failed to cleanup cache:', error);
    }

    return cleanedCount;
  }

  async getStats(): Promise<CacheStats> {
    let totalEntries = 0;
    let cacheSize = 0;
    let oldestEntry = Date.now();
    let newestEntry = 0;

    try {
      const entries = await fs.readdir(this.cacheDir);
      
      for (const entryFile of entries) {
        if (!entryFile.endsWith('.json')) continue;
        
        const entryPath = path.join(this.cacheDir, entryFile);
        
        try {
          const stat = await fs.stat(entryPath);
          const content = await fs.readFile(entryPath, 'utf-8');
          const entry: CacheEntry = JSON.parse(content);
          
          totalEntries++;
          cacheSize += stat.size;
          
          if (entry.timestamp < oldestEntry) {
            oldestEntry = entry.timestamp;
          }
          if (entry.timestamp > newestEntry) {
            newestEntry = entry.timestamp;
          }
        } catch (error) {
          // Skip invalid entries
          continue;
        }
      }
    } catch (error) {
      console.error('Failed to get cache stats:', error);
    }

    const totalRequests = this.stats.hits + this.stats.misses;
    const hitRate = totalRequests > 0 ? this.stats.hits / totalRequests : 0;

    return {
      totalEntries,
      hitRate,
      totalHits: this.stats.hits,
      totalMisses: this.stats.misses,
      cacheSize,
      oldestEntry: totalEntries > 0 ? oldestEntry : 0,
      newestEntry: totalEntries > 0 ? newestEntry : 0,
    };
  }

  async clear(): Promise<void> {
    try {
      const entries = await fs.readdir(this.cacheDir);
      
      for (const entryFile of entries) {
        if (entryFile.endsWith('.json')) {
          await fs.unlink(path.join(this.cacheDir, entryFile));
        }
      }
      
      // Reset stats
      this.stats.hits = 0;
      this.stats.misses = 0;
      
      console.error('Cache cleared');
    } catch (error) {
      console.error('Failed to clear cache:', error);
    }
  }

  private generateKey(
    scanType: string,
    targetPath: string,
    tools: string[],
    profile?: string
  ): string {
    // Create a deterministic key based on scan parameters
    const data = {
      scanType,
      targetPath: path.resolve(targetPath),
      tools: [...tools].sort(),
      profile: profile || 'default',
    };
    
    const dataString = JSON.stringify(data);
    return crypto.createHash('sha256').update(dataString).digest('hex');
  }

  private getEntryPath(key: string): string {
    return path.join(this.cacheDir, `${key}.json`);
  }

  private async enforceMaxEntries(): Promise<void> {
    try {
      const entries = await fs.readdir(this.cacheDir);
      const jsonEntries = entries.filter(f => f.endsWith('.json'));
      
      if (jsonEntries.length >= this.maxEntries) {
        // Remove oldest entries to make room
        const entriesToRemove = jsonEntries.length - this.maxEntries + 1;
        
        // Get entry timestamps
        const entryTimes: Array<{ file: string; timestamp: number }> = [];
        
        for (const entryFile of jsonEntries) {
          try {
            const entryPath = path.join(this.cacheDir, entryFile);
            const content = await fs.readFile(entryPath, 'utf-8');
            const entry: CacheEntry = JSON.parse(content);
            entryTimes.push({ file: entryFile, timestamp: entry.timestamp });
          } catch (error) {
            // Mark corrupted entries for removal
            entryTimes.push({ file: entryFile, timestamp: 0 });
          }
        }
        
        // Sort by timestamp (oldest first)
        entryTimes.sort((a, b) => a.timestamp - b.timestamp);
        
        // Remove oldest entries
        for (let i = 0; i < entriesToRemove; i++) {
          const entryPath = path.join(this.cacheDir, entryTimes[i].file);
          await fs.unlink(entryPath).catch(() => {});
        }
        
        console.error(`Removed ${entriesToRemove} old cache entries`);
      }
    } catch (error) {
      console.error('Failed to enforce max entries:', error);
    }
  }

  private arraysEqual<T>(a: T[], b: T[]): boolean {
    return a.length === b.length && a.every((val, index) => val === b[index]);
  }

  // For testing/debugging
  async listEntries(): Promise<CacheEntry[]> {
    const entries: CacheEntry[] = [];

    try {
      const files = await fs.readdir(this.cacheDir);
      
      for (const file of files) {
        if (!file.endsWith('.json')) continue;
        
        try {
          const content = await fs.readFile(path.join(this.cacheDir, file), 'utf-8');
          const entry: CacheEntry = JSON.parse(content);
          entries.push(entry);
        } catch (error) {
          // Skip invalid entries
          continue;
        }
      }
    } catch (error) {
      console.error('Failed to list cache entries:', error);
    }

    return entries.sort((a, b) => b.timestamp - a.timestamp);
  }
}