export interface Task<T> {
  id: string;
  execute: () => Promise<T>;
  timeout?: number;
  retries?: number;
  priority?: number;
}

export interface ExecutionResult<T> {
  id: string;
  status: 'success' | 'error' | 'timeout';
  result?: T;
  error?: Error;
  duration: number;
  attempts: number;
}

export interface ExecutionOptions {
  maxConcurrency?: number;
  defaultTimeout?: number;
  defaultRetries?: number;
  failFast?: boolean;
}

export class ParallelExecutor<T> {
  private maxConcurrency: number;
  private defaultTimeout: number;
  private defaultRetries: number;
  private failFast: boolean;
  private running: Set<string> = new Set();
  private queue: Task<T>[] = [];

  constructor(options: ExecutionOptions = {}) {
    this.maxConcurrency = options.maxConcurrency || 3;
    this.defaultTimeout = options.defaultTimeout || 300000; // 5 minutes
    this.defaultRetries = options.defaultRetries || 1;
    this.failFast = options.failFast || false;
  }

  async execute(tasks: Task<T>[]): Promise<ExecutionResult<T>[]> {
    // Sort tasks by priority (higher priority first)
    const sortedTasks = [...tasks].sort((a, b) => (b.priority || 0) - (a.priority || 0));
    
    this.queue = [...sortedTasks];
    const results: ExecutionResult<T>[] = [];
    const promises: Promise<ExecutionResult<T>>[] = [];

    console.error(`Executing ${tasks.length} tasks with max concurrency: ${this.maxConcurrency}`);

    // Start initial batch of tasks
    while (promises.length < this.maxConcurrency && this.queue.length > 0) {
      const task = this.queue.shift()!;
      const promise = this.executeTask(task);
      promises.push(promise);
    }

    // Process remaining tasks
    while (promises.length > 0) {
      // Wait for at least one task to complete
      const completedResult = await Promise.race(promises);
      results.push(completedResult);

      // Remove completed promise from active promises
      const completedIndex = promises.findIndex(p => 
        p === Promise.resolve(completedResult)
      );
      if (completedIndex !== -1) {
        promises.splice(completedIndex, 1);
      }

      // Check if we should fail fast
      if (this.failFast && completedResult.status === 'error') {
        console.error(`Failing fast due to task error: ${completedResult.id}`);
        
        // Cancel remaining tasks
        await this.cancelRunningTasks();
        
        // Add error results for remaining tasks
        for (const remainingTask of this.queue) {
          results.push({
            id: remainingTask.id,
            status: 'error',
            error: new Error('Cancelled due to fail-fast'),
            duration: 0,
            attempts: 0,
          });
        }
        
        break;
      }

      // Start next task if available
      if (this.queue.length > 0) {
        const nextTask = this.queue.shift()!;
        const promise = this.executeTask(nextTask);
        promises.push(promise);
      }
    }

    // Wait for any remaining promises to complete
    const remainingResults = await Promise.allSettled(promises);
    for (const settledResult of remainingResults) {
      if (settledResult.status === 'fulfilled' && !results.includes(settledResult.value)) {
        results.push(settledResult.value);
      }
    }

    this.logExecutionSummary(results);
    return results;
  }

  private async executeTask(task: Task<T>): Promise<ExecutionResult<T>> {
    const startTime = Date.now();
    let attempts = 0;
    const maxAttempts = (task.retries || this.defaultRetries) + 1;
    const timeout = task.timeout || this.defaultTimeout;

    this.running.add(task.id);
    console.error(`Starting task: ${task.id}`);

    while (attempts < maxAttempts) {
      attempts++;
      
      try {
        // Execute task with timeout
        const result = await this.executeWithTimeout(task.execute, timeout);
        
        this.running.delete(task.id);
        
        const duration = Date.now() - startTime;
        console.error(`✅ Task completed: ${task.id} (${duration}ms)`);
        
        return {
          id: task.id,
          status: 'success',
          result,
          duration,
          attempts,
        };

      } catch (error) {
        console.error(`❌ Task failed (attempt ${attempts}/${maxAttempts}): ${task.id}`, error);
        
        // If this was the last attempt, return error
        if (attempts >= maxAttempts) {
          this.running.delete(task.id);
          
          const duration = Date.now() - startTime;
          const isTimeout = error instanceof Error && error.message.includes('timeout');
          
          return {
            id: task.id,
            status: isTimeout ? 'timeout' : 'error',
            error: error instanceof Error ? error : new Error(String(error)),
            duration,
            attempts,
          };
        }

        // Wait before retry
        const retryDelay = Math.min(1000 * Math.pow(2, attempts - 1), 10000); // Exponential backoff, max 10s
        await this.delay(retryDelay);
      }
    }

    // Should never reach here, but TypeScript requires it
    throw new Error('Unexpected end of executeTask');
  }

  private async executeWithTimeout<R>(
    fn: () => Promise<R>, 
    timeoutMs: number
  ): Promise<R> {
    return new Promise((resolve, reject) => {
      const timeoutHandle = setTimeout(() => {
        reject(new Error(`Task timeout after ${timeoutMs}ms`));
      }, timeoutMs);

      fn()
        .then(result => {
          clearTimeout(timeoutHandle);
          resolve(result);
        })
        .catch(error => {
          clearTimeout(timeoutHandle);
          reject(error);
        });
    });
  }

  private async cancelRunningTasks(): Promise<void> {
    console.error(`Cancelling ${this.running.size} running tasks`);
    
    // In a real implementation, we would send cancel signals to running tasks
    // For now, we just clear the tracking set
    this.running.clear();
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private logExecutionSummary(results: ExecutionResult<T>[]): void {
    const summary = {
      total: results.length,
      successful: results.filter(r => r.status === 'success').length,
      failed: results.filter(r => r.status === 'error').length,
      timedOut: results.filter(r => r.status === 'timeout').length,
      totalDuration: Math.max(...results.map(r => r.duration)),
      averageDuration: results.reduce((sum, r) => sum + r.duration, 0) / results.length,
    };

    console.error('Execution Summary:', {
      ...summary,
      averageDuration: Math.round(summary.averageDuration),
    });
  }

  // Utility method for creating scanner tasks
  static createScannerTask<T>(
    id: string,
    scannerFn: () => Promise<T>,
    options: {
      timeout?: number;
      retries?: number;
      priority?: number;
    } = {}
  ): Task<T> {
    return {
      id,
      execute: scannerFn,
      timeout: options.timeout,
      retries: options.retries,
      priority: options.priority,
    };
  }

  // Utility for batch processing with size limits
  static async executeBatches<T>(
    tasks: Task<T>[],
    batchSize: number,
    options: ExecutionOptions = {}
  ): Promise<ExecutionResult<T>[]> {
    const allResults: ExecutionResult<T>[] = [];
    
    for (let i = 0; i < tasks.length; i += batchSize) {
      const batch = tasks.slice(i, i + batchSize);
      console.error(`Processing batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(tasks.length / batchSize)}`);
      
      const executor = new ParallelExecutor<T>(options);
      const batchResults = await executor.execute(batch);
      allResults.push(...batchResults);
      
      // Check if we should continue (fail-fast behavior)
      if (options.failFast && batchResults.some(r => r.status === 'error')) {
        console.error('Stopping batch processing due to error');
        break;
      }
    }
    
    return allResults;
  }
}

// Type-safe wrapper for scanner-specific parallel execution
export class ScannerExecutor extends ParallelExecutor<{ findings: any[]; tokenUsage: number }> {
  constructor(options: ExecutionOptions = {}) {
    super({
      maxConcurrency: 2, // Conservative default for scanners
      defaultTimeout: 600000, // 10 minutes for scanners
      ...options,
    });
  }

  async executeScanners(
    scanners: Array<{
      id: string;
      scanner: () => Promise<{ findings: any[]; tokenUsage: number }>;
      priority?: number;
      timeout?: number;
    }>
  ): Promise<{
    allFindings: any[];
    totalTokenUsage: number;
    results: ExecutionResult<{ findings: any[]; tokenUsage: number }>[];
  }> {
    const tasks = scanners.map(s => 
      ParallelExecutor.createScannerTask(s.id, s.scanner, {
        priority: s.priority,
        timeout: s.timeout,
      })
    );

    const results = await this.execute(tasks);
    
    // Aggregate results
    const allFindings: any[] = [];
    let totalTokenUsage = 0;

    for (const result of results) {
      if (result.status === 'success' && result.result) {
        allFindings.push(...result.result.findings);
        totalTokenUsage += result.result.tokenUsage;
      }
    }

    return {
      allFindings,
      totalTokenUsage,
      results,
    };
  }
}