import type { TokenBudget } from '../types/index.js';

export class TokenManager {
  private budget: TokenBudget = {
    maxPerScan: 1000,
    maxPerMinute: 5000,
    maxPerHour: 50000,
    currentUsage: {
      scan: 0,
      minute: 0,
      hour: 0,
    },
  };

  private minuteReset: number = Date.now() + 60000; // Next minute
  private hourReset: number = Date.now() + 3600000; // Next hour

  constructor(customBudget?: Partial<TokenBudget>) {
    if (customBudget) {
      this.budget = { ...this.budget, ...customBudget };
    }
  }

  hasTokensAvailable(): boolean {
    this.resetCountersIfNeeded();
    return (
      this.budget.currentUsage.minute < this.budget.maxPerMinute &&
      this.budget.currentUsage.hour < this.budget.maxPerHour
    );
  }

  canConsume(tokens: number): boolean {
    this.resetCountersIfNeeded();
    return (
      tokens <= this.budget.maxPerScan &&
      this.budget.currentUsage.minute + tokens <= this.budget.maxPerMinute &&
      this.budget.currentUsage.hour + tokens <= this.budget.maxPerHour
    );
  }

  consumeTokens(tokens: number): boolean {
    if (!this.canConsume(tokens)) {
      return false;
    }

    this.budget.currentUsage.scan = tokens;
    this.budget.currentUsage.minute += tokens;
    this.budget.currentUsage.hour += tokens;

    return true;
  }

  getRemainingTokens(): number {
    this.resetCountersIfNeeded();
    return Math.min(
      this.budget.maxPerScan,
      this.budget.maxPerMinute - this.budget.currentUsage.minute,
      this.budget.maxPerHour - this.budget.currentUsage.hour
    );
  }

  getBudgetStatus(): TokenBudget {
    this.resetCountersIfNeeded();
    return { ...this.budget };
  }

  private resetCountersIfNeeded(): void {
    const now = Date.now();

    if (now >= this.minuteReset) {
      this.budget.currentUsage.minute = 0;
      this.minuteReset = now + 60000;
    }

    if (now >= this.hourReset) {
      this.budget.currentUsage.hour = 0;
      this.hourReset = now + 3600000;
    }
  }
}