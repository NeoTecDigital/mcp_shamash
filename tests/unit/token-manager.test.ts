import { TokenManager } from '../../src/utils/token-manager';

describe('TokenManager', () => {
  let tokenManager: TokenManager;

  beforeEach(() => {
    tokenManager = new TokenManager();
  });

  describe('initialization', () => {
    it('should initialize with default budget', () => {
      const status = tokenManager.getBudgetStatus();
      expect(status.maxPerScan).toBe(1000);
      expect(status.maxPerMinute).toBe(5000);
      expect(status.maxPerHour).toBe(50000);
      expect(status.currentUsage.scan).toBe(0);
    });

    it('should allow custom budget configuration', () => {
      const customManager = new TokenManager({
        maxPerScan: 500,
        maxPerMinute: 2000,
      });
      
      const status = customManager.getBudgetStatus();
      expect(status.maxPerScan).toBe(500);
      expect(status.maxPerMinute).toBe(2000);
      expect(status.maxPerHour).toBe(50000); // Should keep default
    });
  });

  describe('hasTokensAvailable', () => {
    it('should return true when under limits', () => {
      expect(tokenManager.hasTokensAvailable()).toBe(true);
    });

    it('should return false when minute limit exceeded', () => {
      // Consume all minute tokens
      tokenManager.consumeTokens(5000);
      expect(tokenManager.hasTokensAvailable()).toBe(false);
    });

    it('should return false when hour limit exceeded', () => {
      // Create manager with low hour limit for testing
      const testManager = new TokenManager({ maxPerHour: 100 });
      testManager.consumeTokens(100);
      expect(testManager.hasTokensAvailable()).toBe(false);
    });
  });

  describe('canConsume', () => {
    it('should allow consumption under scan limit', () => {
      expect(tokenManager.canConsume(500)).toBe(true);
    });

    it('should reject consumption over scan limit', () => {
      expect(tokenManager.canConsume(1500)).toBe(false);
    });

    it('should reject consumption that would exceed minute limit', () => {
      tokenManager.consumeTokens(4000);
      expect(tokenManager.canConsume(1500)).toBe(false); // Would total 5500
    });

    it('should reject consumption that would exceed hour limit', () => {
      const testManager = new TokenManager({ maxPerHour: 1000 });
      testManager.consumeTokens(800);
      expect(testManager.canConsume(300)).toBe(false); // Would total 1100
    });
  });

  describe('consumeTokens', () => {
    it('should consume tokens when allowed', () => {
      const result = tokenManager.consumeTokens(300);
      expect(result).toBe(true);
      
      const status = tokenManager.getBudgetStatus();
      expect(status.currentUsage.scan).toBe(300);
      expect(status.currentUsage.minute).toBe(300);
      expect(status.currentUsage.hour).toBe(300);
    });

    it('should reject consumption when not allowed', () => {
      const result = tokenManager.consumeTokens(1500);
      expect(result).toBe(false);
      
      const status = tokenManager.getBudgetStatus();
      expect(status.currentUsage.scan).toBe(0);
      expect(status.currentUsage.minute).toBe(0);
      expect(status.currentUsage.hour).toBe(0);
    });

    it('should accumulate minute and hour usage', () => {
      tokenManager.consumeTokens(200);
      tokenManager.consumeTokens(300);
      
      const status = tokenManager.getBudgetStatus();
      expect(status.currentUsage.scan).toBe(300); // Last scan only
      expect(status.currentUsage.minute).toBe(500); // Cumulative
      expect(status.currentUsage.hour).toBe(500); // Cumulative
    });
  });

  describe('getRemainingTokens', () => {
    it('should return scan limit when no consumption', () => {
      expect(tokenManager.getRemainingTokens()).toBe(1000);
    });

    it('should return lowest remaining limit', () => {
      tokenManager.consumeTokens(300);
      
      // Should return scan limit (1000) as it's lowest
      expect(tokenManager.getRemainingTokens()).toBe(1000);
      
      // Consume more to make minute limit the constraint
      tokenManager.consumeTokens(800);
      const remaining = tokenManager.getRemainingTokens();
      expect(remaining).toBe(1000); // Still scan limit
    });

    it('should return minute remaining when it is the constraint', () => {
      const testManager = new TokenManager({ maxPerScan: 2000 });
      testManager.consumeTokens(4000);
      
      expect(testManager.getRemainingTokens()).toBe(1000); // 5000 - 4000
    });
  });

  describe('time-based resets', () => {
    beforeEach(() => {
      // Mock Date.now for consistent testing
      jest.useFakeTimers();
      jest.setSystemTime(new Date('2023-01-01T12:00:00Z'));
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it('should reset minute counter after 60 seconds', () => {
      tokenManager.consumeTokens(1000);
      let status = tokenManager.getBudgetStatus();
      expect(status.currentUsage.minute).toBe(1000);
      
      // Advance time by 61 seconds
      jest.advanceTimersByTime(61000);
      
      status = tokenManager.getBudgetStatus();
      expect(status.currentUsage.minute).toBe(0);
      expect(status.currentUsage.hour).toBe(1000); // Hour counter preserved
    });

    it('should reset hour counter after 3600 seconds', () => {
      tokenManager.consumeTokens(1000);
      let status = tokenManager.getBudgetStatus();
      expect(status.currentUsage.hour).toBe(1000);
      
      // Advance time by 3601 seconds
      jest.advanceTimersByTime(3601000);
      
      status = tokenManager.getBudgetStatus();
      expect(status.currentUsage.minute).toBe(0);
      expect(status.currentUsage.hour).toBe(0);
    });

    it('should handle multiple resets correctly', () => {
      // Initial consumption
      tokenManager.consumeTokens(500);
      
      // Advance 30 seconds and consume more
      jest.advanceTimersByTime(30000);
      tokenManager.consumeTokens(300);
      
      let status = tokenManager.getBudgetStatus();
      expect(status.currentUsage.minute).toBe(800);
      
      // Advance past minute mark
      jest.advanceTimersByTime(35000);
      status = tokenManager.getBudgetStatus();
      expect(status.currentUsage.minute).toBe(0);
      expect(status.currentUsage.hour).toBe(800);
    });
  });
});