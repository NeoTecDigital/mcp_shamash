export { ShamashServer } from './core/server.js';
export { BoundaryEnforcer } from './boundaries/enforcer.js';
export { TokenManager } from './utils/token-manager.js';
export { AuditLogger } from './utils/audit-logger.js';
export * from './types/index.js';

// Start server if run directly
if (require.main === module) {
  import('./core/server.js').then(({ ShamashServer }) => {
    const server = new ShamashServer();
    server.start().catch((error) => {
      console.error('Failed to start Shamash server:', error);
      process.exit(1);
    });
  });
}