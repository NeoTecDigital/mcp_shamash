import { BoundaryEnforcer } from '../../src/boundaries/enforcer';
import * as fs from 'fs/promises';
// import * as path from 'path';

// Mock fs module
jest.mock('fs/promises');
const mockedFs = fs as jest.Mocked<typeof fs>;

describe('BoundaryEnforcer', () => {
  let enforcer: BoundaryEnforcer;
  const testProjectRoot = '/test/project';

  beforeEach(async () => {
    enforcer = new BoundaryEnforcer();
    
    // Mock current working directory
    jest.spyOn(process, 'cwd').mockReturnValue(testProjectRoot);
    
    // Mock fs operations
    mockedFs.readFile.mockImplementation(((filePath: string) => {
      if (filePath.includes('docker-compose.yml')) {
        return Promise.resolve(`
version: '3.8'
services:
  web:
    image: nginx
    ports:
      - "80:80"
  db:
    image: postgres
    environment:
      POSTGRES_DB: testdb
networks:
  default:
    driver: bridge
`);
      }
      if (filePath.includes('package.json')) {
        return Promise.resolve('{"name": "test-project", "version": "1.0.0"}');
      }
      return Promise.reject(new Error('ENOENT'));
    }) as any);

    mockedFs.stat.mockImplementation(() => 
      Promise.reject(new Error('ENOENT'))
    );

    mockedFs.access.mockImplementation(() => Promise.resolve());
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('initialize', () => {
    it('should initialize with project scope', async () => {
      await enforcer.initialize();
      const scope = enforcer.getProjectScope();
      
      expect(scope).toBeDefined();
      expect(scope!.projectRoot).toBe(testProjectRoot);
      expect(scope!.allowedPaths).toContain(`${testProjectRoot}/**/*`);
    });

    it('should discover Docker Compose networks', async () => {
      await enforcer.initialize();
      const scope = enforcer.getProjectScope();
      
      expect(scope!.networks).toHaveLength(1);
      expect(scope!.networks[0].name).toBe('mcp_shamash_default');
      expect(scope!.networks[0].type).toBe('docker');
    });

    it('should discover Docker Compose services', async () => {
      await enforcer.initialize();
      const scope = enforcer.getProjectScope();
      
      expect(scope!.services).toHaveLength(2);
      expect(scope!.services[0].name).toBe('web');
      expect(scope!.services[0].ports).toContain(80);
    });
  });

  describe('validatePath', () => {
    beforeEach(async () => {
      await enforcer.initialize();
    });

    it('should allow paths within project root', async () => {
      const result = await enforcer.validatePath(`${testProjectRoot}/src/index.ts`);
      expect(result.allowed).toBe(true);
    });

    it('should reject paths outside project root', async () => {
      const result = await enforcer.validatePath('/etc/passwd');
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('outside project root');
      expect(result.violations).toContain('PATH_ESCAPE');
    });

    it('should reject system paths', async () => {
      const result = await enforcer.validatePath('/usr/bin/sh');
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('denied system directory');
      expect(result.violations).toContain('SYSTEM_PATH_ACCESS');
    });

    it('should handle relative paths', async () => {
      const result = await enforcer.validatePath('src/index.ts');
      expect(result.allowed).toBe(true);
    });

    it('should reject path traversal attempts', async () => {
      const result = await enforcer.validatePath(`${testProjectRoot}/../../../etc/passwd`);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain('PATH_ESCAPE');
    });
  });

  describe('validateNetwork', () => {
    beforeEach(async () => {
      await enforcer.initialize();
    });

    it('should allow localhost', async () => {
      const result = await enforcer.validateNetwork('127.0.0.1');
      expect(result.allowed).toBe(true);
      expect(result.scope?.type).toBe('local');
    });

    it('should reject blocked networks', async () => {
      const result = await enforcer.validateNetwork('10.0.0.1');
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('blocked range');
      expect(result.violations).toContain('BLOCKED_NETWORK');
    });

    it('should reject hostnames', async () => {
      const result = await enforcer.validateNetwork('google.com');
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Hostname resolution not allowed');
      expect(result.violations).toContain('HOSTNAME_NOT_ALLOWED');
    });

    it('should validate CIDR notation', async () => {
      const result = await enforcer.validateNetwork('192.168.1.0/24');
      expect(result.allowed).toBe(false); // Not in project networks
    });

    it('should handle invalid IP addresses', async () => {
      const result = await enforcer.validateNetwork('999.999.999.999');
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain('VALIDATION_ERROR');
    });
  });

  describe('validateUrl', () => {
    beforeEach(async () => {
      await enforcer.initialize();
    });

    it('should allow localhost URLs', async () => {
      const result = await enforcer.validateUrl('http://127.0.0.1:3000');
      expect(result.allowed).toBe(true);
    });

    it('should reject blocked ports', async () => {
      const result = await enforcer.validateUrl('http://127.0.0.1:22');
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Port 22 is blocked');
      expect(result.violations).toContain('BLOCKED_PORT');
    });

    it('should reject external URLs', async () => {
      const result = await enforcer.validateUrl('https://google.com');
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain('HOSTNAME_NOT_ALLOWED');
    });

    it('should handle HTTPS default port', async () => {
      const result = await enforcer.validateUrl('https://127.0.0.1');
      expect(result.allowed).toBe(true); // Port 443 should be allowed
    });

    it('should handle invalid URLs', async () => {
      const result = await enforcer.validateUrl('not-a-url');
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain('INVALID_URL');
    });
  });

  describe('validatePort', () => {
    it('should allow standard ports', async () => {
      const result = await enforcer.validatePort(8080);
      expect(result.allowed).toBe(true);
    });

    it('should reject blocked management ports', async () => {
      const result = await enforcer.validatePort(22);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('blocked for security');
      expect(result.violations).toContain('BLOCKED_PORT');
    });

    it('should reject invalid port ranges', async () => {
      let result = await enforcer.validatePort(0);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain('INVALID_PORT');

      result = await enforcer.validatePort(65536);
      expect(result.allowed).toBe(false);
      expect(result.violations).toContain('INVALID_PORT');
    });
  });
});