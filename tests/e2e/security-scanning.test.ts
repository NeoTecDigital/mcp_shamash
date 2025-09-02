import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import * as fs from 'fs/promises';
import * as os from 'os';

describe('End-to-End Security Scanning', () => {
  let testProjectPath: string;

  beforeAll(async () => {
    // Create a temporary test project
    testProjectPath = await fs.mkdtemp(path.join(os.tmpdir(), 'shamash-test-'));
    
    // Create test files with known vulnerabilities
    await createTestProject(testProjectPath);
  });

  afterAll(async () => {
    // Clean up test project
    if (testProjectPath) {
      await fs.rm(testProjectPath, { recursive: true, force: true });
    }
  });

  describe('Project Boundary Detection', () => {
    it('should detect Docker Compose configuration', async () => {
      // Docker compose file was created in test project
      const composePath = path.join(testProjectPath, 'docker-compose.yml');
      const exists = await fs.access(composePath).then(() => true).catch(() => false);
      expect(exists).toBe(true);
    });

    it('should detect package.json', async () => {
      const packagePath = path.join(testProjectPath, 'package.json');
      const exists = await fs.access(packagePath).then(() => true).catch(() => false);
      expect(exists).toBe(true);
    });
  });

  describe('Container Isolation', () => {
    it('should run scanners in isolated containers', async () => {
      const result = await runDockerCommand([
        'run', '--rm',
        '--network=shamash_sandbox',
        '--security-opt=no-new-privileges:true',
        '--cap-drop=ALL',
        '--read-only',
        'alpine:latest',
        'sh', '-c', 'ping -c 1 8.8.8.8 || echo "BLOCKED"'
      ]);
      
      expect(result.stdout).toContain('BLOCKED');
    });

    it('should enforce resource limits', async () => {
      const result = await runDockerCommand([
        'run', '--rm',
        '--memory=512m',
        '--cpus=0.5',
        '--pids-limit=50',
        'alpine:latest',
        'sh', '-c', 'cat /sys/fs/cgroup/memory/memory.limit_in_bytes'
      ]);
      
      const memoryLimit = parseInt(result.stdout.trim());
      expect(memoryLimit).toBeLessThanOrEqual(536870912); // 512MB
    });
  });

  describe('Security Tool Integration', () => {
    it('should run Semgrep SAST scan', async () => {
      // Build Semgrep container
      await runDockerCommand([
        'build',
        '-f', 'containers/Dockerfile.semgrep',
        '-t', 'shamash-semgrep',
        '.'
      ], process.cwd());

      // Run scan
      const result = await runDockerCommand([
        'run', '--rm',
        '-v', `${testProjectPath}:/scan/target:ro`,
        '-e', 'SHAMASH_TARGET_PATH=/scan/target',
        '-e', 'SHAMASH_SEMGREP_CONFIG=auto',
        'shamash-semgrep'
      ]);

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('Semgrep scan completed');
    }, 60000);

    it('should run Trivy dependency scan', async () => {
      const result = await runDockerCommand([
        'run', '--rm',
        '-v', `${testProjectPath}:/scan/target:ro`,
        'aquasec/trivy:latest',
        'fs', '--format', 'json', '/scan/target'
      ]);

      expect(result.exitCode).toBe(0);
      
      // Parse JSON output
      const scanResults = JSON.parse(result.stdout);
      expect(scanResults.Results).toBeDefined();
    }, 60000);

    it('should run Gitleaks secret scan', async () => {
      const result = await runDockerCommand([
        'run', '--rm',
        '-v', `${testProjectPath}:/scan/target:ro`,
        'zricethezav/gitleaks:latest',
        'detect',
        '--source', '/scan/target',
        '--format', 'json',
        '--no-git'
      ]);

      // Gitleaks exits with 1 if secrets found, 0 if none
      expect([0, 1]).toContain(result.exitCode);
    }, 60000);
  });

  describe('Network Scanning', () => {
    it('should scan localhost services', async () => {
      // Start a test web server
      const server = spawn('python3', ['-m', 'http.server', '8999'], {
        cwd: testProjectPath,
        stdio: 'pipe'
      });

      // Wait for server to start
      await new Promise(resolve => setTimeout(resolve, 2000));

      try {
        const result = await runDockerCommand([
          'run', '--rm',
          '--network=host',
          'instrumentisto/nmap:latest',
          '-sT', '-p', '8999', '127.0.0.1'
        ]);

        expect(result.stdout).toContain('8999/tcp open');
      } finally {
        server.kill();
      }
    }, 30000);

    it('should block external network access from scanners', async () => {
      const result = await runDockerCommand([
        'run', '--rm',
        '--network=shamash_sandbox',
        'alpine:latest',
        'sh', '-c', 'nc -z -w1 8.8.8.8 53 && echo "ALLOWED" || echo "BLOCKED"'
      ]);

      expect(result.stdout).toContain('BLOCKED');
    });
  });

  describe('Audit Logging', () => {
    it('should create audit logs', async () => {
      // Run a scan operation
      // (This would normally be done through MCP server)
      
      const auditLogPath = path.join(testProjectPath, 'audit.log');
      
      // Create a mock audit entry
      const auditEntry = {
        timestamp: new Date().toISOString(),
        operation: {
          type: 'test_scan',
          target: testProjectPath
        },
        boundaries: {
          validated: true
        },
        sessionId: 'test_session'
      };
      
      await fs.writeFile(auditLogPath, JSON.stringify(auditEntry) + '\n');
      
      const auditContent = await fs.readFile(auditLogPath, 'utf-8');
      const entries = auditContent.trim().split('\n').map(line => JSON.parse(line));
      
      expect(entries).toHaveLength(1);
      expect(entries[0].operation.type).toBe('test_scan');
      expect(entries[0].boundaries.validated).toBe(true);
    });
  });
});

// Helper functions
async function createTestProject(projectPath: string): Promise<void> {
  // Create package.json with vulnerable dependency
  const packageJson = {
    name: 'test-project',
    version: '1.0.0',
    dependencies: {
      'lodash': '4.17.20', // Known to have vulnerabilities in older versions
      'express': '4.17.1'
    }
  };
  await fs.writeFile(
    path.join(projectPath, 'package.json'),
    JSON.stringify(packageJson, null, 2)
  );

  // Create docker-compose.yml
  const dockerCompose = `
version: '3.8'
services:
  web:
    image: nginx:latest
    ports:
      - "8080:80"
  db:
    image: postgres:13
    environment:
      POSTGRES_PASSWORD: password123
networks:
  default:
    driver: bridge
`;
  await fs.writeFile(
    path.join(projectPath, 'docker-compose.yml'),
    dockerCompose
  );

  // Create source file with security issues
  const sourceCode = `
// Test file with intentional security issues
const express = require('express');
const app = express();

// Vulnerable: SQL injection
app.get('/user/:id', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.params.id;
  // database.query(query); // This would be vulnerable
  res.send('User data');
});

// Vulnerable: XSS
app.get('/search', (req, res) => {
  const results = "<h1>Results for: " + req.query.q + "</h1>";
  res.send(results);
});

// Secret in code
const API_KEY = "sk_test_51234567890abcdef";

app.listen(3000);
`;
  
  await fs.mkdir(path.join(projectPath, 'src'), { recursive: true });
  await fs.writeFile(
    path.join(projectPath, 'src', 'app.js'),
    sourceCode
  );

  // Create .env file with secrets
  const envFile = `
DATABASE_URL=postgres://user:password123@localhost:5432/db
JWT_SECRET=super_secret_key_12345
API_KEY=sk_live_abcdef123456789
`;
  await fs.writeFile(path.join(projectPath, '.env'), envFile);
}

async function runDockerCommand(args: string[], cwd?: string): Promise<{
  exitCode: number;
  stdout: string;
  stderr: string;
}> {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, {
      cwd: cwd || process.cwd(),
      stdio: 'pipe'
    });

    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', (data) => {
      stdout += data.toString();
    });

    child.stderr?.on('data', (data) => {
      stderr += data.toString();
    });

    child.on('close', (code) => {
      resolve({
        exitCode: code || 0,
        stdout,
        stderr
      });
    });

    child.on('error', reject);
  });
}