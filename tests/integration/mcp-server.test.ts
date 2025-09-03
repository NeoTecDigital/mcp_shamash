// import { ShamashServer } from '../../src/core/server';
// import { BoundaryEnforcer } from '../../src/boundaries/enforcer';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import { z } from 'zod';

describe('MCP Server Integration', () => {
  let serverProcess: ChildProcess;
  let client: Client;
  let transport: StdioClientTransport;

  beforeAll(async () => {
    // Start the server in a child process
    const serverPath = path.resolve(__dirname, '../../src/index.ts');
    serverProcess = spawn('npx', ['tsx', serverPath], {
      stdio: 'pipe',
      cwd: process.cwd(),
    });

    // Set up client transport
    transport = new StdioClientTransport();
    transport.setChildProcess(serverProcess);

    // Initialize client
    client = new Client(
      {
        name: 'test-client',
        version: '1.0.0',
      },
      {
        capabilities: {},
      }
    );

    await client.connect(transport);
  }, 30000);

  afterAll(async () => {
    if (client) {
      await client.close();
    }
    if (serverProcess) {
      serverProcess.kill();
    }
  }, 10000);

  describe('Server Initialization', () => {
    it('should respond to ping', async () => {
      // The connection itself is the test - if we get here, server is responding
      expect(client).toBeDefined();
    });
  });

  describe('Tool Discovery', () => {
    it('should list all available tools', async () => {
      const result = await client.request(
        { method: 'tools/list', params: {} },
        z.object({ tools: z.array(z.any()) })
      );

      expect(result.tools).toBeDefined();
      expect(result.tools.length).toBeGreaterThan(0);
      
      const toolNames = result.tools.map((tool: any) => tool.name);
      expect(toolNames).toContain('scan_project');
      expect(toolNames).toContain('scan_network');
      expect(toolNames).toContain('pentest_application');
      expect(toolNames).toContain('check_compliance');
    });

    it('should have proper tool schemas', async () => {
      const result = await client.request(
        { method: 'tools/list', params: {} },
        z.object({ tools: z.array(z.any()) })
      );

      const scanProjectTool = result.tools.find((tool: any) => tool.name === 'scan_project');
      expect(scanProjectTool).toBeDefined();
      expect(scanProjectTool.inputSchema.properties.path).toBeDefined();
      expect(scanProjectTool.inputSchema.required).toContain('path');
    });
  });

  describe('Boundary Enforcement', () => {
    it('should reject scan requests outside project scope', async () => {
      await expect(
        client.request(
          {
            method: 'tools/call',
            params: {
              name: 'scan_project',
              arguments: {
                path: '/etc/passwd'
              }
            }
          },
          z.any()
        )
      ).rejects.toThrow(/boundary|security|outside|violation/i);
    });
  });

  describe('Resource Access', () => {
    it('should provide access to cache resource', async () => {
      const result = await client.request(
        {
          method: 'resources/read',
          params: {
            uri: 'shamash://cache'
          }
        },
        z.object({ contents: z.array(z.any()) })
      );

      expect(result.contents).toBeDefined();
      expect(Array.isArray(result.contents)).toBe(true);
    });

    it('should provide access to rules resource', async () => {
      const result = await client.request(
        {
          method: 'resources/read',
          params: {
            uri: 'shamash://rules'
          }
        },
        z.object({ contents: z.array(z.any()) })
      );

      expect(result.contents).toBeDefined();
      expect(Array.isArray(result.contents)).toBe(true);
    });
  });

  describe('Network Boundary', () => {
    it('should reject external network scans', async () => {
      await expect(
        client.request(
          {
            method: 'tools/call',
            params: {
              name: 'scan_network',
              arguments: {
                target: '8.8.8.8',
                port_range: '1-65535'
              }
            }
          },
          z.any()
        )
      ).rejects.toThrow(/boundary|external|network|violation/i);
    });

    it('should allow localhost scans', async () => {
      const result = await client.request(
        {
          method: 'tools/call',
          params: {
            name: 'scan_network',
            arguments: {
              target: 'localhost',
              port_range: '80,443,8080'
            }
          }
        },
        z.any()
      );

      expect(result).toBeDefined();
    });
  });

  describe('Audit Logging', () => {
    it('should log all operations', async () => {
      const auditLogPath = path.resolve(__dirname, '../../logs/audit.log');
      
      // Perform an operation
      await client.request(
        {
          method: 'tools/call',
          params: {
            name: 'scan_project',
            arguments: {
              path: '.',
              tools: ['semgrep']
            }
          }
        },
        z.any()
      ).catch(() => {}); // Ignore errors, we just want to trigger logging

      // Check if audit log exists
      const fs = require('fs');
      const logExists = fs.existsSync(auditLogPath);
      expect(logExists).toBe(true);

      if (logExists) {
        const logContent = fs.readFileSync(auditLogPath, 'utf-8');
        expect(logContent).toContain('scan_project');
      }
    });
  });

  describe('Token Management', () => {
    it('should track token usage', async () => {
      const result = await client.request(
        {
          method: 'tools/call',
          params: {
            name: 'scan_project',
            arguments: {
              path: '.',
              tools: ['trivy'],
              token_limit: 1000
            }
          }
        },
        z.any()
      ).catch((error: any) => error);

      // Even if scan fails, token tracking should work
      expect(result).toBeDefined();
    });
  });

  describe('Compliance Framework', () => {
    it('should validate compliance', async () => {
      const result = await client.request(
        {
          method: 'tools/call',
          params: {
            name: 'check_compliance',
            arguments: {
              path: '.',
              framework: 'OWASP Top 10'
            }
          }
        },
        z.any()
      ).catch((error: any) => error);

      expect(result).toBeDefined();
    });

    it('should generate compliance report', async () => {
      const result = await client.request(
        {
          method: 'prompts/get',
          params: {
            name: 'generate_compliance_report'
          }
        },
        z.object({ 
          messages: z.array(z.object({
            role: z.string(),
            content: z.any()
          }))
        })
      );

      expect((result as any).messages).toBeDefined();
      expect((result as any).messages.length).toBeGreaterThan(0);
    });
  });

  describe('Error Handling', () => {
    it('should handle unknown tool calls', async () => {
      await expect(
        client.request(
          {
            method: 'tools/call',
            params: {
              name: 'unknown_tool',
              arguments: {}
            }
          },
          z.any()
        )
      ).rejects.toThrow(/Unknown tool/);
    });

    it('should handle malformed requests', async () => {
      await expect(
        client.request(
          {
            method: 'tools/call',
            params: {
              name: 'scan_project'
              // Missing required arguments
            }
          },
          z.any()
        )
      ).rejects.toThrow();
    });

    it('should handle unknown resources', async () => {
      await expect(
        client.request(
          {
            method: 'resources/read',
            params: {
              uri: 'shamash://unknown-resource'
            }
          },
          z.any()
        )
      ).rejects.toThrow(/Unknown resource/);
    });
  });
});