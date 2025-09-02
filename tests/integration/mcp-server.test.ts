import { ShamashServer } from '../../src/core/server';
import { BoundaryEnforcer } from '../../src/boundaries/enforcer';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';

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

  describe('Tools API', () => {
    it('should list available tools', async () => {
      const result = await client.request(
        { method: 'tools/list', params: {} },
        { method: 'tools/list', params: {} }
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
        { method: 'tools/list', params: {} }
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
          {
            method: 'tools/call',
            params: {
              name: 'scan_project',
              arguments: {
                path: '/etc/passwd'
              }
            }
          }
        )
      ).rejects.toThrow();
    });

    it('should accept scan requests within project scope', async () => {
      // This should not throw - scanning current project directory
      const result = await client.request(
        {
          method: 'tools/call',
          params: {
            name: 'scan_project',
            arguments: {
              path: process.cwd(),
              profile: 'quick'
            }
          }
        },
        {
          method: 'tools/call',
          params: {
            name: 'scan_project',
            arguments: {
              path: process.cwd(),
              profile: 'quick'
            }
          }
        }
      );

      expect(result).toBeDefined();
      expect(result.content).toBeDefined();
      expect(result.content[0].type).toBe('text');
    });

    it('should reject network scans to external IPs', async () => {
      await expect(
        client.request(
          {
            method: 'tools/call',
            params: {
              name: 'scan_network',
              arguments: {
                target: '8.8.8.8'
              }
            }
          },
          {
            method: 'tools/call',
            params: {
              name: 'scan_network',
              arguments: {
                target: '8.8.8.8'
              }
            }
          }
        )
      ).rejects.toThrow();
    });

    it('should accept network scans to localhost', async () => {
      const result = await client.request(
        {
          method: 'tools/call',
          params: {
            name: 'scan_network',
            arguments: {
              target: '127.0.0.1',
              ports: '80,443'
            }
          }
        },
        {
          method: 'tools/call',
          params: {
            name: 'scan_network',
            arguments: {
              target: '127.0.0.1',
              ports: '80,443'
            }
          }
        }
      );

      expect(result).toBeDefined();
    });
  });

  describe('Resources API', () => {
    it('should list available resources', async () => {
      const result = await client.request(
        { method: 'resources/list', params: {} },
        { method: 'resources/list', params: {} }
      );

      expect(result.resources).toBeDefined();
      expect(result.resources.length).toBeGreaterThan(0);
      
      const resourceUris = result.resources.map((resource: any) => resource.uri);
      expect(resourceUris).toContain('shamash://scan-results');
      expect(resourceUris).toContain('shamash://compliance-reports');
    });

    it('should read resources', async () => {
      const result = await client.request(
        {
          method: 'resources/read',
          params: {
            uri: 'shamash://scan-results'
          }
        },
        {
          method: 'resources/read',
          params: {
            uri: 'shamash://scan-results'
          }
        }
      );

      expect(result.contents).toBeDefined();
      expect(result.contents[0].mimeType).toBe('application/json');
    });
  });

  describe('Prompts API', () => {
    it('should list available prompts', async () => {
      const result = await client.request(
        { method: 'prompts/list', params: {} },
        { method: 'prompts/list', params: {} }
      );

      expect(result.prompts).toBeDefined();
      expect(result.prompts.length).toBeGreaterThan(0);
      
      const promptNames = result.prompts.map((prompt: any) => prompt.name);
      expect(promptNames).toContain('security_review');
    });

    it('should get prompt content', async () => {
      const result = await client.request(
        {
          method: 'prompts/get',
          params: {
            name: 'security_review',
            arguments: {
              project_path: process.cwd()
            }
          }
        },
        {
          method: 'prompts/get',
          params: {
            name: 'security_review',
            arguments: {
              project_path: process.cwd()
            }
          }
        }
      );

      expect(result.description).toBeDefined();
      expect(result.messages).toBeDefined();
      expect(result.messages.length).toBeGreaterThan(0);
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
          {
            method: 'tools/call',
            params: {
              name: 'unknown_tool',
              arguments: {}
            }
          }
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
          {
            method: 'tools/call',
            params: {
              name: 'scan_project'
            }
          }
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
          {
            method: 'resources/read',
            params: {
              uri: 'shamash://unknown-resource'
            }
          }
        )
      ).rejects.toThrow(/Unknown resource/);
    });
  });
});