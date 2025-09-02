import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { BoundaryEnforcer } from '../boundaries/enforcer.js';
import { TokenManager } from '../utils/token-manager.js';
import { AuditLogger } from '../utils/audit-logger.js';
import { ProjectScanner } from '../scanners/project-scanner.js';
import { NetworkScanner } from '../scanners/network-scanner.js';
import { PentestScanner } from '../scanners/pentest-scanner.js';
import { ComplianceValidator } from '../compliance/validator.js';
import type { ScanRequest, ScanResult } from '../types/index.js';

export class ShamashServer {
  private server: Server;
  private boundaryEnforcer: BoundaryEnforcer;
  private tokenManager: TokenManager;
  private auditLogger: AuditLogger;
  private projectScanner: ProjectScanner;
  private networkScanner: NetworkScanner;
  private pentestScanner: PentestScanner;
  private complianceValidator: ComplianceValidator;

  constructor() {
    this.server = new Server(
      {
        name: 'shamash',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
          resources: {},
          prompts: {},
        },
      }
    );

    // Initialize components
    this.boundaryEnforcer = new BoundaryEnforcer();
    this.tokenManager = new TokenManager();
    this.auditLogger = new AuditLogger();
    this.projectScanner = new ProjectScanner(this.boundaryEnforcer);
    this.networkScanner = new NetworkScanner(this.boundaryEnforcer);
    this.pentestScanner = new PentestScanner(this.boundaryEnforcer);
    this.complianceValidator = new ComplianceValidator();

    this.setupHandlers();
  }

  private setupHandlers(): void {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'scan_project',
          description: 'Performs comprehensive security scan on project directory',
          inputSchema: {
            type: 'object',
            properties: {
              path: { type: 'string', description: 'Project path to scan' },
              profile: { 
                type: 'string', 
                enum: ['quick', 'standard', 'thorough'],
                description: 'Scan profile'
              },
              tools: {
                type: 'array',
                items: { type: 'string' },
                description: 'Specific tools to use'
              },
            },
            required: ['path'],
          },
        },
        {
          name: 'scan_network',
          description: 'Performs network scanning within project boundaries',
          inputSchema: {
            type: 'object',
            properties: {
              target: { type: 'string', description: 'Network target' },
              ports: { type: 'string', description: 'Port range to scan' },
              serviceDetection: { type: 'boolean', description: 'Enable service detection' },
            },
            required: ['target'],
          },
        },
        {
          name: 'pentest_application',
          description: 'Performs penetration testing on deployed applications',
          inputSchema: {
            type: 'object',
            properties: {
              targetUrl: { type: 'string', description: 'Application URL' },
              testTypes: {
                type: 'array',
                items: { type: 'string' },
                description: 'Types of tests to perform'
              },
              depth: {
                type: 'string',
                enum: ['quick', 'standard', 'thorough'],
                description: 'Testing depth'
              },
            },
            required: ['targetUrl'],
          },
        },
        {
          name: 'check_compliance',
          description: 'Validates project against compliance frameworks',
          inputSchema: {
            type: 'object',
            properties: {
              path: { type: 'string', description: 'Project path' },
              frameworks: {
                type: 'array',
                items: { type: 'string' },
                description: 'Compliance frameworks to check'
              },
            },
            required: ['path', 'frameworks'],
          },
        },
      ],
    }));

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      // Check token budget
      if (!this.tokenManager.hasTokensAvailable()) {
        throw new McpError(ErrorCode.InvalidRequest, 'Token budget exceeded');
      }

      // Log operation start
      const sessionId = await this.auditLogger.startOperation(name, args);

      try {
        let result: any;

        switch (name) {
          case 'scan_project':
            result = await this.handleProjectScan(args);
            break;

          case 'scan_network':
            result = await this.handleNetworkScan(args);
            break;

          case 'pentest_application':
            result = await this.handlePentest(args);
            break;

          case 'check_compliance':
            result = await this.handleComplianceCheck(args);
            break;

          default:
            throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
        }

        // Log successful completion
        await this.auditLogger.completeOperation(sessionId, result);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      } catch (error) {
        // Log error
        await this.auditLogger.failOperation(sessionId, error);
        
        if (error instanceof McpError) {
          throw error;
        }
        
        throw new McpError(
          ErrorCode.InternalError,
          `Tool execution failed: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
      }
    });

    // List resources
    this.server.setRequestHandler(ListResourcesRequestSchema, async () => ({
      resources: [
        {
          uri: 'shamash://scan-results',
          name: 'Scan Results',
          description: 'Access detailed scan results',
          mimeType: 'application/json',
        },
        {
          uri: 'shamash://compliance-reports',
          name: 'Compliance Reports',
          description: 'Access compliance validation reports',
          mimeType: 'application/json',
        },
      ],
    }));

    // Read resources
    this.server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      const { uri } = request.params;
      
      if (uri.startsWith('shamash://scan-results')) {
        // Return scan results
        return {
          contents: [
            {
              uri,
              mimeType: 'application/json',
              text: JSON.stringify({ message: 'Scan results placeholder' }),
            },
          ],
        };
      }
      
      throw new McpError(ErrorCode.InvalidRequest, `Unknown resource: ${uri}`);
    });

    // List prompts
    this.server.setRequestHandler(ListPromptsRequestSchema, async () => ({
      prompts: [
        {
          name: 'security_review',
          description: 'Comprehensive security review prompt',
          arguments: [
            {
              name: 'project_path',
              description: 'Path to project',
              required: true,
            },
          ],
        },
      ],
    }));

    // Get prompt
    this.server.setRequestHandler(GetPromptRequestSchema, async (request) => {
      const { name } = request.params;
      
      if (name === 'security_review') {
        return {
          description: 'Comprehensive security review',
          messages: [
            {
              role: 'user',
              content: {
                type: 'text',
                text: 'Perform a comprehensive security review of the project',
              },
            },
          ],
        };
      }
      
      throw new McpError(ErrorCode.InvalidRequest, `Unknown prompt: ${name}`);
    });
  }

  private async handleProjectScan(args: any): Promise<ScanResult> {
    const { path, profile = 'standard', tools } = args;

    // Validate project boundaries
    const validation = await this.boundaryEnforcer.validatePath(path);
    if (!validation.allowed) {
      throw new McpError(ErrorCode.InvalidRequest, validation.reason || 'Path validation failed');
    }

    // Perform scan
    const request: ScanRequest = {
      type: 'project',
      target: path,
      profile,
      tools,
      options: {
        maxTokens: this.tokenManager.getRemainingTokens(),
      },
    };

    return await this.projectScanner.scan(request);
  }

  private async handleNetworkScan(args: any): Promise<ScanResult> {
    const { target, ports = '1-65535', serviceDetection = true } = args;

    // Validate network boundaries
    const validation = await this.boundaryEnforcer.validateNetwork(target);
    if (!validation.allowed) {
      throw new McpError(ErrorCode.InvalidRequest, validation.reason || 'Network validation failed');
    }

    // Perform network scan
    const request: ScanRequest = {
      type: 'network',
      target,
      options: {
        maxTokens: this.tokenManager.getRemainingTokens(),
      },
    };

    return await this.networkScanner.scan(request, { ports, serviceDetection });
  }

  private async handlePentest(args: any): Promise<ScanResult> {
    const { targetUrl, testTypes = [], depth = 'standard' } = args;

    // Validate target URL is within project
    const validation = await this.boundaryEnforcer.validateUrl(targetUrl);
    if (!validation.allowed) {
      throw new McpError(ErrorCode.InvalidRequest, validation.reason || 'URL validation failed');
    }

    // Perform pentest
    const request: ScanRequest = {
      type: 'application',
      target: targetUrl,
      profile: depth,
      tools: testTypes,
      options: {
        maxTokens: this.tokenManager.getRemainingTokens(),
        maxDuration: 30 * 60 * 1000, // 30 minutes
      },
    };

    return await this.pentestScanner.scan(request);
  }

  private async handleComplianceCheck(args: any): Promise<any> {
    const { path, frameworks } = args;

    // Validate path
    const validation = await this.boundaryEnforcer.validatePath(path);
    if (!validation.allowed) {
      throw new McpError(ErrorCode.InvalidRequest, validation.reason || 'Path validation failed');
    }

    // Check compliance
    return await this.complianceValidator.validate(path, frameworks);
  }

  async start(): Promise<void> {
    // Initialize boundary enforcer with project scope
    await this.boundaryEnforcer.initialize();

    // Start server
    const transport = new StdioServerTransport();
    await this.server.connect(transport);

    console.error('Shamash MCP server started successfully');
  }
}

// Start server if run directly
if (require.main === module) {
  const server = new ShamashServer();
  server.start().catch((error) => {
    console.error('Failed to start server:', error);
    process.exit(1);
  });
}