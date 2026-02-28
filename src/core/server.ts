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
import { WebsiteScanner } from '../scanners/website-scanner.js';
import { ComplianceValidator } from '../compliance/validator.js';
import { IncrementalScanner } from '../scanners/incremental-scanner.js';
import { RemediationAdvisor } from '../advisor/remediation-advisor.js';
import { FalsePositiveFilter } from '../filters/false-positive-filter.js';
import type { ScanRequest, ScanResult } from '../types/index.js';

export class ShamashServer {
  private server: Server;
  private boundaryEnforcer: BoundaryEnforcer;
  private tokenManager: TokenManager;
  private auditLogger: AuditLogger;
  private projectScanner: ProjectScanner;
  private networkScanner: NetworkScanner;
  private pentestScanner: PentestScanner;
  private websiteScanner: WebsiteScanner;
  private complianceValidator: ComplianceValidator;
  private incrementalScanner: IncrementalScanner;
  private remediationAdvisor: RemediationAdvisor;
  private falsePositiveFilter: FalsePositiveFilter;

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
    this.complianceValidator = new ComplianceValidator();
    this.remediationAdvisor = new RemediationAdvisor();
    
    // Scanners will be initialized after boundary enforcer is ready
    this.projectScanner = null as any;
    this.networkScanner = null as any;
    this.pentestScanner = null as any;
    this.websiteScanner = null as any;
    this.incrementalScanner = null as any;
    this.falsePositiveFilter = null as any;

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
              incremental: {
                type: 'boolean',
                description: 'Use incremental scanning if available'
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
          name: 'pentest_website',
          description: 'Performs security testing on web applications via HTTP/HTTPS. Supports external URLs with authorization. Tests security headers, SSL/TLS, information disclosure, cookies, CORS, and more.',
          inputSchema: {
            type: 'object',
            properties: {
              targetUrl: { type: 'string', description: 'Website URL to test (http:// or https://)' },
              testTypes: {
                type: 'array',
                items: { type: 'string' },
                description: 'Tests to run: security_headers, ssl_tls, information_disclosure, directory_listing, cookie_security, http_methods, cors_check, clickjacking, server_fingerprint, ssl_cipher_analysis, error_handling, open_redirect, mixed_content, waf_detection, authentication_check, session_analysis, api_exposure, subdomain_headers',
              },
              depth: {
                type: 'string',
                enum: ['quick', 'standard', 'thorough'],
                description: 'Testing depth (default: standard)',
              },
              authorized: {
                type: 'boolean',
                description: 'Confirm authorization to test external targets (required for non-local URLs)',
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
                items: { 
                  type: 'string',
                  enum: ['OWASP', 'CIS', 'NIST', 'ISO27001']
                },
                description: 'Compliance frameworks to check'
              },
              profile: {
                type: 'string',
                enum: ['minimal', 'standard', 'comprehensive'],
                description: 'Compliance check profile (default: standard)'
              },
            },
            required: ['path', 'frameworks'],
          },
        },
        {
          name: 'generate_remediation',
          description: 'Generate actionable remediation advice for findings',
          inputSchema: {
            type: 'object',
            properties: {
              findingIds: {
                type: 'array',
                items: { type: 'string' },
                description: 'IDs of findings to generate remediation for'
              },
            },
            required: [],
          },
        },
        {
          name: 'manage_false_positives',
          description: 'Manage false positive suppressions',
          inputSchema: {
            type: 'object',
            properties: {
              action: {
                type: 'string',
                enum: ['add', 'remove', 'list', 'filter'],
                description: 'Action to perform'
              },
              findingId: { type: 'string', description: 'Finding ID to suppress' },
              reason: { type: 'string', description: 'Reason for suppression' },
            },
            required: ['action'],
          },
        },
        {
          name: 'manage_custom_rules',
          description: 'Manage custom security rules',
          inputSchema: {
            type: 'object',
            properties: {
              action: {
                type: 'string',
                enum: ['list', 'add', 'update', 'remove', 'enable', 'disable', 'stats', 'validate'],
                description: 'Action to perform'
              },
              ruleId: { type: 'string', description: 'Rule ID for update/remove/enable/disable' },
              rule: {
                type: 'object',
                description: 'Rule definition for add/update',
                properties: {
                  name: { type: 'string' },
                  description: { type: 'string' },
                  severity: { 
                    type: 'string', 
                    enum: ['critical', 'high', 'medium', 'low', 'informational'] 
                  },
                  category: { 
                    type: 'string', 
                    enum: ['security', 'performance', 'maintainability', 'style'] 
                  },
                  pattern: { type: 'string' },
                  filePatterns: { 
                    type: 'array', 
                    items: { type: 'string' } 
                  },
                  excludePatterns: { 
                    type: 'array', 
                    items: { type: 'string' } 
                  },
                  messageTemplate: { type: 'string' },
                  remediation: { type: 'string' },
                  references: { 
                    type: 'array', 
                    items: { type: 'string' } 
                  },
                  enabled: { type: 'boolean' },
                  createdBy: { type: 'string' }
                }
              }
            },
            required: ['action'],
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

          case 'pentest_website':
            result = await this.handleWebsitePentest(args);
            break;

          case 'check_compliance':
            result = await this.handleComplianceCheck(args);
            break;

          case 'generate_remediation':
            result = await this.handleGenerateRemediation(args);
            break;

          case 'manage_false_positives':
            result = await this.handleManageFalsePositives(args);
            break;

          case 'manage_custom_rules':
            result = await this.handleManageCustomRules(args);
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
    const { path, profile = 'standard', tools, incremental = false } = args;

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
        incremental,
      },
    };

    // Use incremental scanner if requested
    if (incremental && this.incrementalScanner) {
      const result = await this.incrementalScanner.scan(request);
      
      // Apply false positive filtering
      if (this.falsePositiveFilter) {
        const filterResults = await this.falsePositiveFilter.filterFindings(result.findings);
        result.findings = filterResults.filter(r => !r.filtered).map(r => r.finding);
        
        // Add filter stats to result
        const filterStats = this.falsePositiveFilter.getStatistics(filterResults);
        console.error(`Filtered ${filterStats.filtered} false positives (${filterStats.filterRate.toFixed(1)}%)`);
      }
      
      return result;
    }

    // Regular scan
    const result = await this.projectScanner.scan(request);
    
    // Apply false positive filtering
    if (this.falsePositiveFilter) {
      const filterResults = await this.falsePositiveFilter.filterFindings(result.findings);
      result.findings = filterResults.filter(r => !r.filtered).map(r => r.finding);
    }
    
    return result;
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

  private async handleWebsitePentest(args: any): Promise<ScanResult> {
    const { targetUrl, testTypes = [], depth = 'standard', authorized = false } = args;

    // Validate URL with external authorization support
    const validation = await this.boundaryEnforcer.validateExternalUrl(targetUrl, authorized);
    if (!validation.allowed) {
      throw new McpError(ErrorCode.InvalidRequest, validation.reason || 'URL validation failed');
    }

    const request: ScanRequest = {
      type: 'website',
      target: targetUrl,
      profile: depth,
      tools: testTypes.length > 0 ? testTypes : undefined,
      options: {
        maxTokens: this.tokenManager.getRemainingTokens(),
        maxDuration: 5 * 60 * 1000, // 5 minutes
      },
    };

    return await this.websiteScanner.scan(request);
  }

  private async handleComplianceCheck(args: any): Promise<any> {
    const { path, frameworks, profile = 'standard' } = args;

    // Validate path
    const validation = await this.boundaryEnforcer.validatePath(path);
    if (!validation.allowed) {
      throw new McpError(ErrorCode.InvalidRequest, validation.reason || 'Path validation failed');
    }

    // Set the project scanner for the compliance validator
    this.complianceValidator.setProjectScanner(this.projectScanner);

    // Check compliance - this will run scans and map to frameworks
    const report = await this.complianceValidator.validate(path, frameworks, profile);

    // Generate HTML report
    const htmlPath = await this.complianceValidator.generateHTMLReport(report);

    // Return simplified result for MCP response
    return {
      status: 'success',
      summary: {
        overallCompliance: `${report.summary.overallCompliance}%`,
        totalFindings: report.summary.totalFindings,
        criticalFindings: report.summary.criticalFindings,
        highFindings: report.summary.highFindings,
      },
      frameworks: report.frameworks.map(f => ({
        name: f.framework,
        coverage: `${f.coverage}%`,
        passed: f.passed,
        failed: f.failed,
        total: f.totalControls,
      })),
      recommendations: report.summary.recommendations.slice(0, 5),
      reportPath: htmlPath,
      tokenUsage: report.scanResults?.tokenUsage || 0,
    };
  }

  private async handleGenerateRemediation(_args: any): Promise<any> {
    // Get recent scan results or specific findings
    // For demo, we'll generate advice for sample findings
    const sampleFindings = [
      {
        id: 'sample_001',
        type: 'dependency',
        severity: 'high' as const,
        title: 'Vulnerable dependency: lodash@4.17.19',
        description: 'Known security vulnerability CVE-2021-23337',
        location: { file: 'package.json' },
        cve: 'CVE-2021-23337',
      },
    ];

    const plan = await this.remediationAdvisor.generateRemediationPlan(sampleFindings);
    const markdown = this.remediationAdvisor.generateMarkdownReport(plan);

    return {
      status: 'success',
      remediations: plan.remediations.length,
      summary: plan.summary,
      report: markdown,
    };
  }

  private async handleManageFalsePositives(args: any): Promise<any> {
    const { action, findingId, reason } = args;

    switch (action) {
      case 'add':
        if (!findingId || !reason) {
          throw new McpError(ErrorCode.InvalidRequest, 'Finding ID and reason required for add action');
        }
        
        await this.falsePositiveFilter.addRule({
          findingType: 'manual',
          pattern: findingId,
          reason,
        });
        
        return {
          status: 'success',
          message: `Added false positive rule for ${findingId}`,
        };

      case 'remove':
        if (!findingId) {
          throw new McpError(ErrorCode.InvalidRequest, 'Finding ID required for remove action');
        }
        
        const removed = await this.falsePositiveFilter.removeRule(findingId);
        
        return {
          status: removed ? 'success' : 'not_found',
          message: removed ? `Removed rule ${findingId}` : `Rule ${findingId} not found`,
        };

      case 'list':
        await this.falsePositiveFilter.loadRules();
        
        return {
          status: 'success',
          rules: [], // Would need to expose rules from filter
        };

      case 'filter':
        // This would be used internally during scans
        return {
          status: 'success',
          message: 'False positive filtering is applied automatically during scans',
        };

      default:
        throw new McpError(ErrorCode.InvalidRequest, `Unknown action: ${action}`);
    }
  }

  private async handleManageCustomRules(args: any): Promise<any> {
    const { action, ruleId, rule } = args;

    // Get custom rule engine from project scanner
    const projectRoot = this.boundaryEnforcer.getProjectScope()?.projectRoot || process.cwd();
    const { CustomRuleEngine } = await import('../rules/custom-rule-engine.js');
    const customRuleEngine = new (CustomRuleEngine as any)(projectRoot);
    await customRuleEngine.loadRules();

    switch (action) {
      case 'list':
        const rules = customRuleEngine.getRules();
        return {
          status: 'success',
          rules: rules,
          count: rules.length
        };

      case 'add':
        if (!rule) {
          throw new McpError(ErrorCode.InvalidRequest, 'Rule definition required for add action');
        }
        
        const validation = await customRuleEngine.validateRule(rule);
        if (!validation.valid) {
          throw new McpError(ErrorCode.InvalidRequest, `Invalid rule: ${validation.errors.join(', ')}`);
        }
        
        const newRuleId = await customRuleEngine.addRule(rule);
        return {
          status: 'success',
          message: `Added custom rule ${rule.name}`,
          ruleId: newRuleId
        };

      case 'update':
        if (!ruleId || !rule) {
          throw new McpError(ErrorCode.InvalidRequest, 'Rule ID and rule definition required for update action');
        }
        
        const updateValidation = await customRuleEngine.validateRule(rule);
        if (!updateValidation.valid) {
          throw new McpError(ErrorCode.InvalidRequest, `Invalid rule: ${updateValidation.errors.join(', ')}`);
        }
        
        const updated = await customRuleEngine.updateRule(ruleId, rule);
        return {
          status: updated ? 'success' : 'not_found',
          message: updated ? `Updated rule ${ruleId}` : `Rule ${ruleId} not found`
        };

      case 'remove':
        if (!ruleId) {
          throw new McpError(ErrorCode.InvalidRequest, 'Rule ID required for remove action');
        }
        
        const removed = await customRuleEngine.removeRule(ruleId);
        return {
          status: removed ? 'success' : 'not_found',
          message: removed ? `Removed rule ${ruleId}` : `Rule ${ruleId} not found`
        };

      case 'enable':
        if (!ruleId) {
          throw new McpError(ErrorCode.InvalidRequest, 'Rule ID required for enable action');
        }
        
        const enabled = await customRuleEngine.enableRule(ruleId);
        return {
          status: enabled ? 'success' : 'not_found',
          message: enabled ? `Enabled rule ${ruleId}` : `Rule ${ruleId} not found`
        };

      case 'disable':
        if (!ruleId) {
          throw new McpError(ErrorCode.InvalidRequest, 'Rule ID required for disable action');
        }
        
        const disabled = await customRuleEngine.disableRule(ruleId);
        return {
          status: disabled ? 'success' : 'not_found',
          message: disabled ? `Disabled rule ${ruleId}` : `Rule ${ruleId} not found`
        };

      case 'stats':
        const stats = customRuleEngine.getStats();
        return {
          status: 'success',
          stats: stats
        };

      case 'validate':
        if (!rule) {
          throw new McpError(ErrorCode.InvalidRequest, 'Rule definition required for validate action');
        }
        
        const validationResult = await customRuleEngine.validateRule(rule);
        return {
          status: 'success',
          valid: validationResult.valid,
          errors: validationResult.errors
        };

      default:
        throw new McpError(ErrorCode.InvalidRequest, `Unknown action: ${action}`);
    }
  }

  async start(): Promise<void> {
    // Initialize boundary enforcer with project scope
    await this.boundaryEnforcer.initialize();

    const projectRoot = this.boundaryEnforcer.getProjectScope()?.projectRoot || process.cwd();

    // Now create scanners with initialized boundary enforcer
    this.projectScanner = new ProjectScanner(this.boundaryEnforcer);
    this.networkScanner = new NetworkScanner(this.boundaryEnforcer);
    this.pentestScanner = new PentestScanner(this.boundaryEnforcer);
    this.websiteScanner = new WebsiteScanner(this.boundaryEnforcer);

    // Initialize Sprint 5 features
    this.incrementalScanner = new IncrementalScanner(projectRoot, this.projectScanner);
    this.falsePositiveFilter = new FalsePositiveFilter(projectRoot);

    // Initialize scanners
    await this.projectScanner.initialize();
    await this.falsePositiveFilter.loadRules();

    // Start server
    const transport = new StdioServerTransport();
    await this.server.connect(transport);

    console.error('Shamash MCP server started successfully');
    console.error('Sprint 5 features enabled: Incremental scanning, Remediation advisor, FP filtering');
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