# MCP Shamash - Security Audit & Compliance Server

A Model Context Protocol (MCP) server for security auditing, penetration testing, and compliance validation with strict project boundary enforcement.

## Features

- **Project-Scoped Security Scanning**: Never escapes project boundaries
- **Multiple Security Tools**: Semgrep, Trivy, Gitleaks, OWASP ZAP, and more
- **Network Penetration Testing**: Safe network scanning within project scope
- **Compliance Validation**: OWASP, CIS, NIST, ISO 27001 frameworks
- **Containerized Execution**: Isolated scanner execution
- **Token Efficiency**: <1000 tokens per operation
- **Comprehensive Audit Logging**: Complete operation trails

## Quick Start

### Installation

```bash
npm install
npm run build
```

### Running the Server

```bash
npm start
```

Or for development:

```bash
npm run dev
```

### MCP Integration

Configure in your MCP-compatible client:

```json
{
  "mcpServers": {
    "shamash": {
      "command": "node",
      "args": ["/path/to/mcp_shamash/dist/index.js"]
    }
  }
}
```

## Available Tools

### scan_project
Comprehensive security scan of project directory.

```json
{
  "name": "scan_project",
  "arguments": {
    "path": "/path/to/project",
    "profile": "standard",
    "tools": ["semgrep", "trivy", "gitleaks"]
  }
}
```

### scan_network
Network scanning within project boundaries.

```json
{
  "name": "scan_network",
  "arguments": {
    "target": "127.0.0.1",
    "ports": "80,443",
    "serviceDetection": true
  }
}
```

### pentest_application
Penetration testing of deployed applications.

```json
{
  "name": "pentest_application",
  "arguments": {
    "targetUrl": "http://localhost:3000",
    "testTypes": ["sql_injection", "xss", "csrf"],
    "depth": "thorough"
  }
}
```

### check_compliance
Compliance framework validation.

```json
{
  "name": "check_compliance",
  "arguments": {
    "path": "/path/to/project",
    "frameworks": ["OWASP", "CIS", "NIST"]
  }
}
```

## Security Boundaries

### Project Scope Detection
- Automatic discovery of Docker Compose networks
- Kubernetes service detection
- Package.json analysis for Node.js apps
- Local service enumeration

### Multi-Layer Enforcement
1. **Path Validation**: Prevents directory traversal
2. **Network Boundaries**: CIDR-based network restrictions
3. **Container Isolation**: Docker security hardening
4. **Resource Limits**: Memory, CPU, and process constraints

### Blocked Operations
- System path access (`/etc`, `/usr`, `/var`)
- External network scanning
- Management port access (22, 3389, 445)
- Privilege escalation attempts

## Architecture

```
mcp-shamash/
├── src/
│   ├── core/           # MCP server core
│   ├── boundaries/     # Scope enforcement
│   ├── scanners/       # Tool integrations
│   ├── compliance/     # Framework validators
│   └── utils/          # Token management, audit logging
├── containers/         # Docker configurations
├── rules/             # Security rules
└── tests/            # Test suites
```

## Development

### Building

```bash
npm run build
```

### Testing

```bash
npm test
npm run test:coverage
```

### Linting

```bash
npm run lint
npm run format
```

## Container Usage

### Build Scanner Containers

```bash
# Build Semgrep scanner
docker build -f containers/Dockerfile.semgrep -t shamash-semgrep .

# Build all scanners
docker-compose -f containers/docker-compose.scanners.yml build
```

### Run Isolated Scan

```bash
# Set target path and run scan
export SHAMASH_TARGET_PATH=/path/to/project
docker-compose -f containers/docker-compose.scanners.yml up semgrep
```

## Configuration

### Environment Variables

- `SHAMASH_MAX_TOKENS_PER_SCAN`: Token limit per scan (default: 1000)
- `SHAMASH_MAX_TOKENS_PER_HOUR`: Hourly token limit (default: 50000)
- `SHAMASH_AUDIT_LOG_PATH`: Audit log location (default: ./audit.log)

### Project Configuration

Create `.shamash.yml` in project root:

```yaml
networks:
  allowed:
    - 172.20.0.0/16
    - 127.0.0.1/32
  blocked:
    - 10.0.0.0/8

ports:
  allowed: [80, 443, 3000, 8080]
  blocked: [22, 3389, 445]

tools:
  semgrep:
    config: "auto"
    timeout: 300
  trivy:
    severity: "HIGH,CRITICAL"
  gitleaks:
    entropy_threshold: 4.5
```

## Compliance Frameworks

### OWASP Top 10 Coverage
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable Components
- A07: Authentication Failures
- A08: Software/Data Integrity
- A09: Security Logging
- A10: Server-Side Request Forgery

### CIS Controls
- Inventory and Control of Assets
- Access Control Management
- Continuous Vulnerability Management
- Network Infrastructure Management
- Data Protection

### NIST Cybersecurity Framework
- **Identify**: Asset management, governance
- **Protect**: Access control, data security
- **Detect**: Security monitoring, detection processes
- **Respond**: Response planning, incident management
- **Recover**: Recovery planning, improvements

## Security Considerations

### Defensive Only
- No offensive capabilities
- Read-only filesystem operations
- No credential harvesting
- Audit trail for all operations

### Boundary Enforcement
- Multiple validation layers
- Real-time monitoring
- Automatic violation detection
- Emergency shutdown capability

### Token Management
- Per-scan limits (1000 tokens)
- Rate limiting (5000/minute, 50000/hour)
- Usage tracking and reporting

## License

MIT License

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Support

For issues and questions:
- Create an issue on GitHub
- Check the audit logs for troubleshooting
- Review boundary enforcement logs