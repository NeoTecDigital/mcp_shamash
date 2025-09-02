# MCP API Specification - Shamash Security Server

## Overview
MCP Shamash provides security audit and compliance validation capabilities through the Model Context Protocol, offering defensive security scanning with strict project boundaries and token efficiency.

## Server Information
```json
{
  "name": "shamash",
  "version": "1.0.0",
  "description": "Security audit and compliance MCP server",
  "capabilities": {
    "tools": true,
    "resources": true,
    "prompts": true
  }
}
```

## Tools API

### 1. scan_project
Performs comprehensive security scan on project directory.

**Request:**
```json
{
  "name": "scan_project",
  "arguments": {
    "path": "/path/to/project",
    "profile": "standard",
    "tools": ["semgrep", "trivy", "gitleaks"],
    "options": {
      "incremental": false,
      "parallel": true,
      "max_tokens": 1000
    }
  }
}
```

**Response:**
```json
{
  "status": "success",
  "scan_id": "scan_123456",
  "summary": {
    "vulnerabilities": 15,
    "critical": 2,
    "high": 5,
    "medium": 8,
    "low": 0
  },
  "token_usage": 856,
  "scan_time_ms": 2340
}
```

### 2. check_compliance
Validates project against compliance frameworks.

**Request:**
```json
{
  "name": "check_compliance",
  "arguments": {
    "path": "/path/to/project",
    "frameworks": ["OWASP", "CIS", "NIST"],
    "level": "standard"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "compliance": {
    "OWASP_Top_10": {
      "coverage": "100%",
      "passed": 8,
      "failed": 2
    },
    "CIS_Controls": {
      "coverage": "85%",
      "passed": 17,
      "failed": 3
    }
  },
  "report_url": "/reports/compliance_123456.json"
}
```

### 3. scan_dependencies
Analyzes project dependencies for vulnerabilities.

**Request:**
```json
{
  "name": "scan_dependencies",
  "arguments": {
    "path": "/path/to/project",
    "depth": 2,
    "include_dev": false
  }
}
```

**Response:**
```json
{
  "status": "success",
  "dependencies": {
    "total": 145,
    "vulnerable": 12,
    "outdated": 34
  },
  "critical_cves": [
    {
      "package": "log4j",
      "version": "2.14.0",
      "cve": "CVE-2021-44228",
      "severity": "critical"
    }
  ]
}
```

### 4. detect_secrets
Scans for exposed secrets and credentials.

**Request:**
```json
{
  "name": "detect_secrets",
  "arguments": {
    "path": "/path/to/project",
    "exclude_patterns": [".git", "node_modules"],
    "entropy_threshold": 4.5
  }
}
```

**Response:**
```json
{
  "status": "success",
  "secrets_found": 3,
  "findings": [
    {
      "file": "config/database.yml",
      "line": 15,
      "type": "aws_access_key",
      "confidence": "high"
    }
  ]
}
```

### 5. validate_iac
Validates Infrastructure as Code configurations.

**Request:**
```json
{
  "name": "validate_iac",
  "arguments": {
    "path": "/path/to/terraform",
    "providers": ["aws", "azure"],
    "policies": "cis-1.4"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "issues": 7,
  "by_severity": {
    "critical": 1,
    "high": 2,
    "medium": 4
  }
}
```

### 6. scan_network
Performs network scanning and service discovery within project boundaries.

**Request:**
```json
{
  "name": "scan_network",
  "arguments": {
    "target": "project",
    "scope": {
      "docker_compose": true,
      "kubernetes": true,
      "local_services": true
    },
    "scan_type": "comprehensive",
    "ports": "1-65535",
    "service_detection": true
  }
}
```

**Response:**
```json
{
  "status": "success",
  "discovered_services": 12,
  "hosts": [
    {
      "ip": "172.29.0.2",
      "hostname": "webapp",
      "ports": [
        {"port": 80, "service": "http", "version": "nginx/1.21.0"},
        {"port": 443, "service": "https", "version": "nginx/1.21.0"}
      ]
    }
  ],
  "vulnerabilities_detected": 3,
  "token_usage": 450
}
```

### 7. pentest_application
Performs comprehensive penetration testing on deployed applications.

**Request:**
```json
{
  "name": "pentest_application",
  "arguments": {
    "target_url": "http://localhost:3000",
    "test_types": [
      "sql_injection",
      "xss",
      "csrf",
      "authentication",
      "authorization",
      "api_security"
    ],
    "depth": "thorough",
    "authenticated": false,
    "max_duration_minutes": 30
  }
}
```

**Response:**
```json
{
  "status": "success",
  "test_id": "pentest_789012",
  "findings": {
    "critical": 1,
    "high": 3,
    "medium": 7,
    "low": 12,
    "informational": 23
  },
  "exploitable_vulnerabilities": [
    {
      "type": "SQL Injection",
      "endpoint": "/api/users/search",
      "parameter": "query",
      "cvss_score": 9.1,
      "proof_of_concept": "..."
    }
  ],
  "scan_duration_ms": 28340,
  "token_usage": 892
}
```

### 8. test_docker_security
Tests Docker container and compose configuration security.

**Request:**
```json
{
  "name": "test_docker_security",
  "arguments": {
    "compose_file": "./docker-compose.yml",
    "running_containers": true,
    "image_scan": true,
    "runtime_analysis": true,
    "network_policies": true
  }
}
```

**Response:**
```json
{
  "status": "success",
  "container_risks": [
    {
      "container": "webapp",
      "issues": [
        "Running as root",
        "Capabilities not dropped",
        "No resource limits"
      ]
    }
  ],
  "image_vulnerabilities": {
    "critical": 2,
    "high": 5
  },
  "network_exposure": [
    {
      "service": "database",
      "exposed_ports": [3306],
      "risk": "Database port exposed to host"
    }
  ]
}
```

### 9. runtime_security_test
Performs Interactive Application Security Testing (IAST) on running applications.

**Request:**
```json
{
  "name": "runtime_security_test",
  "arguments": {
    "application_url": "http://localhost:8080",
    "test_scenarios": [
      "user_registration",
      "login_flow",
      "data_processing",
      "api_calls"
    ],
    "monitor_duration_minutes": 10,
    "inject_tests": true
  }
}
```

**Response:**
```json
{
  "status": "success",
  "runtime_vulnerabilities": [
    {
      "type": "Insecure Deserialization",
      "stack_trace": "...",
      "triggered_by": "POST /api/process",
      "severity": "critical"
    }
  ],
  "performance_issues": [
    {
      "type": "N+1 Query",
      "endpoint": "/api/users/list",
      "impact": "500ms delay per request"
    }
  ],
  "security_headers_missing": [
    "Content-Security-Policy",
    "X-Frame-Options"
  ]
}
```

### 10. api_security_test
Comprehensive API security testing including REST, GraphQL, and gRPC.

**Request:**
```json
{
  "name": "api_security_test",
  "arguments": {
    "api_spec": "./openapi.yaml",
    "base_url": "http://localhost:3000/api",
    "test_types": [
      "authentication_bypass",
      "authorization_flaws",
      "injection_attacks",
      "rate_limiting",
      "data_validation"
    ],
    "fuzzing": true,
    "wordlists": ["common", "extended"]
  }
}
```

**Response:**
```json
{
  "status": "success",
  "endpoints_tested": 47,
  "vulnerabilities": [
    {
      "endpoint": "POST /api/users",
      "vulnerability": "Mass Assignment",
      "severity": "high",
      "details": "Can set admin role via user registration"
    },
    {
      "endpoint": "GET /api/users/{id}",
      "vulnerability": "IDOR",
      "severity": "critical",
      "details": "No authorization check for user data access"
    }
  ],
  "fuzzing_crashes": 2,
  "rate_limit_bypass": true
}
```

### 11. get_remediation
Provides remediation guidance for findings.

**Request:**
```json
{
  "name": "get_remediation",
  "arguments": {
    "finding_id": "VULN-123456",
    "context": true,
    "examples": true
  }
}
```

**Response:**
```json
{
  "status": "success",
  "remediation": {
    "description": "SQL injection vulnerability in user input",
    "fix": "Use parameterized queries",
    "code_example": "...",
    "effort": "low",
    "priority": "critical"
  }
}
```

## Resources API

### 1. scan_results
Access detailed scan results.

**URI:** `shamash://scans/{scan_id}`

**Response:**
```json
{
  "scan_id": "scan_123456",
  "timestamp": "2024-01-01T12:00:00Z",
  "findings": [...],
  "metadata": {
    "tools_used": ["semgrep", "trivy"],
    "scan_duration_ms": 2340,
    "files_scanned": 456
  }
}
```

### 2. compliance_reports
Access compliance validation reports.

**URI:** `shamash://compliance/{report_id}`

### 3. vulnerability_database
Query vulnerability database.

**URI:** `shamash://vulndb/query`

## Prompts API

### 1. security_review
Template for security review requests.

```json
{
  "name": "security_review",
  "description": "Comprehensive security review prompt",
  "arguments": [
    {
      "name": "project_path",
      "description": "Path to project",
      "required": true
    }
  ]
}
```

### 2. compliance_check
Template for compliance validation.

```json
{
  "name": "compliance_check",
  "description": "Compliance framework validation",
  "arguments": [
    {
      "name": "framework",
      "description": "Compliance framework",
      "required": true
    }
  ]
}
```

## Error Handling

### Error Response Format
```json
{
  "error": {
    "code": "SCOPE_VIOLATION",
    "message": "Attempted to scan outside project boundary",
    "details": {
      "requested_path": "/etc/passwd",
      "allowed_path": "/home/user/project"
    }
  }
}
```

### Error Codes
- `SCOPE_VIOLATION`: Attempted access outside project
- `TOKEN_EXCEEDED`: Token budget exceeded
- `TOOL_FAILURE`: Security tool execution failed
- `INVALID_PATH`: Invalid or non-existent path
- `PERMISSION_DENIED`: Insufficient permissions
- `RATE_LIMITED`: Too many requests

## Security Boundaries

### Scope Enforcement
```json
{
  "project_root": "/home/user/project",
  "allowed_paths": [
    "/home/user/project/**/*"
  ],
  "denied_paths": [
    "/etc/**",
    "/usr/**",
    "/var/**",
    "/**/.ssh/**"
  ],
  "network_boundaries": {
    "allowed_networks": [
      "172.29.0.0/16",  // Docker project network
      "172.17.0.0/16",  // Docker bridge
      "127.0.0.1/32",   // Localhost
      "::1/128"         // IPv6 localhost
    ],
    "blocked_networks": [
      "0.0.0.0/8",
      "10.0.0.0/8",     // Unless explicitly in project
      "192.168.0.0/16", // Unless explicitly in project
      "169.254.0.0/16"
    ],
    "max_concurrent_connections": 100,
    "scan_rate_limit": "1000/second"
  },
  "container_isolation": {
    "network_mode": "bridge",
    "capabilities_dropped": ["ALL"],
    "capabilities_added": ["NET_RAW", "NET_ADMIN"],
    "read_only_root": true,
    "no_new_privileges": true
  }
}
```

### Token Budget
```json
{
  "max_tokens_per_scan": 1000,
  "max_tokens_per_minute": 5000,
  "max_tokens_per_hour": 50000
}
```

## Webhook Events

### scan.completed
```json
{
  "event": "scan.completed",
  "data": {
    "scan_id": "scan_123456",
    "status": "success",
    "findings_count": 15
  }
}
```

### compliance.failed
```json
{
  "event": "compliance.failed",
  "data": {
    "framework": "OWASP",
    "failures": ["A01", "A06"]
  }
}
```

## Rate Limiting

### Limits
- 10 scans per minute
- 100 scans per hour
- 1000 scans per day

### Headers
```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1704110400
```

## Authentication

### API Key
```
Authorization: Bearer mcp_shamash_key_xxxxx
```

### Permissions
```json
{
  "permissions": {
    "scan": ["read", "write"],
    "compliance": ["read"],
    "remediation": ["read"]
  }
}
```

## Versioning

### API Version
```
Accept: application/vnd.shamash.v1+json
```

### Compatibility
- Backward compatible within major version
- Deprecation notices 30 days before removal
- Version sunset after 6 months

## Integration Examples

### TypeScript Client
```typescript
import { ShamashClient } from '@mcp/shamash';

const client = new ShamashClient({
  apiKey: process.env.SHAMASH_API_KEY
});

const result = await client.scanProject({
  path: './my-project',
  profile: 'standard'
});
```

### Python Client
```python
from mcp_shamash import ShamashClient

client = ShamashClient(api_key=os.environ['SHAMASH_API_KEY'])

result = client.scan_project(
    path='./my-project',
    profile='standard'
)
```

## Performance SLA

### Response Times
- Simple scan: <1s
- Full scan: <10s
- Compliance check: <5s

### Availability
- 99.9% uptime SLA
- Graceful degradation
- Circuit breaker pattern

## Monitoring

### Metrics Exposed
- `shamash_scans_total`
- `shamash_scan_duration_seconds`
- `shamash_findings_total`
- `shamash_token_usage`
- `shamash_errors_total`

### Health Check
```
GET /health

{
  "status": "healthy",
  "version": "1.0.0",
  "tools": {
    "semgrep": "operational",
    "trivy": "operational"
  }
}
```