# MCP Shamash Security Server - API Documentation

**Version**: 1.0.0  
**Protocol**: Model Context Protocol (MCP)  
**Last Updated**: 2025-09-02  
**Sprint**: 6 - Production Ready  

## Overview

The MCP Shamash Security Server provides comprehensive security scanning capabilities through the Model Context Protocol (MCP). It integrates 9 industry-standard security tools plus a custom rule engine to deliver thorough security analysis across multiple domains including SAST, dependency scanning, secrets detection, infrastructure analysis, and custom pattern matching.

### Key Features
- **9 Integrated Security Scanners**: Complete security coverage
- **Custom Rule Engine**: 5 default rules with full CRUD management
- **Compliance Frameworks**: OWASP, CIS, NIST, ISO 27001 support
- **Advanced Features**: Incremental scanning, remediation advice, false positive filtering
- **Production Ready**: High performance, containerized execution

## MCP Server Information

```json
{
  "name": "shamash",
  "version": "1.0.0",
  "capabilities": {
    "tools": {},
    "resources": {},
    "prompts": {}
  }
}
```

## Tools API

The server provides 7 comprehensive security tools accessible via MCP protocol:

### 1. scan_project

**Description**: Performs comprehensive security scan on project directory using multiple security scanners.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Project path to scan",
      "required": true
    },
    "profile": {
      "type": "string",
      "enum": ["quick", "standard", "thorough"],
      "description": "Scan profile determining tool selection",
      "default": "standard"
    },
    "tools": {
      "type": "array",
      "items": {"type": "string"},
      "description": "Specific tools to use (overrides profile)"
    },
    "incremental": {
      "type": "boolean",
      "description": "Use incremental scanning if available",
      "default": false
    }
  },
  "required": ["path"]
}
```

**Scanner Tool Options**:
- `semgrep` - Static Application Security Testing (SAST)
- `trivy` - Dependency vulnerability scanning
- `gitleaks` - Secret and credential detection
- `checkov` - Infrastructure-as-Code security validation
- `nuclei` - Template-based vulnerability scanning
- `bandit` - Python-specific SAST analysis
- `grype` - Container and dependency vulnerability scanning
- `owasp_dependency_check` - Comprehensive dependency analysis
- `custom_rules` - Custom pattern-based security rules

**Scan Profiles**:
- **quick**: `['gitleaks', 'custom_rules']` - Fast secret and pattern detection
- **standard**: `['semgrep', 'trivy', 'checkov', 'custom_rules']` - Balanced coverage
- **thorough**: `['semgrep', 'trivy', 'gitleaks', 'checkov', 'nuclei', 'bandit', 'grype', 'owasp_dependency_check', 'custom_rules']` - Complete coverage

**Response Format**:
```json
{
  "scanId": "scan_1704067200000_abc123def",
  "status": "success|partial|failed", 
  "summary": {
    "vulnerabilities": 15,
    "critical": 2,
    "high": 4,
    "medium": 6,
    "low": 2,
    "informational": 1
  },
  "findings": [
    {
      "id": "semgrep_rule_id_123",
      "type": "sast|dependency|secret|infrastructure|vulnerability|custom",
      "severity": "critical|high|medium|low|informational",
      "title": "Finding title",
      "description": "Detailed description", 
      "location": {
        "file": "path/to/file.js",
        "line": 42,
        "column": 15
      },
      "cve": "CVE-2023-12345",
      "cvssScore": 8.5,
      "remediation": "Recommended fix"
    }
  ],
  "tokenUsage": 450,
  "scanTimeMs": 12500,
  "errors": ["Optional error messages"]
}
```

**Example Usage**:
```json
{
  "name": "scan_project",
  "arguments": {
    "path": "/projects/my-app",
    "profile": "thorough",
    "incremental": true
  }
}
```

### 2. scan_network

**Description**: Performs network scanning within project boundaries for infrastructure assessment.

**Input Schema**:
```json
{
  "type": "object", 
  "properties": {
    "target": {
      "type": "string",
      "description": "Network target (IP, hostname, or range)",
      "required": true
    },
    "ports": {
      "type": "string", 
      "description": "Port range to scan (e.g., '1-1000', '80,443,8080')",
      "default": "1-65535"
    },
    "serviceDetection": {
      "type": "boolean",
      "description": "Enable service version detection",
      "default": true
    }
  },
  "required": ["target"]
}
```

**Example Usage**:
```json
{
  "name": "scan_network",
  "arguments": {
    "target": "localhost",
    "ports": "80,443,8080-8090",
    "serviceDetection": true
  }
}
```

### 3. pentest_application

**Description**: Performs penetration testing on deployed applications using OWASP ZAP.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "targetUrl": {
      "type": "string", 
      "description": "Application URL to test",
      "required": true
    },
    "testTypes": {
      "type": "array",
      "items": {"type": "string"},
      "description": "Types of penetration tests to perform"
    },
    "depth": {
      "type": "string",
      "enum": ["quick", "standard", "thorough"],
      "description": "Testing depth and coverage",
      "default": "standard"
    }
  },
  "required": ["targetUrl"]
}
```

**Example Usage**:
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

### 4. check_compliance

**Description**: Validates project against multiple compliance frameworks (OWASP, CIS, NIST, ISO 27001).

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Project path to validate",
      "required": true
    },
    "frameworks": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": ["OWASP", "CIS", "NIST", "ISO27001"]
      },
      "description": "Compliance frameworks to validate against",
      "required": true
    },
    "profile": {
      "type": "string", 
      "enum": ["minimal", "standard", "comprehensive"],
      "description": "Compliance check depth",
      "default": "standard"
    }
  },
  "required": ["path", "frameworks"]
}
```

**Response Format**:
```json
{
  "status": "success",
  "summary": {
    "overallCompliance": "78%",
    "totalFindings": 25,
    "criticalFindings": 3,
    "highFindings": 8
  },
  "frameworks": [
    {
      "name": "OWASP Top 10 2021",
      "coverage": "85%", 
      "passed": 17,
      "failed": 3,
      "total": 20
    }
  ],
  "recommendations": ["Update dependencies", "Fix authentication"],
  "reportPath": "/tmp/compliance-report.html",
  "tokenUsage": 350
}
```

**Example Usage**:
```json
{
  "name": "check_compliance",
  "arguments": {
    "path": "/projects/my-app",
    "frameworks": ["OWASP", "NIST"],
    "profile": "comprehensive"
  }
}
```

### 5. generate_remediation

**Description**: Generate actionable remediation advice for security findings.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "findingIds": {
      "type": "array",
      "items": {"type": "string"},
      "description": "IDs of findings to generate remediation for"
    }
  },
  "required": []
}
```

**Response Format**:
```json
{
  "status": "success",
  "remediations": 5,
  "summary": {
    "criticalFixes": 2,
    "quickWins": 3,
    "estimatedHours": 8.5
  },
  "report": "# Remediation Plan\n\n## Critical Issues\n..."
}
```

### 6. manage_false_positives

**Description**: Manage false positive suppressions to reduce noise in scan results.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "action": {
      "type": "string",
      "enum": ["add", "remove", "list", "filter"],
      "description": "Action to perform",
      "required": true
    },
    "findingId": {
      "type": "string",
      "description": "Finding ID to suppress (for add/remove)"
    },
    "reason": {
      "type": "string", 
      "description": "Reason for suppression (for add)"
    }
  },
  "required": ["action"]
}
```

**Example Usage**:
```json
{
  "name": "manage_false_positives",
  "arguments": {
    "action": "add",
    "findingId": "semgrep_rule_123",
    "reason": "False positive - test file"
  }
}
```

### 7. manage_custom_rules

**Description**: Manage custom security rules with full CRUD operations.

**Input Schema**:
```json
{
  "type": "object",
  "properties": {
    "action": {
      "type": "string",
      "enum": ["list", "add", "update", "remove", "enable", "disable", "stats", "validate"],
      "description": "Action to perform",
      "required": true
    },
    "ruleId": {
      "type": "string",
      "description": "Rule ID for update/remove/enable/disable operations"
    },
    "rule": {
      "type": "object",
      "description": "Rule definition for add/update operations",
      "properties": {
        "name": {"type": "string", "description": "Rule name"},
        "description": {"type": "string", "description": "Rule description"},
        "severity": {
          "type": "string",
          "enum": ["critical", "high", "medium", "low", "informational"],
          "description": "Finding severity level"
        },
        "category": {
          "type": "string", 
          "enum": ["security", "performance", "maintainability", "style"],
          "description": "Rule category"
        },
        "pattern": {
          "type": "string",
          "description": "Regular expression pattern to match"
        },
        "filePatterns": {
          "type": "array",
          "items": {"type": "string"},
          "description": "File patterns to include (e.g., ['*.js', '*.ts'])"
        },
        "excludePatterns": {
          "type": "array", 
          "items": {"type": "string"},
          "description": "Paths to exclude from scanning"
        },
        "messageTemplate": {
          "type": "string",
          "description": "Message template with {matchedText} placeholder"
        },
        "remediation": {
          "type": "string",
          "description": "Remediation guidance"
        },
        "references": {
          "type": "array",
          "items": {"type": "string"},
          "description": "Reference URLs for more information"
        },
        "enabled": {
          "type": "boolean",
          "description": "Whether rule is enabled"
        },
        "createdBy": {
          "type": "string", 
          "description": "Rule creator identifier"
        }
      }
    }
  },
  "required": ["action"]
}
```

**Default Custom Rules**:

1. **Hardcoded API Key Detection**
   - **Pattern**: `(api[_-]?key|apikey)\\s*[=:]\\s*["\'][a-zA-Z0-9]{20,}["\']`
   - **Severity**: High
   - **Files**: `*.js, *.ts, *.py, *.java, *.go`

2. **Weak Password Hashing**
   - **Pattern**: `(md5|sha1)\\s*\\(`
   - **Severity**: High
   - **Files**: `*.js, *.ts, *.py, *.java, *.php`

3. **Console Log in Production**
   - **Pattern**: `console\\.(log|debug|info)\\s*\\(`
   - **Severity**: Low
   - **Files**: `*.js, *.ts`

4. **SQL Injection Risk** 
   - **Pattern**: `(query|execute)\\s*\\(\\s*["\'][^"\']*\\+`
   - **Severity**: Critical
   - **Files**: `*.js, *.ts, *.py, *.java, *.php`

5. **Insecure Random Number Generation**
   - **Pattern**: `(Math\\.random|random\\.randint|rand\\()`
   - **Severity**: Medium
   - **Files**: `*.js, *.ts, *.py, *.java`

**Example Operations**:

**List all rules**:
```json
{
  "name": "manage_custom_rules",
  "arguments": {"action": "list"}
}
```

**Add new rule**:
```json
{
  "name": "manage_custom_rules", 
  "arguments": {
    "action": "add",
    "rule": {
      "name": "Hardcoded Password",
      "description": "Detects hardcoded passwords in source code",
      "severity": "high",
      "category": "security", 
      "pattern": "password\\s*[=:]\\s*[\"'][^\"']+[\"']",
      "filePatterns": ["*.js", "*.ts", "*.py"],
      "messageTemplate": "Hardcoded password detected: {matchedText}",
      "remediation": "Move password to environment variable",
      "enabled": true
    }
  }
}
```

**Get rule statistics**:
```json
{
  "name": "manage_custom_rules",
  "arguments": {"action": "stats"}
}
```

**Response Format**:
```json
{
  "status": "success",
  "stats": {
    "totalRules": 5,
    "enabledRules": 5,
    "disabledRules": 0,
    "categoryCounts": {
      "security": 4,
      "maintainability": 1
    },
    "severityCounts": {
      "critical": 1,
      "high": 2, 
      "medium": 1,
      "low": 1
    }
  }
}
```

## Resources API

### shamash://scan-results

**Description**: Access detailed scan results from recent operations.

**MIME Type**: `application/json`

**Usage**:
```json
{
  "uri": "shamash://scan-results",
  "method": "read"
}
```

### shamash://compliance-reports

**Description**: Access compliance validation reports in JSON format.

**MIME Type**: `application/json`

**Usage**:
```json
{
  "uri": "shamash://compliance-reports", 
  "method": "read"
}
```

## Prompts API

### security_review

**Description**: Comprehensive security review prompt for project assessment.

**Arguments**:
- `project_path` (required): Path to project for review

**Usage**:
```json
{
  "name": "security_review",
  "arguments": {
    "project_path": "/projects/my-application"
  }
}
```

## Performance Characteristics

### Response Times
- **Quick Scan**: 5-15 seconds
- **Standard Scan**: 30-90 seconds  
- **Thorough Scan**: 2-10 minutes
- **Custom Rules**: <5ms processing time
- **Compliance Check**: 1-3 minutes

### Resource Usage
- **Memory**: <512MB during scanning
- **CPU**: 1-2 cores maximum
- **Token Budget**: <1000 tokens per operation
- **Disk**: Temporary files cleaned automatically

### Concurrency
- **Parallel Scanner Execution**: Up to 3 concurrent scanners
- **Request Handling**: Single-threaded MCP server
- **Cache Hit Rate**: 60-80% for repeat scans

## Error Handling

### Common Error Codes

- `InvalidRequest`: Invalid parameters or malformed requests
- `MethodNotFound`: Unknown tool or resource name
- `InternalError`: Scanner execution or processing failures
- `Timeout`: Operation exceeded time limits
- `ResourceExhausted`: Token budget or resource limits exceeded

### Error Response Format
```json
{
  "error": {
    "code": "InvalidRequest",
    "message": "Path validation failed: boundary violation",
    "details": {
      "parameter": "path",
      "value": "/invalid/path"
    }
  }
}
```

## Security Considerations

### Boundary Enforcement
- All operations restricted to project scope
- Path traversal protection
- Network access limited to project boundaries
- URL validation for pentest targets

### Container Security
- All scanners run in isolated Docker containers
- Resource limits enforced (CPU, memory, processes)
- Network isolation for scanner execution
- Temporary file cleanup

### Input Validation
- Parameter type and format validation
- File path sanitization
- URL validation for external targets
- Custom rule pattern validation

## Integration Examples

### Basic Project Scan
```typescript
const scanResult = await mcp.callTool('scan_project', {
  path: '/path/to/project',
  profile: 'standard'
});

console.log(`Found ${scanResult.summary.vulnerabilities} issues`);
```

### Comprehensive Security Assessment
```typescript
// 1. Full project scan
const scanResults = await mcp.callTool('scan_project', {
  path: '/path/to/project', 
  profile: 'thorough'
});

// 2. Compliance validation
const compliance = await mcp.callTool('check_compliance', {
  path: '/path/to/project',
  frameworks: ['OWASP', 'CIS', 'NIST'],
  profile: 'comprehensive'
});

// 3. Generate remediation plan
const remediation = await mcp.callTool('generate_remediation', {
  findingIds: scanResults.findings.slice(0, 10).map(f => f.id)
});
```

### Custom Rule Management
```typescript
// Add custom rule
await mcp.callTool('manage_custom_rules', {
  action: 'add',
  rule: {
    name: 'Debug Code Detection',
    pattern: 'console\\.log\\(.*debug.*\\)',
    severity: 'low',
    category: 'maintainability',
    filePatterns: ['*.js', '*.ts'],
    messageTemplate: 'Debug code detected: {matchedText}',
    remediation: 'Remove debug statements before production',
    enabled: true
  }
});

// Run scan with custom rules
const results = await mcp.callTool('scan_project', {
  path: '/path/to/project',
  tools: ['custom_rules']
});
```

## Rate Limits and Quotas

- **Token Budget**: 1000 tokens per operation (tracked automatically)
- **Concurrent Requests**: 1 request at a time per MCP connection
- **Scan Frequency**: No artificial limits (cached results optimize performance)
- **Resource Cleanup**: Automatic cleanup of temporary files and containers

## Changelog

### Version 1.0.0 (Sprint 6)
- ✅ Added 4 additional security scanners (Nuclei, Bandit, Grype, OWASP Dependency-Check)
- ✅ Implemented custom rule engine with 5 default rules
- ✅ Added custom rule CRUD management API
- ✅ Enhanced MCP server with all 7 tools
- ✅ Production performance optimization
- ✅ Comprehensive documentation update

### Previous Versions
- **Sprint 5**: Advanced features (incremental scanning, remediation, false positives)  
- **Sprint 4**: Compliance framework integration
- **Sprint 3**: Core security tool integration (Semgrep, Trivy, Gitleaks, Checkov)
- **Sprint 1-2**: Foundation and MCP server implementation

---

**Documentation Version**: 1.0.0  
**API Stability**: Stable - Production Ready  
**Support**: Internal security team  
**Next Update**: Post-production feedback integration