# Security Tools Research - MCP Shamash

## Executive Summary
Comprehensive analysis of opensource security tools suitable for integration into MCP Shamash, focusing on project-scoped, token-efficient, containerizable solutions.

## Top Opensource Security Tools

### 1. Static Application Security Testing (SAST)

#### Semgrep
- **Language Support**: 30+ languages
- **Token Efficiency**: Rule-based, no AI required
- **Container Ready**: Yes, official Docker images
- **Project Scope**: Excellent, configurable paths
- **License**: LGPL-2.1
- **Key Features**: Custom rules, OWASP patterns, fast scanning

#### Bandit (Python)
- **Focus**: Python security linting
- **Token Efficiency**: Excellent, pattern matching
- **Container Ready**: Yes
- **Project Scope**: Built-in
- **License**: Apache-2.0

#### ESLint Security Plugins (JavaScript)
- **Focus**: JavaScript/TypeScript
- **Token Efficiency**: Excellent
- **Container Ready**: Yes via Node
- **Project Scope**: Config-based
- **License**: MIT

### 2. Dynamic Application Security Testing (DAST)

#### OWASP ZAP (Zed Attack Proxy)
- **Type**: Web app scanner
- **Token Efficiency**: API-driven, no AI needed
- **Container Ready**: Official Docker images
- **Project Scope**: Configurable contexts
- **License**: Apache-2.0
- **Note**: Can be configured for passive scanning only

#### Nuclei
- **Type**: Template-based scanner
- **Token Efficiency**: Excellent, template-driven
- **Container Ready**: Yes
- **Project Scope**: Target specification
- **License**: MIT
- **Key Features**: 5000+ templates, low false positives

### 3. Dependency Scanning

#### OWASP Dependency-Check
- **Coverage**: Java, .NET, Node.js, Python, Ruby
- **Token Efficiency**: Database lookups, no AI
- **Container Ready**: Yes
- **Project Scope**: Built-in
- **License**: Apache-2.0
- **Database**: NVD, NPM Audit, RetireJS

#### Trivy
- **Coverage**: Dependencies, containers, IaC
- **Token Efficiency**: Excellent
- **Container Ready**: Native
- **Project Scope**: Yes
- **License**: Apache-2.0
- **Key Features**: Fast, comprehensive, low memory

#### Safety (Python)
- **Focus**: Python dependencies
- **Token Efficiency**: DB lookups
- **Container Ready**: Yes
- **Project Scope**: Requirements.txt based
- **License**: MIT

### 4. Infrastructure as Code (IaC) Security

#### Checkov
- **Coverage**: Terraform, CloudFormation, Kubernetes, Docker
- **Token Efficiency**: Policy-based
- **Container Ready**: Yes
- **Project Scope**: Directory-based
- **License**: Apache-2.0

#### Terrascan
- **Coverage**: Terraform, Kubernetes, Helm, Docker
- **Token Efficiency**: Excellent
- **Container Ready**: Yes
- **Project Scope**: Configurable
- **License**: Apache-2.0

### 5. Container Security

#### Grype
- **Focus**: Container vulnerability scanning
- **Token Efficiency**: DB-based
- **Container Ready**: Native
- **Project Scope**: Image-specific
- **License**: Apache-2.0

#### Clair
- **Focus**: Container static analysis
- **Token Efficiency**: Good
- **Container Ready**: Yes
- **Project Scope**: Layer analysis
- **License**: Apache-2.0

### 6. Secrets Detection

#### Gitleaks
- **Focus**: Secret scanning in code
- **Token Efficiency**: Regex-based
- **Container Ready**: Yes
- **Project Scope**: Git-aware
- **License**: MIT

#### TruffleHog
- **Focus**: Secret detection with entropy
- **Token Efficiency**: Good
- **Container Ready**: Yes
- **Project Scope**: Repository-based
- **License**: AGPL-3.0

## Compliance Framework Tools

### OWASP Tools Suite
- **Dependency-Check**: Vulnerability identification
- **ZAP**: Web application testing
- **Amass**: Attack surface mapping (limited use)
- **ModSecurity**: WAF rules (reference)

### CIS Benchmark Tools
- **CIS-CAT Lite**: Free compliance scanner
- **Docker Bench**: Container security
- **Kubernetes Bench**: K8s security

### NIST Framework Tools
- **SCAP Compliance Checker**: NIST validation
- **OpenSCAP**: Security compliance

## Token-Efficient Architecture Recommendations

### 1. Tiered Scanning Approach
- **Level 1**: Fast pattern matching (Semgrep, Bandit)
- **Level 2**: Dependency checks (Trivy, Dependency-Check)
- **Level 3**: Detailed analysis (only if issues found)

### 2. Cache Strategy
- Vulnerability database caching
- Previous scan results
- Pattern match optimization

### 3. Selective AI Enhancement
- Use AI only for:
  - Result summarization
  - Remediation suggestions
  - False positive analysis
- Never for core scanning

## Container Integration Strategy

### 1. Tool Containers
- Individual containers per tool
- Shared volume for project code
- Results aggregation container

### 2. Orchestration
- Docker Compose for local
- Kubernetes for scale
- Podman for rootless

### 3. Security Boundaries
- Read-only project mount
- Network isolation
- Resource limits
- No privileged operations

## Recommended Tool Stack

### Core Tools (Must Have)
1. **Semgrep**: Multi-language SAST
2. **Trivy**: Comprehensive vulnerability scanning
3. **Gitleaks**: Secret detection
4. **Checkov**: IaC security

### Extended Tools (Nice to Have)
1. **Nuclei**: Template-based scanning
2. **OWASP Dependency-Check**: Deep dependency analysis
3. **Grype**: Container scanning
4. **Bandit**: Python-specific

### Integration Priority
1. Semgrep (broadest language coverage)
2. Trivy (dependencies + containers)
3. Gitleaks (critical for secrets)
4. Checkov (IaC coverage)

## Implementation Considerations

### 1. Tool Wrapper Design
```
Tool Wrapper
├── Input validation (scope check)
├── Tool execution (containerized)
├── Output parsing (standardized)
├── Token counting (budget enforcement)
└── Result caching (efficiency)
```

### 2. Result Aggregation
- Unified format (SARIF considered)
- Severity normalization
- Deduplication logic
- Priority scoring

### 3. Performance Optimization
- Parallel tool execution where safe
- Incremental scanning
- Smart file filtering
- Result caching

## Conclusion
The recommended stack provides comprehensive security coverage while maintaining strict token efficiency and project scope boundaries. All tools are containerizable and require zero AI for core operations.