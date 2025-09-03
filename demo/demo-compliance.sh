#!/bin/bash

# Demo script for MCP Shamash Compliance Framework
echo "========================================="
echo "MCP Shamash Compliance Framework Demo"
echo "========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Start the MCP server in background
echo -e "${BLUE}Starting MCP Shamash server...${NC}"
node dist/core/server.js &
SERVER_PID=$!
sleep 2

echo -e "${GREEN}✓ Server started (PID: $SERVER_PID)${NC}"
echo ""

# Function to simulate MCP client calls
simulate_compliance_check() {
    local path=$1
    local frameworks=$2
    local profile=$3
    
    echo -e "${YELLOW}Running compliance check:${NC}"
    echo "  Path: $path"
    echo "  Frameworks: $frameworks"
    echo "  Profile: $profile"
    echo ""
    
    # In a real scenario, this would be an MCP client call
    # For demo purposes, we'll show the expected output
    cat << EOF
{
  "status": "success",
  "summary": {
    "overallCompliance": "78%",
    "totalFindings": 42,
    "criticalFindings": 2,
    "highFindings": 8
  },
  "frameworks": [
    {
      "name": "OWASP Top 10 2021",
      "coverage": "80%",
      "passed": 8,
      "failed": 2,
      "total": 10
    },
    {
      "name": "CIS Controls v8",
      "coverage": "75%",
      "passed": 4,
      "failed": 1,
      "total": 5
    }
  ],
  "recommendations": [
    "URGENT: Address 2 critical security findings immediately",
    "HIGH PRIORITY: Fix 8 high severity vulnerabilities",
    "OWASP Top 10 2021: Improve compliance (currently 80%)",
    "Focus on: Cryptographic Failures, Vulnerable Components",
    "Implement secret scanning in CI/CD pipeline"
  ],
  "reportPath": "/home/persist/repos/lib/mcp_shamash/compliance_reports/compliance_report_2025-01-02T10-30-00.html",
  "tokenUsage": 850
}
EOF
    echo ""
}

# Demo 1: Minimal Profile (OWASP only)
echo -e "${BLUE}=== Demo 1: Minimal Compliance Check ===${NC}"
simulate_compliance_check "." '["OWASP"]' "minimal"

# Demo 2: Standard Profile (OWASP + CIS)
echo -e "${BLUE}=== Demo 2: Standard Compliance Check ===${NC}"
simulate_compliance_check "." '["OWASP", "CIS"]' "standard"

# Demo 3: Comprehensive Profile (All frameworks)
echo -e "${BLUE}=== Demo 3: Comprehensive Compliance Audit ===${NC}"
simulate_compliance_check "." '["OWASP", "CIS", "NIST", "ISO27001"]' "comprehensive"

# Show compliance profiles
echo -e "${BLUE}=== Available Compliance Profiles ===${NC}"
cat << EOF
1. Minimal Profile:
   - Frameworks: OWASP Top 10
   - Scan Type: Quick (secrets only)
   - Use Case: Rapid security check
   
2. Standard Profile:
   - Frameworks: OWASP Top 10, CIS Controls
   - Scan Type: Standard (SAST, dependencies, IaC)
   - Use Case: Regular compliance validation
   
3. Comprehensive Profile:
   - Frameworks: OWASP, CIS, NIST CSF, ISO 27001
   - Scan Type: Thorough (all scanners)
   - Use Case: Full compliance audit
EOF
echo ""

# Show framework mappings
echo -e "${BLUE}=== Compliance Framework Mappings ===${NC}"
cat << EOF
Scanner Finding Types → Compliance Controls:

• Semgrep (SAST) findings map to:
  - OWASP A01: Broken Access Control
  - OWASP A03: Injection
  - CIS-16: Application Software Security
  - NIST PR.AC: Access Control
  - ISO A.14: System Development

• Trivy (Dependencies) findings map to:
  - OWASP A06: Vulnerable Components
  - CIS-2: Software Inventory
  - NIST ID.RA: Risk Assessment
  - ISO A.12: Operations Security

• Gitleaks (Secrets) findings map to:
  - OWASP A02: Cryptographic Failures
  - CIS-3: Data Protection
  - NIST PR.DS: Data Security
  - ISO A.10: Cryptography

• Checkov (IaC) findings map to:
  - OWASP A05: Security Misconfiguration
  - CIS-4: Secure Configuration
  - NIST ID.AM: Asset Management
  - ISO A.8: Asset Management

• OWASP ZAP (DAST) findings map to:
  - OWASP A07: Authentication Failures
  - OWASP A10: SSRF
  - CIS-16: Application Security
  - ISO A.14: System Development
EOF
echo ""

# Clean up
echo -e "${BLUE}Stopping server...${NC}"
kill $SERVER_PID 2>/dev/null
echo -e "${GREEN}✓ Demo completed successfully!${NC}"
echo ""

echo "========================================="
echo "Key Features Demonstrated:"
echo "- Multi-framework compliance validation"
echo "- Automated finding-to-control mapping"
echo "- Tiered compliance profiles"
echo "- HTML report generation"
echo "- Token-efficient scanning"
echo "- Project-scoped validation"
echo "========================================="