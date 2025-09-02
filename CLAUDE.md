# MCP Shamash - Security Audit & Compliance Server

## Project Overview
**Name:** MCP Shamash
**Path:** /home/persist/repos/lib/mcp_shamash
**Description:** Model Context Protocol server for security audits, pentesting reviews, and compliance standards verification with scoped, containerized execution

## Core Requirements
1. **Scoped Operation**: Never scan entire system - project-scoped only
2. **Minimal AI Dependency**: Smart but not AI-heavy, token-efficient
3. **Containerization**: Support for isolated execution environments
4. **Industry Standards**: Meet OWASP, CIS, NIST, ISO 27001 compliance
5. **Agentic Capabilities**: Intelligent project scanning with constraints

## Key Constraints
- NO unauthorized system-wide scanning
- NO credential harvesting or malicious code assistance
- NO excessive token usage
- ONLY defensive security operations
- MUST be containerizable and scopeable

## Technology Stack (TBD)
- Language: TypeScript/Python (to be determined)
- MCP SDK for server implementation
- Security tools integration (to be researched)
- Container runtime support

## Project Phases
1. **Research Phase** (Current)
   - Identify top opensource security tools
   - Review compliance standards
   - Analyze token-efficient architectures
   
2. **Design Phase**
   - Architecture specification
   - API design
   - Security boundaries definition
   
3. **Implementation Phase**
   - Core MCP server
   - Tool integrations
   - Container support
   
4. **Testing Phase**
   - Security validation
   - Compliance verification
   - Performance testing

## Active Agents
- @agent-coordinator: Workflow orchestration
- @agent-researcher: Security tools research
- @agent-security_auditor: Compliance standards
- @agent-planner: Roadmap development
- @agent-api_designer: MCP API specification

## Rules & Guidelines
1. All security operations must be defensive only
2. Implement strict scope boundaries
3. Token usage optimization is critical
4. Follow OWASP secure coding practices
5. Maintain audit logs for all operations
6. Zero false positives tolerance
7. Container-first design approach

## Documentation Structure
- `./.claude/context/` - Project context and state
- `./.claude/agents/` - Agent specifications
- `./.claude/commands/` - Standardized procedures
- `./docs/` - User documentation
- `./specs/` - Technical specifications

## Success Criteria
- Industry-standard compliance validation
- Sub-second response times for basic scans
- <1000 tokens per audit operation
- Zero system-wide access attempts
- 100% containerizable
- Clear audit trails