# Sandbox Isolation Design - MCP Shamash

## Overview
Multi-layered sandbox architecture ensuring network scanning and pentesting operations remain strictly within project boundaries while providing comprehensive security testing capabilities.

## Core Isolation Principles

### 1. Defense in Depth
- Multiple independent isolation layers
- Failure of one layer doesn't compromise security
- Each layer enforces project boundaries

### 2. Least Privilege
- Minimal permissions for each operation
- Capability-based security model
- Time-limited access tokens

### 3. Zero Trust Network
- No implicit trust between components
- All network traffic validated
- Continuous boundary verification

## Isolation Architecture

### Layer 1: Container Network Isolation

```yaml
# Docker Compose Network Configuration
networks:
  shamash_sandbox:
    driver: bridge
    internal: true  # No external connectivity
    ipam:
      config:
        - subnet: 172.28.0.0/16
          ip_range: 172.28.5.0/24
  
  project_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.29.0.0/16
```

**Enforcement Rules:**
- Scanner containers ONLY access `project_network`
- No direct internet access from scanner containers
- All external requests proxied through boundary controller

### Layer 2: Linux Namespaces

```typescript
interface NamespaceConfig {
  network: {
    isolated: true,
    allowedSubnets: ["172.29.0.0/16"],  // Project network only
    blockedPorts: [22, 3389, 445],      // Management ports
    maxConnections: 1000
  },
  pid: {
    isolated: true,
    maxProcesses: 100
  },
  mount: {
    readonly: ["/", "/usr", "/bin"],
    writable: ["/tmp", "/var/shamash"],
    projectMount: "/scan/target"
  },
  user: {
    uid: 65534,  // nobody
    gid: 65534   // nogroup
  }
}
```

### Layer 3: Seccomp Filters

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["socket"],
      "action": "SCMP_ACT_ALLOW",
      "args": [
        {
          "index": 0,
          "value": 2,  // AF_INET only
          "op": "SCMP_CMP_EQ"
        }
      ]
    },
    {
      "names": ["connect", "bind"],
      "action": "SCMP_ACT_NOTIFY"  // Validate target
    },
    {
      "names": ["ptrace", "process_vm_readv", "process_vm_writev"],
      "action": "SCMP_ACT_ERRNO"  // Block debugging
    }
  ]
}
```

### Layer 4: Network Boundary Controller

```typescript
class NetworkBoundaryController {
  private projectCIDR: string;
  private allowedPorts: Set<number>;
  private connectionTracker: Map<string, ConnectionInfo>;
  
  async validateConnection(request: NetworkRequest): Promise<boolean> {
    // 1. Check target is within project CIDR
    if (!this.isInProjectNetwork(request.targetIP)) {
      this.logViolation("OUT_OF_SCOPE", request);
      return false;
    }
    
    // 2. Validate port is allowed for scanning
    if (!this.allowedPorts.has(request.targetPort)) {
      return false;
    }
    
    // 3. Check rate limits
    if (this.exceedsRateLimit(request.sourceContainer)) {
      return false;
    }
    
    // 4. Track connection for audit
    this.trackConnection(request);
    return true;
  }
  
  private isInProjectNetwork(ip: string): boolean {
    // Validate IP is within:
    // - Docker project network (172.29.0.0/16)
    // - Kubernetes cluster network
    // - localhost/loopback for local testing
    return this.ipInCIDR(ip, this.projectCIDR) || 
           this.isLoopback(ip) ||
           this.isDockerInternal(ip);
  }
}
```

### Layer 5: Resource Limits (cgroups)

```yaml
# Resource constraints per scanner container
resources:
  limits:
    memory: 2G
    cpus: '2.0'
    pids: 200
  reservations:
    memory: 512M
    cpus: '0.5'
  
  # Network bandwidth limits
  networks:
    - shamash_sandbox:
        priority: 100
        rate: 10mb  # 10 Mbps max
```

## Project Scope Detection

### Automatic Service Discovery

```typescript
class ProjectScopeDetector {
  async detectProjectBoundaries(): Promise<ProjectScope> {
    const scope: ProjectScope = {
      networks: [],
      services: [],
      ports: [],
      excludes: []
    };
    
    // 1. Docker Compose Detection
    if (await this.hasDockerCompose()) {
      const compose = await this.parseDockerCompose();
      scope.networks.push(...compose.networks);
      scope.services.push(...compose.services);
    }
    
    // 2. Kubernetes Detection
    if (await this.hasKubernetesManifests()) {
      const k8s = await this.parseK8sServices();
      scope.services.push(...k8s.services);
      scope.networks.push(k8s.clusterCIDR);
    }
    
    // 3. Local Application Detection
    const localPorts = await this.scanLocalPorts();
    scope.ports.push(...localPorts.filter(p => p > 1024));
    
    // 4. Explicit Excludes (never scan)
    scope.excludes = [
      '0.0.0.0/8',      // Current network
      '10.0.0.0/8',     // Private network (unless project)
      '192.168.0.0/16', // Private network (unless project)
      '169.254.0.0/16', // Link-local
      '224.0.0.0/4'     // Multicast
    ];
    
    return scope;
  }
}
```

## Scanner Integration

### OWASP ZAP Sandboxed Configuration

```typescript
class ZAPSandbox {
  private readonly config = {
    container: {
      image: 'owasp/zap2docker-stable:2.14.0',
      network: 'shamash_sandbox',
      securityOpt: [
        'no-new-privileges:true',
        'apparmor:docker-shamash-zap'
      ],
      capDrop: ['ALL'],
      capAdd: ['NET_RAW'],  // For packet capture only
      readOnlyRootfs: true,
      tmpfs: ['/tmp', '/zap/wrk']
    },
    
    zapConfig: {
      api: {
        addrs: ['127.0.0.1'],
        port: 8090,
        key: generateSecureKey()
      },
      proxy: {
        enabled: false  // No proxy mode
      },
      scanner: {
        maxScanDurationMins: 30,
        maxScansInUI: 5,
        threadPerHost: 2
      }
    }
  };
  
  async scan(target: string): Promise<ScanResult> {
    // Validate target is in project scope
    if (!await this.boundaryController.validateTarget(target)) {
      throw new Error('Target outside project scope');
    }
    
    // Launch sandboxed ZAP container
    const container = await this.launchContainer();
    
    // Configure scan policies
    await this.configurePolicies(container, {
      attackStrength: 'MEDIUM',
      alertThreshold: 'LOW',
      technologies: this.detectTechnologies(target)
    });
    
    // Execute scan with monitoring
    return await this.executeMonitoredScan(container, target);
  }
}
```

### Nmap Sandboxed Configuration

```typescript
class NmapSandbox {
  private readonly config = {
    container: {
      image: 'instrumentisto/nmap:7.94',
      network: 'shamash_sandbox',
      capDrop: ['ALL'],
      capAdd: ['NET_RAW', 'NET_ADMIN'],  // Required for SYN scan
      readOnlyRootfs: true
    },
    
    nmapFlags: {
      required: [
        '--unprivileged',     // No privileged operations
        '--max-rtt-timeout=100ms',  // Fast timeout
        '--max-retries=1',    // Minimal retries
        '--max-hostgroup=10'  // Small batches
      ],
      forbidden: [
        '--script',  // No NSE scripts (can escape)
        '-iL',       // No file input
        '-oG',       // No greppable output (file write)
        '--resume'   // No state files
      ]
    }
  };
  
  async scanNetwork(cidr: string): Promise<NetworkScan> {
    // Validate CIDR is project network
    if (!this.isProjectNetwork(cidr)) {
      throw new Error('Network outside project scope');
    }
    
    // Build safe nmap command
    const command = this.buildSafeCommand(cidr, {
      scanType: '-sT',  // TCP connect (safer in container)
      ports: '-p1-65535',
      timing: '-T4'
    });
    
    return await this.executeScan(command);
  }
}
```

## Enforcement Mechanisms

### Pre-Scan Validation

```typescript
async function validateScanRequest(request: ScanRequest): Promise<ValidationResult> {
  const checks = [
    validateProjectPath(request.targetPath),
    validateNetworkScope(request.targetNetwork),
    validateResourceLimits(request.expectedResources),
    validateTimeWindow(request.duration),
    validateUserPermissions(request.userId)
  ];
  
  const results = await Promise.all(checks);
  
  if (results.some(r => !r.valid)) {
    return {
      allowed: false,
      reason: results.filter(r => !r.valid).map(r => r.reason)
    };
  }
  
  return { allowed: true };
}
```

### Runtime Monitoring

```typescript
class SandboxMonitor {
  private violations: Map<string, Violation[]> = new Map();
  
  async monitorContainer(containerId: string): Promise<void> {
    // Network traffic monitoring
    this.monitorNetworkTraffic(containerId, (packet) => {
      if (!this.isAllowedTarget(packet.destination)) {
        this.handleViolation(containerId, 'NETWORK_ESCAPE', packet);
      }
    });
    
    // Syscall monitoring
    this.monitorSyscalls(containerId, (syscall) => {
      if (this.isDangerousSyscall(syscall)) {
        this.handleViolation(containerId, 'DANGEROUS_SYSCALL', syscall);
      }
    });
    
    // Resource monitoring
    this.monitorResources(containerId, (usage) => {
      if (usage.memory > this.limits.memory) {
        this.killContainer(containerId, 'MEMORY_EXCEEDED');
      }
    });
  }
  
  private handleViolation(containerId: string, type: string, data: any): void {
    // Log violation
    this.logViolation(containerId, type, data);
    
    // Immediate termination for critical violations
    if (this.isCriticalViolation(type)) {
      this.killContainer(containerId, type);
    }
    
    // Alert administrators
    this.sendAlert({
      severity: 'HIGH',
      container: containerId,
      violation: type,
      timestamp: Date.now()
    });
  }
}
```

## Testing Strategy

### Boundary Testing Suite

```typescript
describe('Sandbox Boundary Enforcement', () => {
  test('Should block external network access', async () => {
    const scanner = new SandboxedScanner();
    
    // Attempt to scan external IP
    await expect(scanner.scan('8.8.8.8')).rejects.toThrow('Target outside project scope');
    
    // Verify no packets sent
    const packets = await networkMonitor.getCapturedPackets();
    expect(packets.filter(p => p.dest === '8.8.8.8')).toHaveLength(0);
  });
  
  test('Should enforce resource limits', async () => {
    const scanner = new SandboxedScanner();
    
    // Create memory bomb payload
    const memoryBomb = generateLargePayload(3000); // 3GB
    
    // Scanner should be killed before consuming 3GB
    const result = await scanner.scan(memoryBomb);
    expect(result.status).toBe('KILLED');
    expect(result.reason).toBe('MEMORY_EXCEEDED');
  });
  
  test('Should detect and block privilege escalation', async () => {
    const scanner = new SandboxedScanner();
    
    // Attempt privilege escalation
    const exploit = createPrivEscPayload();
    
    await expect(scanner.scan(exploit)).rejects.toThrow('DANGEROUS_SYSCALL');
    
    // Verify container terminated
    const containerStatus = await docker.getContainer(scanner.id).inspect();
    expect(containerStatus.State.Running).toBe(false);
  });
});
```

## Compliance Verification

### Security Standards Alignment

| Standard | Requirement | Implementation |
|----------|------------|----------------|
| OWASP | Input validation | All network targets validated |
| NIST CSF | Boundary protection | Multi-layer isolation |
| CIS Controls | Network segmentation | Container network isolation |
| ISO 27001 | Access control | RBAC + capability model |
| PCI DSS | Network isolation | Segregated scanner networks |

## Conclusion

This sandbox design provides comprehensive isolation for network scanning and pentesting operations while maintaining strict project boundaries. The multi-layered approach ensures that even if one isolation mechanism fails, others prevent escape from the project scope.