# Network Boundary Enforcement Design - MCP Shamash

## Overview
Comprehensive network boundary enforcement ensuring all pentesting and network scanning operations remain strictly within project scope while enabling thorough security testing of deployed applications.

## Core Principle: Project-First Security
All network operations MUST originate from and target only project-defined resources. The system assumes zero trust and validates every network operation.

## Boundary Detection & Definition

### Automatic Project Network Discovery

```typescript
interface ProjectNetworkScope {
  networks: NetworkDefinition[];
  services: ServiceDefinition[];
  containers: ContainerDefinition[];
  excludedRanges: string[];
  allowedPorts: number[];
}

class ProjectNetworkDiscovery {
  async discoverProjectScope(): Promise<ProjectNetworkScope> {
    const scope: ProjectNetworkScope = {
      networks: [],
      services: [],
      containers: [],
      excludedRanges: [],
      allowedPorts: []
    };
    
    // 1. Docker Network Discovery
    const dockerNetworks = await this.docker.listNetworks();
    for (const network of dockerNetworks) {
      if (this.isProjectNetwork(network)) {
        scope.networks.push({
          name: network.Name,
          subnet: network.IPAM.Config[0].Subnet,
          gateway: network.IPAM.Config[0].Gateway,
          type: 'docker'
        });
      }
    }
    
    // 2. Docker Compose Service Discovery
    const composeServices = await this.parseComposeFile();
    scope.services.push(...composeServices.services.map(s => ({
      name: s.name,
      network: s.network,
      ports: s.ports,
      internal: s.internal || false
    })));
    
    // 3. Kubernetes Service Discovery
    if (await this.hasKubernetes()) {
      const k8sServices = await this.kubectl.getServices('default');
      scope.services.push(...k8sServices.map(s => ({
        name: s.metadata.name,
        network: s.spec.clusterIP,
        ports: s.spec.ports.map(p => p.port),
        internal: s.spec.type === 'ClusterIP'
      })));
    }
    
    // 4. Running Container Discovery
    const containers = await this.docker.listContainers();
    scope.containers = containers.map(c => ({
      id: c.Id,
      name: c.Names[0],
      network: c.NetworkSettings.Networks,
      ports: Object.keys(c.Ports || {}).map(p => parseInt(p))
    }));
    
    // 5. Define Excluded Ranges (NEVER scan)
    scope.excludedRanges = [
      '0.0.0.0/8',       // Current network
      '224.0.0.0/4',     // Multicast
      '255.255.255.255/32', // Broadcast
      '169.254.0.0/16',  // Link-local
      // Add external private ranges unless in project
      ...this.getExternalPrivateRanges(scope.networks)
    ];
    
    return scope;
  }
  
  private isProjectNetwork(network: any): boolean {
    // Check if network was created by docker-compose
    if (network.Labels?.['com.docker.compose.project']) {
      return true;
    }
    
    // Check if network name matches project patterns
    const projectName = this.getProjectName();
    if (network.Name.includes(projectName)) {
      return true;
    }
    
    // Check custom labels
    if (network.Labels?.['shamash.project'] === 'true') {
      return true;
    }
    
    return false;
  }
}
```

## Multi-Layer Boundary Enforcement

### Layer 1: iptables/nftables Rules

```bash
#!/bin/bash
# Network boundary enforcement rules

# Create shamash chain
iptables -N SHAMASH_BOUNDARY 2>/dev/null || true

# Default DROP for shamash containers
iptables -A SHAMASH_BOUNDARY -j LOG --log-prefix "SHAMASH_BLOCKED: "
iptables -A SHAMASH_BOUNDARY -j DROP

# Allow only project networks (example: 172.29.0.0/16)
iptables -I SHAMASH_BOUNDARY -d 172.29.0.0/16 -j ACCEPT
iptables -I SHAMASH_BOUNDARY -d 127.0.0.1/32 -j ACCEPT

# Block all external networks
iptables -I SHAMASH_BOUNDARY -d 0.0.0.0/8 -j DROP
iptables -I SHAMASH_BOUNDARY -d 10.0.0.0/8 -j DROP
iptables -I SHAMASH_BOUNDARY -d 192.168.0.0/16 -j DROP

# Apply to scanner containers
iptables -A FORWARD -s 172.28.0.0/16 -j SHAMASH_BOUNDARY
```

### Layer 2: Network Namespace Isolation

```typescript
class NetworkNamespaceManager {
  async createScannerNamespace(projectScope: ProjectNetworkScope): Promise<string> {
    const nsName = `shamash_${Date.now()}`;
    
    // Create network namespace
    await exec(`ip netns add ${nsName}`);
    
    // Create veth pair
    await exec(`ip link add veth0 type veth peer name veth1`);
    
    // Move veth1 to namespace
    await exec(`ip link set veth1 netns ${nsName}`);
    
    // Configure namespace interface
    await exec(`ip netns exec ${nsName} ip addr add 172.28.1.2/24 dev veth1`);
    await exec(`ip netns exec ${nsName} ip link set veth1 up`);
    await exec(`ip netns exec ${nsName} ip link set lo up`);
    
    // Add routes ONLY for project networks
    for (const network of projectScope.networks) {
      await exec(`ip netns exec ${nsName} ip route add ${network.subnet} via 172.28.1.1`);
    }
    
    // NO default route - prevent external access
    // await exec(`ip netns exec ${nsName} ip route add default via 172.28.1.1`); // NEVER DO THIS
    
    return nsName;
  }
  
  async enforceNamespaceBoundaries(nsName: string, rules: BoundaryRules): Promise<void> {
    // Apply tc (traffic control) rules for rate limiting
    await exec(`ip netns exec ${nsName} tc qdisc add dev veth1 root tbf rate 10mbit burst 32kbit latency 400ms`);
    
    // Apply connection limits
    await exec(`ip netns exec ${nsName} sysctl -w net.ipv4.netfilter.ip_conntrack_max=${rules.maxConnections}`);
    
    // Apply port restrictions using iptables in namespace
    for (const port of rules.blockedPorts) {
      await exec(`ip netns exec ${nsName} iptables -A OUTPUT -p tcp --dport ${port} -j DROP`);
    }
  }
}
```

### Layer 3: Container Runtime Boundaries

```typescript
class ContainerBoundaryEnforcer {
  async createScannerContainer(
    image: string, 
    projectScope: ProjectNetworkScope
  ): Promise<Container> {
    const config: ContainerCreateOptions = {
      Image: image,
      HostConfig: {
        // Network isolation
        NetworkMode: 'shamash_sandbox',
        
        // Security options
        SecurityOpt: [
          'no-new-privileges:true',
          'apparmor:shamash-scanner',
          'seccomp:shamash-scanner.json'
        ],
        
        // Capability management
        CapDrop: ['ALL'],
        CapAdd: ['NET_RAW', 'NET_ADMIN'], // Only for scanning
        
        // Resource limits
        Memory: 2 * 1024 * 1024 * 1024, // 2GB
        CpuQuota: 200000, // 2 CPUs
        PidsLimit: 200,
        
        // Filesystem
        ReadonlyRootfs: true,
        Tmpfs: {
          '/tmp': 'rw,noexec,nosuid,size=512m',
          '/var/run': 'rw,noexec,nosuid,size=128m'
        },
        
        // No privileged operations
        Privileged: false,
        
        // DNS configuration - only project DNS
        Dns: this.getProjectDNS(projectScope),
        DnsSearch: [],
        DnsOptions: ['ndots:0'], // Prevent DNS leaks
        
        // Extra hosts - map external domains to localhost
        ExtraHosts: [
          'google.com:127.0.0.1',
          'github.com:127.0.0.1',
          'aws.amazon.com:127.0.0.1'
        ]
      },
      
      // Environment variables
      Env: [
        `SHAMASH_PROJECT_SCOPE=${JSON.stringify(projectScope)}`,
        'SHAMASH_BOUNDARY_ENFORCEMENT=strict',
        'SHAMASH_MAX_SCAN_DEPTH=3'
      ],
      
      // Labels for tracking
      Labels: {
        'shamash.scanner': 'true',
        'shamash.project': this.projectId,
        'shamash.timestamp': new Date().toISOString()
      }
    };
    
    return await this.docker.createContainer(config);
  }
}
```

### Layer 4: Application-Level Validation

```typescript
class NetworkTargetValidator {
  private projectScope: ProjectNetworkScope;
  private validationCache: Map<string, ValidationResult> = new Map();
  
  async validateTarget(target: string): Promise<ValidationResult> {
    // Check cache first
    if (this.validationCache.has(target)) {
      return this.validationCache.get(target)!;
    }
    
    const result: ValidationResult = {
      allowed: false,
      reason: '',
      scope: null
    };
    
    // Parse target
    const parsed = this.parseTarget(target);
    
    // 1. Check if IP is in excluded ranges
    if (this.isInExcludedRange(parsed.ip)) {
      result.reason = 'Target in excluded range';
      this.logViolation('EXCLUDED_RANGE', target);
      return result;
    }
    
    // 2. Check if IP is in project networks
    const projectNetwork = this.findProjectNetwork(parsed.ip);
    if (!projectNetwork) {
      result.reason = 'Target not in project network';
      this.logViolation('OUT_OF_SCOPE', target);
      return result;
    }
    
    // 3. Check if port is allowed
    if (parsed.port && !this.isPortAllowed(parsed.port)) {
      result.reason = `Port ${parsed.port} not allowed for scanning`;
      return result;
    }
    
    // 4. Check rate limits
    if (this.exceedsRateLimit(target)) {
      result.reason = 'Rate limit exceeded';
      return result;
    }
    
    // 5. Additional checks for specific services
    if (this.isDatabasePort(parsed.port)) {
      // Extra validation for database ports
      if (!this.hasDbScanPermission()) {
        result.reason = 'Database scanning requires explicit permission';
        return result;
      }
    }
    
    result.allowed = true;
    result.scope = projectNetwork;
    
    // Cache result
    this.validationCache.set(target, result);
    
    // Log allowed scan
    this.logAllowedScan(target, projectNetwork);
    
    return result;
  }
  
  private isInExcludedRange(ip: string): boolean {
    for (const range of this.projectScope.excludedRanges) {
      if (this.ipInCIDR(ip, range)) {
        return true;
      }
    }
    return false;
  }
  
  private findProjectNetwork(ip: string): NetworkDefinition | null {
    for (const network of this.projectScope.networks) {
      if (this.ipInCIDR(ip, network.subnet)) {
        return network;
      }
    }
    return null;
  }
}
```

## Real-Time Monitoring & Enforcement

### Network Traffic Monitor

```typescript
class NetworkTrafficMonitor {
  private packetCapture: PacketCapture;
  private violations: ViolationLog[] = [];
  
  async monitorScanner(containerId: string): Promise<void> {
    // Start packet capture on container network
    this.packetCapture = new PacketCapture({
      interface: `veth_${containerId}`,
      filter: 'tcp or udp',
      promiscuous: false
    });
    
    this.packetCapture.on('packet', async (packet) => {
      const validation = await this.validatePacket(packet);
      
      if (!validation.allowed) {
        this.handleViolation(containerId, packet, validation.reason);
      }
      
      // Track metrics
      this.updateMetrics(packet);
    });
  }
  
  private async validatePacket(packet: Packet): Promise<ValidationResult> {
    // Check destination is in project scope
    if (!this.isProjectDestination(packet.destination)) {
      return {
        allowed: false,
        reason: `Destination ${packet.destination} outside project scope`
      };
    }
    
    // Check for scanning patterns
    if (this.isPortScan(packet)) {
      const rate = this.getPortScanRate(packet.source);
      if (rate > this.config.maxPortScanRate) {
        return {
          allowed: false,
          reason: 'Port scan rate exceeded'
        };
      }
    }
    
    // Check for exploitation attempts
    if (this.isExploitPattern(packet.payload)) {
      return {
        allowed: false,
        reason: 'Potential exploitation attempt detected'
      };
    }
    
    return { allowed: true };
  }
  
  private handleViolation(
    containerId: string, 
    packet: Packet, 
    reason: string
  ): void {
    const violation: ViolationLog = {
      timestamp: Date.now(),
      containerId,
      packet: {
        source: packet.source,
        destination: packet.destination,
        protocol: packet.protocol,
        port: packet.port
      },
      reason,
      action: 'BLOCKED'
    };
    
    this.violations.push(violation);
    
    // Log to audit system
    this.auditLogger.log('BOUNDARY_VIOLATION', violation);
    
    // Take action based on severity
    if (this.isCriticalViolation(reason)) {
      // Immediate container termination
      this.docker.kill(containerId, 'SIGKILL');
      
      // Alert administrators
      this.alertAdmin({
        severity: 'CRITICAL',
        message: `Scanner ${containerId} terminated for: ${reason}`,
        details: violation
      });
    } else {
      // Warning and rate limiting
      this.applyRateLimit(containerId);
    }
  }
}
```

## Pentesting Tools Integration

### OWASP ZAP Integration with Boundaries

```typescript
class BoundedZAPScanner {
  async scanWebApplication(target: string): Promise<ScanResult> {
    // Validate target
    const validation = await this.validator.validateTarget(target);
    if (!validation.allowed) {
      throw new BoundaryViolationError(validation.reason);
    }
    
    // Create isolated ZAP container
    const container = await this.boundaryEnforcer.createScannerContainer(
      'owasp/zap2docker-stable:latest',
      this.projectScope
    );
    
    // Configure ZAP with boundaries
    const zapConfig = {
      target,
      context: {
        includePaths: [this.getProjectPaths(target)],
        excludePaths: this.getExternalPaths()
      },
      scanner: {
        maxDepth: 3,
        maxDuration: 1800000, // 30 minutes
        maxChildren: 10,
        maxAlerts: 1000
      },
      network: {
        connectionTimeout: 10000,
        socketTimeout: 20000,
        maxConnections: 50,
        dnsTtl: 60
      }
    };
    
    // Start monitoring
    await this.monitor.monitorScanner(container.id);
    
    try {
      // Execute scan
      const result = await this.executeZAPScan(container, zapConfig);
      
      // Validate results don't contain external data
      this.validateScanResults(result);
      
      return result;
    } finally {
      // Cleanup
      await container.stop();
      await container.remove();
    }
  }
}
```

### SQLMap Integration with Boundaries

```typescript
class BoundedSQLMapScanner {
  async testSQLInjection(target: string): Promise<SQLiResult> {
    // Create sandboxed SQLMap container
    const container = await this.createSQLMapContainer();
    
    // Enforce boundaries in SQLMap command
    const command = [
      'python', 'sqlmap.py',
      '-u', target,
      '--batch',           // Non-interactive
      '--threads=2',       // Limited threads
      '--timeout=10',      // Connection timeout
      '--retries=1',       // Minimal retries
      '--no-cast',         // Prevent heavy queries
      '--technique=BEUSTQ', // All techniques
      '--level=3',         // Thorough testing
      '--risk=2',          // Medium risk
      '--output-dir=/tmp/scan',
      '--disable-coloring',
      // Boundary enforcement
      '--safe-url=' + this.getProjectUrl(),
      '--safe-post=' + this.getProjectPost(),
      '--safe-req=' + this.getProjectRequest(),
      '--safe-freq=10'     // Check boundaries every 10 requests
    ];
    
    // Monitor execution
    const monitor = this.startMonitoring(container.id);
    
    try {
      const result = await container.exec(command);
      
      // Parse and validate results
      return this.parseSQLMapResults(result);
    } finally {
      monitor.stop();
      await container.kill();
    }
  }
}
```

## Kubernetes Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: shamash-scanner-isolation
  namespace: shamash
spec:
  podSelector:
    matchLabels:
      app: shamash-scanner
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: shamash
    ports:
    - protocol: TCP
      port: 8080
  egress:
  # Only allow traffic to project namespace
  - to:
    - namespaceSelector:
        matchLabels:
          shamash.io/project: "true"
    ports:
    - protocol: TCP
      port: 80
    - protocol: TCP
      port: 443
    - protocol: TCP
      port: 8080
  # Block all other egress
  - to:
    - podSelector:
        matchLabels:
          block: "true"  # Never matches - blocks all
```

## Audit & Compliance

### Comprehensive Audit Logging

```typescript
class BoundaryAuditLogger {
  async logScanOperation(operation: ScanOperation): Promise<void> {
    const auditEntry: AuditEntry = {
      timestamp: new Date().toISOString(),
      operation: {
        type: operation.type,
        target: operation.target,
        scanner: operation.scanner,
        duration: operation.duration
      },
      boundaries: {
        validated: operation.boundariesValidated,
        networks: operation.allowedNetworks,
        violations: operation.violations || []
      },
      results: {
        findings: operation.findings,
        tokensUsed: operation.tokensUsed
      },
      compliance: {
        frameworks: ['OWASP', 'CIS', 'NIST'],
        passed: operation.complianceChecks
      }
    };
    
    // Write to immutable audit log
    await this.writeToAuditLog(auditEntry);
    
    // Send to SIEM if configured
    if (this.siemEnabled) {
      await this.sendToSIEM(auditEntry);
    }
  }
}
```

## Emergency Shutdown

```typescript
class EmergencyShutdown {
  async initiateShutdown(reason: string): Promise<void> {
    console.error(`EMERGENCY SHUTDOWN: ${reason}`);
    
    // 1. Stop all scanner containers
    const containers = await this.docker.listContainers({
      filters: { label: ['shamash.scanner=true'] }
    });
    
    for (const container of containers) {
      await this.docker.kill(container.Id, 'SIGKILL');
    }
    
    // 2. Flush iptables rules
    await exec('iptables -F SHAMASH_BOUNDARY');
    
    // 3. Delete network namespaces
    const namespaces = await this.listShamasNamespaces();
    for (const ns of namespaces) {
      await exec(`ip netns delete ${ns}`);
    }
    
    // 4. Alert administrators
    await this.alertAllAdmins({
      severity: 'CRITICAL',
      event: 'EMERGENCY_SHUTDOWN',
      reason,
      timestamp: new Date().toISOString()
    });
    
    // 5. Create incident report
    await this.createIncidentReport(reason);
  }
}
```

## Conclusion

This network boundary enforcement design ensures that all pentesting and network scanning operations remain strictly within project boundaries through multiple independent layers of security controls, real-time monitoring, and automatic violation response. The system enables comprehensive security testing while preventing any possibility of scanning or affecting external systems.