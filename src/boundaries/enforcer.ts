import * as path from 'path';
import * as fs from 'fs/promises';
import CIDR from 'ip-cidr';
import * as YAML from 'yaml';
import type { 
  ProjectScope, 
  BoundaryValidation, 
  NetworkDefinition, 
  ServiceDefinition 
} from '../types/index.js';

export class BoundaryEnforcer {
  private projectScope: ProjectScope | null = null;
  private readonly BLOCKED_NETWORKS = [
    '0.0.0.0/8',      // Current network
    '10.0.0.0/8',     // Private network (unless in project)
    '224.0.0.0/4',    // Multicast
    '255.255.255.255/32', // Broadcast
    '169.254.0.0/16', // Link-local
  ];
  
  private readonly BLOCKED_PORTS = [22, 3389, 445, 135, 139]; // Management ports
  private readonly SYSTEM_PATHS = ['/etc', '/usr', '/var', '/sys', '/proc'];

  async initialize(): Promise<void> {
    this.projectScope = await this.discoverProjectScope();
    console.error('Boundary enforcer initialized with scope:', {
      projectRoot: this.projectScope.projectRoot,
      networks: this.projectScope.networks.length,
      services: this.projectScope.services.length,
    });
  }

  private async discoverProjectScope(): Promise<ProjectScope> {
    const projectRoot = process.cwd();
    
    const scope: ProjectScope = {
      projectRoot,
      networks: [],
      services: [],
      containers: [],
      allowedPaths: [`${projectRoot}/**/*`],
      deniedPaths: this.SYSTEM_PATHS,
      excludedRanges: [...this.BLOCKED_NETWORKS],
      allowedPorts: [],
    };

    try {
      // 1. Docker Compose Discovery
      await this.discoverDockerCompose(scope);
      
      // 2. Kubernetes Discovery
      await this.discoverKubernetes(scope);
      
      // 3. Package.json Discovery (for Node.js apps)
      await this.discoverNodeApp(scope);
      
      // 4. Local Service Discovery
      await this.discoverLocalServices(scope);
      
    } catch (error) {
      console.error('Error discovering project scope:', error);
    }

    return scope;
  }

  private async discoverDockerCompose(scope: ProjectScope): Promise<void> {
    const composePaths = [
      'docker-compose.yml',
      'docker-compose.yaml',
      'compose.yml',
      'compose.yaml',
    ];

    for (const composePath of composePaths) {
      const fullPath = path.join(scope.projectRoot, composePath);
      
      try {
        const content = await fs.readFile(fullPath, 'utf-8');
        const compose = YAML.parse(content) as any;
        
        // Extract networks
        if (compose.networks) {
          for (const [name, config] of Object.entries(compose.networks as any)) {
            const networkConfig = config as any;
            const networkDef: NetworkDefinition = {
              name: `${path.basename(scope.projectRoot)}_${name}`,
              subnet: networkConfig?.ipam?.config?.[0]?.subnet || '172.20.0.0/16',
              type: 'docker',
              internal: networkConfig?.internal || false,
            };
            scope.networks.push(networkDef);
          }
        }
        
        // Extract services
        if (compose.services) {
          for (const [name, config] of Object.entries(compose.services as any)) {
            const serviceConfig = config as any;
            const ports: number[] = [];
            
            if (serviceConfig?.ports) {
              for (const portMapping of serviceConfig.ports) {
                const port = typeof portMapping === 'string' 
                  ? parseInt(portMapping.split(':')[0])
                  : portMapping;
                if (!isNaN(port)) ports.push(port);
              }
            }
            
            const serviceDef: ServiceDefinition = {
              name,
              network: `${path.basename(scope.projectRoot)}_default`,
              ports,
              internal: !serviceConfig?.ports || serviceConfig.ports.length === 0,
            };
            scope.services.push(serviceDef);
          }
        }
        
        console.error(`Discovered Docker Compose: ${composePath}`);
        break; // Use first found compose file
      } catch (error) {
        // File doesn't exist or invalid, continue
      }
    }
  }

  private async discoverKubernetes(scope: ProjectScope): Promise<void> {
    const k8sPaths = ['k8s', 'kubernetes', '.kube'];
    
    for (const k8sPath of k8sPaths) {
      const fullPath = path.join(scope.projectRoot, k8sPath);
      
      try {
        const stats = await fs.stat(fullPath);
        if (stats.isDirectory()) {
          // TODO: Implement K8s manifest parsing
          console.error(`Found Kubernetes directory: ${k8sPath}`);
          
          // Add default cluster network
          scope.networks.push({
            name: 'kubernetes-cluster',
            subnet: '10.244.0.0/16', // Default Kubernetes pod CIDR
            type: 'kubernetes',
          });
        }
      } catch (error) {
        // Directory doesn't exist, continue
      }
    }
  }

  private async discoverNodeApp(scope: ProjectScope): Promise<void> {
    try {
      const packagePath = path.join(scope.projectRoot, 'package.json');
      const content = await fs.readFile(packagePath, 'utf-8');
      JSON.parse(content); // Validate JSON structure
      
      // Look for common development ports
      const devPorts = [3000, 3001, 8000, 8080, 8081, 5173, 4000];
      scope.allowedPorts.push(...devPorts);
      
      console.error('Discovered Node.js project');
    } catch (error) {
      // Not a Node.js project, continue
    }
  }

  private async discoverLocalServices(scope: ProjectScope): Promise<void> {
    // Add localhost ranges
    scope.networks.push({
      name: 'localhost',
      subnet: '127.0.0.0/8',
      type: 'local',
    });
    
    // Add common development ports
    const commonPorts = [
      80, 443, 3000, 3001, 8000, 8080, 8081, 5000, 5001, 5173, 4000, 9000
    ];
    scope.allowedPorts.push(...commonPorts);
  }

  async validatePath(targetPath: string): Promise<BoundaryValidation> {
    if (!this.projectScope) {
      throw new Error('Boundary enforcer not initialized');
    }

    try {
      // Resolve path to absolute
      const absolutePath = path.resolve(targetPath);
      
      // Check if path is within project root
      const relativePath = path.relative(this.projectScope.projectRoot, absolutePath);
      
      if (relativePath.startsWith('..')) {
        return {
          allowed: false,
          reason: 'Path is outside project root',
          violations: ['PATH_ESCAPE'],
        };
      }
      
      // Check against denied paths
      for (const deniedPath of this.projectScope.deniedPaths) {
        if (absolutePath.startsWith(deniedPath)) {
          return {
            allowed: false,
            reason: `Path is in denied system directory: ${deniedPath}`,
            violations: ['SYSTEM_PATH_ACCESS'],
          };
        }
      }
      
      // Check if path exists (optional - create if scanning)
      try {
        await fs.access(absolutePath);
      } catch (error) {
        // Path doesn't exist - this might be OK for scanning
        console.error(`Warning: Path does not exist: ${absolutePath}`);
      }
      
      return { allowed: true };
      
    } catch (error) {
      return {
        allowed: false,
        reason: `Path validation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        violations: ['VALIDATION_ERROR'],
      };
    }
  }

  async validateNetwork(target: string): Promise<BoundaryValidation> {
    if (!this.projectScope) {
      throw new Error('Boundary enforcer not initialized');
    }

    try {
      // Parse target (could be IP, CIDR, or hostname)
      let targetIP: string;
      
      if (target === 'localhost' || target === '127.0.0.1') {
        targetIP = '127.0.0.1';
      } else if (target.includes('/')) {
        // CIDR notation
        const cidr = new CIDR(target);
        targetIP = cidr.addressStart.address;
      } else if (target.match(/^\d+\.\d+\.\d+\.\d+$/)) {
        // IP address
        targetIP = target;
      } else {
        return {
          allowed: false,
          reason: 'Hostname resolution not allowed - use IP addresses only',
          violations: ['HOSTNAME_NOT_ALLOWED'],
        };
      }
      
      // Check if IP is in blocked ranges
      for (const blockedRange of this.BLOCKED_NETWORKS) {
        const cidr = new CIDR(blockedRange);
        if (cidr.contains(targetIP)) {
          return {
            allowed: false,
            reason: `Target IP is in blocked range: ${blockedRange}`,
            violations: ['BLOCKED_NETWORK'],
          };
        }
      }
      
      // Check if IP is in allowed project networks
      for (const network of this.projectScope.networks) {
        const cidr = new CIDR(network.subnet);
        if (cidr.contains(targetIP)) {
          return { 
            allowed: true, 
            scope: network 
          };
        }
      }
      
      return {
        allowed: false,
        reason: 'Target is not in any project network',
        violations: ['OUT_OF_SCOPE'],
      };
      
    } catch (error) {
      return {
        allowed: false,
        reason: `Network validation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        violations: ['VALIDATION_ERROR'],
      };
    }
  }

  async validateUrl(url: string): Promise<BoundaryValidation> {
    try {
      const urlObj = new URL(url);
      
      // Extract hostname and port
      const hostname = urlObj.hostname;
      const port = urlObj.port ? parseInt(urlObj.port) : (urlObj.protocol === 'https:' ? 443 : 80);
      
      // Check if port is blocked
      if (this.BLOCKED_PORTS.includes(port)) {
        return {
          allowed: false,
          reason: `Port ${port} is blocked for security`,
          violations: ['BLOCKED_PORT'],
        };
      }
      
      // Validate the hostname as a network target
      return await this.validateNetwork(hostname);
      
    } catch (error) {
      return {
        allowed: false,
        reason: `Invalid URL: ${error instanceof Error ? error.message : 'Unknown error'}`,
        violations: ['INVALID_URL'],
      };
    }
  }

  async validatePort(port: number): Promise<BoundaryValidation> {
    if (this.BLOCKED_PORTS.includes(port)) {
      return {
        allowed: false,
        reason: `Port ${port} is blocked for security (management port)`,
        violations: ['BLOCKED_PORT'],
      };
    }
    
    if (port < 1 || port > 65535) {
      return {
        allowed: false,
        reason: 'Port number out of valid range (1-65535)',
        violations: ['INVALID_PORT'],
      };
    }
    
    return { allowed: true };
  }

  getProjectScope(): ProjectScope | null {
    return this.projectScope;
  }

  async logViolation(type: string, target: string, details?: any): Promise<void> {
    const violation = {
      timestamp: new Date().toISOString(),
      type,
      target,
      details,
      projectRoot: this.projectScope?.projectRoot,
    };
    
    console.error('BOUNDARY VIOLATION:', JSON.stringify(violation, null, 2));
    
    // TODO: Send to audit logger and/or SIEM
  }
}