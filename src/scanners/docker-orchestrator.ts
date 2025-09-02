import Docker from 'dockerode';
import * as path from 'path';
import * as fs from 'fs/promises';
import type { ProjectScope } from '../types/index.js';

export interface ScannerConfig {
  image: string;
  command?: string[];
  environment: Record<string, string>;
  volumes: Array<{
    source: string;
    target: string;
    readonly?: boolean;
  }>;
  resourceLimits: {
    memory: number;
    cpus: number;
    pidsLimit: number;
  };
  timeout: number;
  networkMode?: string;
}

export interface ScannerResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  duration: number;
  containerId: string;
}

export class DockerOrchestrator {
  private docker: Docker;
  private projectScope: ProjectScope;

  constructor(projectScope: ProjectScope) {
    this.docker = new Docker();
    this.projectScope = projectScope;
  }

  async runScanner(
    scannerName: string,
    config: ScannerConfig,
    targetPath: string
  ): Promise<ScannerResult> {
    const startTime = Date.now();
    let container: Docker.Container | null = null;

    try {
      // Validate target is within project scope
      if (!this.isPathInProject(targetPath)) {
        throw new Error(`Target path ${targetPath} is outside project scope`);
      }

      // Create scanner network if needed
      await this.ensureScannerNetwork();

      // Create container
      container = await this.createScannerContainer(scannerName, config, targetPath);

      // Start container
      await container.start();

      console.error(`Started scanner container: ${container.id}`);

      // Wait for completion with timeout
      const result = await this.waitForCompletion(container, config.timeout);

      return {
        ...result,
        duration: Date.now() - startTime,
        containerId: container.id,
      };

    } catch (error) {
      console.error(`Scanner ${scannerName} failed:`, error);
      throw error;
    } finally {
      // Cleanup container
      if (container) {
        try {
          await container.remove({ force: true });
        } catch (error) {
          console.error('Failed to cleanup container:', error);
        }
      }
    }
  }

  private async createScannerContainer(
    scannerName: string,
    config: ScannerConfig,
    targetPath: string
  ): Promise<Docker.Container> {
    // Create bind mounts
    const binds = config.volumes.map(vol => 
      `${vol.source}:${vol.target}${vol.readonly ? ':ro' : ''}`
    );

    // Add target path mount
    binds.push(`${targetPath}:/scan/target:ro`);

    // Create results directory
    const resultsPath = path.join(process.cwd(), 'scanner_results', scannerName);
    await fs.mkdir(resultsPath, { recursive: true });
    binds.push(`${resultsPath}:/var/scanner:rw`);

    const containerConfig = {
      Image: config.image,
      Cmd: config.command,
      Env: Object.entries(config.environment).map(([key, value]) => `${key}=${value}`),
      
      // Security configuration
      HostConfig: {
        Binds: binds,
        NetworkMode: config.networkMode || 'shamash_sandbox',
        
        // Resource limits
        Memory: config.resourceLimits.memory,
        CpuQuota: Math.floor(config.resourceLimits.cpus * 100000),
        CpuPeriod: 100000,
        PidsLimit: config.resourceLimits.pidsLimit,
        
        // Security options
        SecurityOpt: [
          'no-new-privileges:true',
          'apparmor:docker-shamash-scanner'
        ],
        CapDrop: ['ALL'],
        CapAdd: scannerName.includes('network') ? ['NET_RAW', 'NET_ADMIN'] : [],
        ReadonlyRootfs: true,
        
        // Temporary filesystems
        Tmpfs: {
          '/tmp': 'rw,noexec,nosuid,size=512m',
          '/var/run': 'rw,noexec,nosuid,size=128m'
        },
      },
      
      // Labels for tracking
      Labels: {
        'shamash.scanner': 'true',
        'shamash.scanner.name': scannerName,
        'shamash.project': path.basename(this.projectScope.projectRoot),
        'shamash.timestamp': new Date().toISOString()
      },
      
      // Working directory
      WorkingDir: '/scanner',
      
      // User (non-root)
      User: '65534:65534',
    };

    return await this.docker.createContainer(containerConfig);
  }

  private async waitForCompletion(
    container: Docker.Container,
    timeoutMs: number
  ): Promise<{ exitCode: number; stdout: string; stderr: string }> {
    return new Promise(async (resolve, reject) => {
      let timeoutHandle: NodeJS.Timeout;
      let stdout = '';
      let stderr = '';

      // Set up timeout
      timeoutHandle = setTimeout(async () => {
        try {
          await container.kill({ signal: 'SIGKILL' });
          reject(new Error(`Scanner timed out after ${timeoutMs}ms`));
        } catch (error) {
          reject(error);
        }
      }, timeoutMs);

      try {
        // Get logs stream
        const logStream = await container.logs({
          stdout: true,
          stderr: true,
          follow: true,
        });

        // Parse container logs
        logStream.on('data', (chunk) => {
          const data = chunk.toString();
          // Docker multiplexes stdout/stderr - first byte indicates stream type
          if (chunk[0] === 1) {
            stdout += data.slice(8); // Remove Docker header
          } else if (chunk[0] === 2) {
            stderr += data.slice(8); // Remove Docker header
          }
        });

        // Wait for container to finish
        const statusCode = await container.wait();

        clearTimeout(timeoutHandle);

        resolve({
          exitCode: statusCode.StatusCode,
          stdout,
          stderr,
        });

      } catch (error) {
        clearTimeout(timeoutHandle);
        reject(error);
      }
    });
  }

  private async ensureScannerNetwork(): Promise<void> {
    try {
      // Check if network exists
      const networks = await this.docker.listNetworks();
      const shamashNetwork = networks.find(net => net.Name === 'shamash_sandbox');
      
      if (!shamashNetwork) {
        // Create isolated network
        await this.docker.createNetwork({
          Name: 'shamash_sandbox',
          Driver: 'bridge',
          Internal: true, // No external access
          IPAM: {
            Config: [{
              Subnet: '172.28.0.0/16',
              IPRange: '172.28.5.0/24',
            }]
          },
          Labels: {
            'shamash.network': 'true'
          }
        });
        console.error('Created shamash_sandbox network');
      }
    } catch (error) {
      console.error('Failed to ensure scanner network:', error);
      throw error;
    }
  }

  private isPathInProject(targetPath: string): boolean {
    const absoluteTarget = path.resolve(targetPath);
    const projectRoot = path.resolve(this.projectScope.projectRoot);
    const relativePath = path.relative(projectRoot, absoluteTarget);
    
    return !relativePath.startsWith('..');
  }

  async buildScannerImage(dockerfilePath: string, imageName: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const buildStream = this.docker.buildImage({
        context: process.cwd(),
        src: [dockerfilePath, 'containers/scanner-utils.sh']
      }, {
        t: imageName,
        dockerfile: dockerfilePath,
        pull: true,
        rm: true
      });

      buildStream.then(stream => {
        stream.pipe(process.stderr);
        
        stream.on('end', () => {
          console.error(`Built scanner image: ${imageName}`);
          resolve();
        });
        
        stream.on('error', reject);
      }).catch(reject);
    });
  }

  async pullRequiredImages(): Promise<void> {
    const requiredImages = [
      'aquasec/trivy:latest',
      'zricethezav/gitleaks:latest',
      'owasp/zap2docker-stable:latest'
    ];

    for (const image of requiredImages) {
      try {
        console.error(`Pulling image: ${image}`);
        const pullStream = await this.docker.pull(image);
        
        await new Promise((resolve, reject) => {
          pullStream.pipe(process.stderr);
          pullStream.on('end', resolve);
          pullStream.on('error', reject);
        });
        
        console.error(`✅ Pulled: ${image}`);
      } catch (error) {
        console.error(`❌ Failed to pull ${image}:`, error);
        // Don't throw - scanner will fail gracefully if image missing
      }
    }
  }

  async cleanup(): Promise<void> {
    try {
      // Remove all shamash containers
      const containers = await this.docker.listContainers({ 
        all: true,
        filters: {
          label: ['shamash.scanner=true']
        }
      });

      for (const containerInfo of containers) {
        try {
          const container = this.docker.getContainer(containerInfo.Id);
          await container.remove({ force: true });
          console.error(`Cleaned up container: ${containerInfo.Id}`);
        } catch (error) {
          console.error(`Failed to cleanup container ${containerInfo.Id}:`, error);
        }
      }

      // Clean up network
      const networks = await this.docker.listNetworks({
        filters: {
          label: ['shamash.network=true']
        }
      });

      for (const networkInfo of networks) {
        try {
          const network = this.docker.getNetwork(networkInfo.Id);
          await network.remove();
          console.error(`Cleaned up network: ${networkInfo.Name}`);
        } catch (error) {
          console.error(`Failed to cleanup network ${networkInfo.Id}:`, error);
        }
      }

    } catch (error) {
      console.error('Cleanup failed:', error);
    }
  }
}