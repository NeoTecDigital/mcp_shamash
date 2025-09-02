#!/usr/bin/env node

const { spawn } = require('child_process');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');

async function testMCPServer() {
  console.log('🚀 Testing MCP Shamash Server...\n');

  // Start the server
  const serverProcess = spawn('npx', ['tsx', 'src/index.ts'], {
    stdio: 'pipe',
    cwd: process.cwd(),
  });

  // Set up transport
  const transport = new StdioClientTransport();
  transport.setChildProcess(serverProcess);

  // Initialize client
  const client = new Client(
    {
      name: 'test-client',
      version: '1.0.0',
    },
    {
      capabilities: {},
    }
  );

  try {
    // Connect to server
    await client.connect(transport);
    console.log('✅ Connected to Shamash server');

    // Test 1: List tools
    console.log('\n📋 Testing tools/list...');
    const toolsResult = await client.request(
      { method: 'tools/list', params: {} },
      { method: 'tools/list', params: {} }
    );
    console.log(`✅ Found ${toolsResult.tools.length} tools:`);
    toolsResult.tools.forEach(tool => {
      console.log(`   • ${tool.name}: ${tool.description}`);
    });

    // Test 2: Test project scan (should work)
    console.log('\n🔍 Testing project scan (valid path)...');
    try {
      const scanResult = await client.request(
        {
          method: 'tools/call',
          params: {
            name: 'scan_project',
            arguments: {
              path: process.cwd(),
              profile: 'quick'
            }
          }
        },
        {
          method: 'tools/call',
          params: {
            name: 'scan_project',
            arguments: {
              path: process.cwd(),
              profile: 'quick'
            }
          }
        }
      );
      console.log('✅ Project scan completed successfully');
      const result = JSON.parse(scanResult.content[0].text);
      console.log(`   • Scan ID: ${result.scanId}`);
      console.log(`   • Token usage: ${result.tokenUsage}`);
    } catch (error) {
      console.log(`❌ Project scan failed: ${error.message}`);
    }

    // Test 3: Test boundary enforcement (should fail)
    console.log('\n🚫 Testing boundary enforcement (/etc access)...');
    try {
      await client.request(
        {
          method: 'tools/call',
          params: {
            name: 'scan_project',
            arguments: {
              path: '/etc'
            }
          }
        },
        {
          method: 'tools/call',
          params: {
            name: 'scan_project',
            arguments: {
              path: '/etc'
            }
          }
        }
      );
      console.log('❌ Boundary enforcement failed - scan should have been blocked');
    } catch (error) {
      console.log('✅ Boundary enforcement working - access blocked');
      console.log(`   • Reason: ${error.message}`);
    }

    // Test 4: Test network scan
    console.log('\n🌐 Testing network scan (localhost)...');
    try {
      const networkResult = await client.request(
        {
          method: 'tools/call',
          params: {
            name: 'scan_network',
            arguments: {
              target: '127.0.0.1',
              ports: '80,443'
            }
          }
        },
        {
          method: 'tools/call',
          params: {
            name: 'scan_network',
            arguments: {
              target: '127.0.0.1',
              ports: '80,443'
            }
          }
        }
      );
      console.log('✅ Network scan completed successfully');
      const result = JSON.parse(networkResult.content[0].text);
      console.log(`   • Scan ID: ${result.scanId}`);
      console.log(`   • Findings: ${result.findings.length}`);
    } catch (error) {
      console.log(`❌ Network scan failed: ${error.message}`);
    }

    // Test 5: Test compliance check
    console.log('\n📊 Testing compliance check...');
    try {
      const complianceResult = await client.request(
        {
          method: 'tools/call',
          params: {
            name: 'check_compliance',
            arguments: {
              path: process.cwd(),
              frameworks: ['OWASP', 'CIS']
            }
          }
        },
        {
          method: 'tools/call',
          params: {
            name: 'check_compliance',
            arguments: {
              path: process.cwd(),
              frameworks: ['OWASP', 'CIS']
            }
          }
        }
      );
      console.log('✅ Compliance check completed successfully');
      const result = JSON.parse(complianceResult.content[0].text);
      console.log(`   • OWASP coverage: ${result.compliance.OWASP_Top_10.coverage}`);
      console.log(`   • CIS coverage: ${result.compliance.CIS_Controls.coverage}`);
    } catch (error) {
      console.log(`❌ Compliance check failed: ${error.message}`);
    }

    console.log('\n🎉 All tests completed!');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
  } finally {
    // Clean up
    await client.close();
    serverProcess.kill();
  }
}

// Run tests
testMCPServer().catch(console.error);