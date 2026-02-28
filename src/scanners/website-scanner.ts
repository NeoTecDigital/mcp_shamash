import * as https from 'https';
import * as http from 'http';
import * as tls from 'tls';
import type { ScanRequest, ScanResult, Finding } from '../types/index.js';
import type { BoundaryEnforcer } from '../boundaries/enforcer.js';

interface HttpResponse {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  redirectUrl?: string;
}

interface TestResult {
  findings: Finding[];
  tokenUsage: number;
}

type TestType =
  | 'security_headers'
  | 'ssl_tls'
  | 'information_disclosure'
  | 'directory_listing'
  | 'cookie_security'
  | 'http_methods'
  | 'cors_check'
  | 'clickjacking'
  | 'server_fingerprint'
  | 'ssl_cipher_analysis'
  | 'error_handling'
  | 'open_redirect'
  | 'mixed_content'
  | 'waf_detection'
  | 'authentication_check'
  | 'session_analysis'
  | 'api_exposure'
  | 'subdomain_headers';

const PROFILE_TESTS: Record<string, TestType[]> = {
  quick: ['security_headers', 'cookie_security', 'server_fingerprint'],
  standard: [
    'security_headers', 'ssl_tls', 'information_disclosure',
    'cookie_security', 'http_methods', 'server_fingerprint',
    'error_handling', 'waf_detection',
  ],
  thorough: [
    'security_headers', 'ssl_tls', 'information_disclosure',
    'directory_listing', 'cookie_security', 'http_methods',
    'cors_check', 'clickjacking', 'server_fingerprint',
    'ssl_cipher_analysis', 'error_handling', 'open_redirect',
    'mixed_content', 'waf_detection', 'authentication_check',
    'session_analysis', 'api_exposure', 'subdomain_headers',
  ],
};

export class WebsiteScanner {
  constructor(private boundaryEnforcer: BoundaryEnforcer) {
    // BoundaryEnforcer must be initialized before use
    const projectScope = this.boundaryEnforcer.getProjectScope();
    if (!projectScope) {
      throw new Error('Project scope not initialized');
    }
  }

  async scan(request: ScanRequest): Promise<ScanResult> {
    const scanId = this.generateScanId();
    const startTime = Date.now();

    console.error(`Starting website scan: ${scanId}`);

    const allFindings: Finding[] = [];
    const errors: string[] = [];
    let tokenUsage = 0;

    const testTypes = (request.tools as TestType[]) || this.getDefaultTests(request.profile);

    for (const testType of testTypes) {
      try {
        const result = await this.runTest(testType, request.target);
        allFindings.push(...result.findings);
        tokenUsage += result.tokenUsage;
      } catch (error) {
        const msg = `Test ${testType} failed: ${error instanceof Error ? error.message : 'Unknown error'}`;
        console.error(msg);
        errors.push(msg);
      }
    }

    const summary = this.calculateSummary(allFindings);

    const result: ScanResult = {
      scanId,
      status: errors.length === 0 ? 'success' : (allFindings.length > 0 ? 'partial' : 'failed'),
      summary,
      findings: allFindings,
      tokenUsage,
      scanTimeMs: Date.now() - startTime,
      errors: errors.length > 0 ? errors : undefined,
    };

    console.error(`Website scan completed: ${result.status}, ${allFindings.length} findings`);
    return result;
  }

  private async runTest(testType: TestType, targetUrl: string): Promise<TestResult> {
    switch (testType) {
      case 'security_headers':
        return this.testSecurityHeaders(targetUrl);
      case 'ssl_tls':
        return this.testSslTls(targetUrl);
      case 'information_disclosure':
        return this.testInformationDisclosure(targetUrl);
      case 'directory_listing':
        return this.testDirectoryListing(targetUrl);
      case 'cookie_security':
        return this.testCookieSecurity(targetUrl);
      case 'http_methods':
        return this.testHttpMethods(targetUrl);
      case 'cors_check':
        return this.testCorsCheck(targetUrl);
      case 'clickjacking':
        return this.testClickjacking(targetUrl);
      case 'server_fingerprint':
        return this.testServerFingerprint(targetUrl);
      case 'ssl_cipher_analysis':
        return this.testSslCipherAnalysis(targetUrl);
      case 'error_handling':
        return this.testErrorHandling(targetUrl);
      case 'open_redirect':
        return this.testOpenRedirect(targetUrl);
      case 'mixed_content':
        return this.testMixedContent(targetUrl);
      case 'waf_detection':
        return this.testWafDetection(targetUrl);
      case 'authentication_check':
        return this.testAuthenticationCheck(targetUrl);
      case 'session_analysis':
        return this.testSessionAnalysis(targetUrl);
      case 'api_exposure':
        return this.testApiExposure(targetUrl);
      case 'subdomain_headers':
        return this.testSubdomainHeaders(targetUrl);
    }
  }

  private async testSecurityHeaders(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];

    try {
      const response = await this.makeRequest(targetUrl, { method: 'HEAD' });

      const criticalHeaders: Array<{ name: string; severity: 'medium' | 'low'; remediation: string }> = [
        {
          name: 'content-security-policy',
          severity: 'medium',
          remediation: 'Add Content-Security-Policy header to prevent XSS and data injection attacks',
        },
        {
          name: 'strict-transport-security',
          severity: 'medium',
          remediation: 'Add Strict-Transport-Security header to enforce HTTPS connections',
        },
        {
          name: 'x-frame-options',
          severity: 'medium',
          remediation: 'Add X-Frame-Options header (DENY or SAMEORIGIN) to prevent clickjacking',
        },
        {
          name: 'x-content-type-options',
          severity: 'medium',
          remediation: 'Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing',
        },
        {
          name: 'x-xss-protection',
          severity: 'low',
          remediation: 'Add X-XSS-Protection: 1; mode=block (legacy browsers)',
        },
        {
          name: 'referrer-policy',
          severity: 'low',
          remediation: 'Add Referrer-Policy header to control referrer information leakage',
        },
        {
          name: 'permissions-policy',
          severity: 'low',
          remediation: 'Add Permissions-Policy header to restrict browser feature access',
        },
      ];

      for (const header of criticalHeaders) {
        if (!response.headers[header.name]) {
          findings.push({
            id: `header_${header.name}_${Date.now()}`,
            type: 'security_misconfiguration',
            severity: header.severity,
            title: `Missing Security Header: ${header.name}`,
            description: `The response from ${targetUrl} does not include the ${header.name} header`,
            location: { endpoint: targetUrl },
            remediation: header.remediation,
          });
        }
      }
    } catch (error) {
      console.error(`Security headers test error: ${error instanceof Error ? error.message : 'Unknown'}`);
    }

    return { findings, tokenUsage: 25 };
  }

  private async testSslTls(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];

    try {
      const urlObj = new URL(targetUrl);

      if (urlObj.protocol !== 'https:') {
        findings.push({
          id: `ssl_no_https_${Date.now()}`,
          type: 'security_misconfiguration',
          severity: 'high',
          title: 'Site Not Using HTTPS',
          description: `${targetUrl} is served over plain HTTP without TLS encryption`,
          location: { endpoint: targetUrl },
          remediation: 'Enable HTTPS with a valid TLS certificate',
        });
        return { findings, tokenUsage: 20 };
      }

      const port = urlObj.port ? parseInt(urlObj.port) : 443;
      const certInfo = await this.inspectCertificate(urlObj.hostname, port);

      if (certInfo.selfSigned) {
        findings.push({
          id: `ssl_self_signed_${Date.now()}`,
          type: 'security_misconfiguration',
          severity: 'high',
          title: 'Self-Signed TLS Certificate',
          description: `${urlObj.hostname} uses a self-signed certificate`,
          location: { endpoint: targetUrl },
          remediation: 'Use a certificate from a trusted Certificate Authority',
        });
      }

      if (certInfo.expiringSoon) {
        findings.push({
          id: `ssl_expiring_${Date.now()}`,
          type: 'security_misconfiguration',
          severity: 'medium',
          title: 'TLS Certificate Expiring Soon',
          description: `Certificate for ${urlObj.hostname} expires on ${certInfo.validTo}`,
          location: { endpoint: targetUrl },
          remediation: 'Renew the TLS certificate before expiry',
        });
      }

      if (certInfo.expired) {
        findings.push({
          id: `ssl_expired_${Date.now()}`,
          type: 'security_misconfiguration',
          severity: 'critical',
          title: 'TLS Certificate Expired',
          description: `Certificate for ${urlObj.hostname} expired on ${certInfo.validTo}`,
          location: { endpoint: targetUrl },
          remediation: 'Immediately renew the expired TLS certificate',
        });
      }

      if (certInfo.protocol && certInfo.protocol < 'TLSv1.2') {
        findings.push({
          id: `ssl_weak_proto_${Date.now()}`,
          type: 'security_misconfiguration',
          severity: 'high',
          title: 'Weak TLS Protocol Version',
          description: `${urlObj.hostname} supports ${certInfo.protocol} which is deprecated`,
          location: { endpoint: targetUrl },
          remediation: 'Disable TLS versions below 1.2 and prefer TLS 1.3',
        });
      }

      // HSTS preload and max-age checks
      const hstsResponse = await this.makeRequest(targetUrl, { method: 'HEAD' });
      const hstsHeader = hstsResponse.headers['strict-transport-security'];
      if (typeof hstsHeader === 'string') {
        const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/);
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
        const ONE_YEAR = 31536000;

        if (maxAge < ONE_YEAR) {
          findings.push({
            id: `ssl_hsts_short_maxage_${Date.now()}`,
            type: 'security_misconfiguration',
            severity: 'medium',
            title: 'HSTS max-age Too Short',
            description: `HSTS max-age is ${maxAge} seconds (${Math.round(maxAge / 86400)} days). Recommended minimum is 1 year (31536000 seconds)`,
            location: { endpoint: targetUrl },
            remediation: 'Set Strict-Transport-Security max-age to at least 31536000 (1 year)',
          });
        }

        if (!hstsHeader.toLowerCase().includes('includesubdomains')) {
          findings.push({
            id: `ssl_hsts_no_subdomains_${Date.now()}`,
            type: 'security_misconfiguration',
            severity: 'low',
            title: 'HSTS Missing includeSubDomains Directive',
            description: 'HSTS header does not include the includeSubDomains directive, leaving subdomains unprotected',
            location: { endpoint: targetUrl },
            remediation: 'Add includeSubDomains to the Strict-Transport-Security header',
          });
        }

        if (!hstsHeader.toLowerCase().includes('preload')) {
          findings.push({
            id: `ssl_hsts_no_preload_${Date.now()}`,
            type: 'security_misconfiguration',
            severity: 'informational',
            title: 'HSTS Missing preload Directive',
            description: 'HSTS header does not include the preload directive. The site is not eligible for HSTS preload lists',
            location: { endpoint: targetUrl },
            remediation: 'Add preload to the Strict-Transport-Security header and submit to hstspreload.org',
          });
        }
      }
    } catch (error) {
      console.error(`SSL/TLS test error: ${error instanceof Error ? error.message : 'Unknown'}`);
    }

    return { findings, tokenUsage: 35 };
  }

  private async testInformationDisclosure(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];

    const sensitiveFiles: Array<{ path: string; severity: 'high' | 'medium' | 'low'; description: string }> = [
      { path: '/.env', severity: 'high', description: 'Environment configuration file with potential secrets' },
      { path: '/.git/config', severity: 'high', description: 'Git configuration exposing repository details' },
      { path: '/.htaccess', severity: 'medium', description: 'Apache configuration file' },
      { path: '/.htpasswd', severity: 'high', description: 'Apache password file' },
      { path: '/server-status', severity: 'medium', description: 'Apache server status page' },
      { path: '/server-info', severity: 'medium', description: 'Apache server info page' },
      { path: '/phpinfo.php', severity: 'high', description: 'PHP info page exposing server configuration' },
      { path: '/.svn/entries', severity: 'medium', description: 'SVN metadata exposing repository structure' },
      { path: '/wp-admin/', severity: 'low', description: 'WordPress admin panel accessible' },
      { path: '/admin/', severity: 'low', description: 'Admin panel accessible' },
      { path: '/.DS_Store', severity: 'medium', description: 'macOS directory metadata file exposing file structure' },
      { path: '/crossdomain.xml', severity: 'medium', description: 'Flash cross-domain policy may allow unauthorized access' },
      { path: '/clientaccesspolicy.xml', severity: 'medium', description: 'Silverlight cross-domain policy may allow unauthorized access' },
      { path: '/index.php.bak', severity: 'high', description: 'Backup file may expose source code' },
      { path: '/index.html.bak', severity: 'medium', description: 'Backup file may expose page content' },
      { path: '/web.config.bak', severity: 'high', description: 'Backup of IIS configuration may expose secrets' },
      { path: '/debug/', severity: 'high', description: 'Debug interface accessible' },
      { path: '/test/', severity: 'medium', description: 'Test environment accessible in production' },
      { path: '/staging/', severity: 'medium', description: 'Staging environment accessible in production' },
      { path: '/wp-config.php', severity: 'high', description: 'WordPress configuration file with database credentials' },
      { path: '/wp-config.php.bak', severity: 'high', description: 'Backup of WordPress configuration with credentials' },
      { path: '/elmah.axd', severity: 'high', description: '.NET error log handler exposing stack traces and errors' },
      { path: '/trace.axd', severity: 'high', description: '.NET request tracing handler exposing application internals' },
    ];

    const infoFiles: Array<{ path: string; description: string }> = [
      { path: '/robots.txt', description: 'Robots.txt may reveal hidden paths' },
      { path: '/sitemap.xml', description: 'Sitemap may reveal application structure' },
      { path: '/.well-known/security.txt', description: 'Security contact information' },
    ];

    const baseUrl = targetUrl.replace(/\/+$/, '');

    for (const file of sensitiveFiles) {
      try {
        const response = await this.makeRequest(`${baseUrl}${file.path}`, {
          method: 'GET',
          timeout: 5000,
        });

        if (response.statusCode === 200 && response.body.length > 0) {
          findings.push({
            id: `info_disclosure_${file.path.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}`,
            type: 'information_disclosure',
            severity: file.severity,
            title: `Sensitive File Accessible: ${file.path}`,
            description: `${file.description}. File returned HTTP ${response.statusCode} with ${response.body.length} bytes`,
            location: { endpoint: `${baseUrl}${file.path}` },
            remediation: 'Block access to sensitive files via web server configuration',
          });
        }
      } catch (_error) {
        // Connection errors are expected for non-existent paths
      }
    }

    for (const file of infoFiles) {
      try {
        const response = await this.makeRequest(`${baseUrl}${file.path}`, {
          method: 'GET',
          timeout: 5000,
        });

        if (response.statusCode === 200 && response.body.length > 0) {
          findings.push({
            id: `info_file_${file.path.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}`,
            type: 'information_disclosure',
            severity: 'informational',
            title: `Information File Found: ${file.path}`,
            description: `${file.description}. Review contents for sensitive information`,
            location: { endpoint: `${baseUrl}${file.path}` },
          });
        }
      } catch (_error) {
        // Expected for missing files
      }
    }

    return { findings, tokenUsage: 50 };
  }

  private async testDirectoryListing(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];
    const baseUrl = targetUrl.replace(/\/+$/, '');

    const testPaths = ['/images/', '/css/', '/js/', '/assets/', '/uploads/', '/static/', '/media/'];
    const listingPatterns = [
      /Index of \//i,
      /Directory listing for/i,
      /<title>Index of/i,
      /Parent Directory/i,
      /\[To Parent Directory\]/i,
    ];

    for (const dirPath of testPaths) {
      try {
        const response = await this.makeRequest(`${baseUrl}${dirPath}`, {
          method: 'GET',
          timeout: 5000,
        });

        if (response.statusCode === 200) {
          const hasListing = listingPatterns.some(pattern => pattern.test(response.body));
          if (hasListing) {
            findings.push({
              id: `dir_listing_${dirPath.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}`,
              type: 'security_misconfiguration',
              severity: 'medium',
              title: `Directory Listing Enabled: ${dirPath}`,
              description: `Directory listing is enabled at ${baseUrl}${dirPath}, exposing file structure`,
              location: { endpoint: `${baseUrl}${dirPath}` },
              remediation: 'Disable directory listing in web server configuration (Options -Indexes for Apache, autoindex off for nginx)',
            });
          }
        }
      } catch (_error) {
        // Expected for non-existent paths
      }
    }

    return { findings, tokenUsage: 30 };
  }

  private async testCookieSecurity(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];

    try {
      const response = await this.makeRequest(targetUrl, { method: 'GET' });
      const setCookieHeaders = this.getSetCookieHeaders(response.headers);

      for (const cookieStr of setCookieHeaders) {
        const cookieName = cookieStr.split('=')[0].trim();
        const cookieLower = cookieStr.toLowerCase();

        if (!cookieLower.includes('httponly')) {
          findings.push({
            id: `cookie_httponly_${cookieName}_${Date.now()}`,
            type: 'security_misconfiguration',
            severity: 'medium',
            title: `Cookie Missing HttpOnly Flag: ${cookieName}`,
            description: `Cookie "${cookieName}" is accessible via JavaScript (XSS risk)`,
            location: { endpoint: targetUrl },
            remediation: 'Add the HttpOnly flag to prevent JavaScript access to the cookie',
          });
        }

        const urlObj = new URL(targetUrl);
        if (urlObj.protocol === 'https:' && !cookieLower.includes('secure')) {
          findings.push({
            id: `cookie_secure_${cookieName}_${Date.now()}`,
            type: 'security_misconfiguration',
            severity: 'medium',
            title: `Cookie Missing Secure Flag: ${cookieName}`,
            description: `Cookie "${cookieName}" may be transmitted over unencrypted connections`,
            location: { endpoint: targetUrl },
            remediation: 'Add the Secure flag to ensure the cookie is only sent over HTTPS',
          });
        }

        if (!cookieLower.includes('samesite')) {
          findings.push({
            id: `cookie_samesite_${cookieName}_${Date.now()}`,
            type: 'security_misconfiguration',
            severity: 'low',
            title: `Cookie Missing SameSite Attribute: ${cookieName}`,
            description: `Cookie "${cookieName}" does not set SameSite attribute (CSRF risk)`,
            location: { endpoint: targetUrl },
            remediation: 'Add SameSite=Strict or SameSite=Lax to prevent cross-site request forgery',
          });
        }

        const domainMatch = cookieLower.match(/domain=([^;]+)/);
        if (domainMatch) {
          const domain = domainMatch[1].trim();
          if (domain.startsWith('.') && domain.split('.').length <= 2) {
            findings.push({
              id: `cookie_domain_${cookieName}_${Date.now()}`,
              type: 'security_misconfiguration',
              severity: 'medium',
              title: `Cookie Has Overly Broad Domain: ${cookieName}`,
              description: `Cookie "${cookieName}" domain is set to "${domain}" which is too permissive`,
              location: { endpoint: targetUrl },
              remediation: 'Restrict the cookie domain to the specific subdomain needed',
            });
          }
        }
      }
    } catch (error) {
      console.error(`Cookie security test error: ${error instanceof Error ? error.message : 'Unknown'}`);
    }

    return { findings, tokenUsage: 25 };
  }

  private async testHttpMethods(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];
    const dangerousMethods = ['PUT', 'DELETE', 'TRACE'];

    try {
      const optionsResponse = await this.makeRequest(targetUrl, { method: 'OPTIONS' });
      const allowHeader = optionsResponse.headers['allow'] || '';

      if (typeof allowHeader === 'string' && allowHeader.length > 0) {
        const allowedMethods = allowHeader.split(',').map(m => m.trim().toUpperCase());

        for (const method of dangerousMethods) {
          if (allowedMethods.includes(method)) {
            findings.push({
              id: `http_method_${method.toLowerCase()}_${Date.now()}`,
              type: 'security_misconfiguration',
              severity: method === 'TRACE' ? 'medium' : 'low',
              title: `Dangerous HTTP Method Allowed: ${method}`,
              description: `The server allows the ${method} HTTP method which may be exploitable`,
              location: { endpoint: targetUrl },
              remediation: `Disable the ${method} HTTP method in web server configuration`,
            });
          }
        }
      }

      // Directly test TRACE even if OPTIONS didn't reveal it
      try {
        const traceResponse = await this.makeRequest(targetUrl, { method: 'TRACE', timeout: 5000 });
        if (traceResponse.statusCode === 200 && traceResponse.body.includes('TRACE')) {
          const alreadyReported = findings.some(f => f.title.includes('TRACE'));
          if (!alreadyReported) {
            findings.push({
              id: `http_trace_active_${Date.now()}`,
              type: 'security_misconfiguration',
              severity: 'medium',
              title: 'HTTP TRACE Method Active',
              description: 'TRACE method is active and reflects requests, enabling Cross-Site Tracing (XST) attacks',
              location: { endpoint: targetUrl },
              remediation: 'Disable TRACE method in web server configuration (TraceEnable Off for Apache)',
            });
          }
        }
      } catch (_error) {
        // TRACE blocked is expected
      }
    } catch (error) {
      console.error(`HTTP methods test error: ${error instanceof Error ? error.message : 'Unknown'}`);
    }

    return { findings, tokenUsage: 30 };
  }

  private async testCorsCheck(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];

    const maliciousOrigins = [
      'https://evil.com',
      'https://attacker.example.com',
      'null',
    ];

    try {
      for (const origin of maliciousOrigins) {
        const response = await this.makeRequest(targetUrl, {
          method: 'GET',
          headers: { 'Origin': origin },
          timeout: 5000,
        });

        const acao = response.headers['access-control-allow-origin'];

        if (acao === '*') {
          findings.push({
            id: `cors_wildcard_${Date.now()}`,
            type: 'security_misconfiguration',
            severity: 'medium',
            title: 'CORS Wildcard Origin Allowed',
            description: 'The server allows requests from any origin (Access-Control-Allow-Origin: *)',
            location: { endpoint: targetUrl },
            remediation: 'Restrict CORS to specific trusted origins instead of using wildcard',
          });
          break; // No need to test other origins
        }

        if (typeof acao === 'string' && acao === origin && origin !== 'null') {
          findings.push({
            id: `cors_reflection_${Date.now()}`,
            type: 'security_misconfiguration',
            severity: 'high',
            title: 'CORS Origin Reflection Vulnerability',
            description: `The server reflects arbitrary Origin headers back in Access-Control-Allow-Origin (reflected: ${origin})`,
            location: { endpoint: targetUrl },
            remediation: 'Implement an origin whitelist instead of reflecting the Origin header',
          });
          break;
        }

        if (typeof acao === 'string' && acao === 'null') {
          findings.push({
            id: `cors_null_origin_${Date.now()}`,
            type: 'security_misconfiguration',
            severity: 'medium',
            title: 'CORS Allows Null Origin',
            description: 'The server accepts requests with Origin: null, which can be spoofed via sandboxed iframes',
            location: { endpoint: targetUrl },
            remediation: 'Do not allow the null origin in CORS configuration',
          });
          break;
        }
      }

      // Check for credentials with wildcard
      const credResponse = await this.makeRequest(targetUrl, {
        method: 'GET',
        headers: { 'Origin': 'https://test.com' },
        timeout: 5000,
      });

      const credAcao = credResponse.headers['access-control-allow-origin'];
      const credAcac = credResponse.headers['access-control-allow-credentials'];

      if (credAcao === '*' && credAcac === 'true') {
        findings.push({
          id: `cors_cred_wildcard_${Date.now()}`,
          type: 'security_misconfiguration',
          severity: 'high',
          title: 'CORS Wildcard With Credentials',
          description: 'Server allows credentials with wildcard origin, enabling credential theft',
          location: { endpoint: targetUrl },
          remediation: 'Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true',
        });
      }
    } catch (error) {
      console.error(`CORS check error: ${error instanceof Error ? error.message : 'Unknown'}`);
    }

    return { findings, tokenUsage: 35 };
  }

  private async testClickjacking(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];

    try {
      const response = await this.makeRequest(targetUrl, { method: 'GET' });

      const xfo = response.headers['x-frame-options'];
      const csp = response.headers['content-security-policy'];

      const hasXfo = typeof xfo === 'string' && xfo.length > 0;
      const hasCspFrameAncestors = typeof csp === 'string' && csp.includes('frame-ancestors');

      if (!hasXfo && !hasCspFrameAncestors) {
        findings.push({
          id: `clickjack_no_protection_${Date.now()}`,
          type: 'security_misconfiguration',
          severity: 'medium',
          title: 'No Clickjacking Protection',
          description: 'The page can be embedded in iframes on any domain (no X-Frame-Options or CSP frame-ancestors)',
          location: { endpoint: targetUrl },
          remediation: 'Add X-Frame-Options: DENY (or SAMEORIGIN) and/or Content-Security-Policy: frame-ancestors \'self\'',
        });
      } else if (hasXfo && !hasCspFrameAncestors) {
        // X-Frame-Options alone is legacy, recommend CSP upgrade
        findings.push({
          id: `clickjack_no_csp_${Date.now()}`,
          type: 'security_misconfiguration',
          severity: 'low',
          title: 'Clickjacking Protection Uses Legacy Header Only',
          description: 'X-Frame-Options is set but CSP frame-ancestors is missing (modern browsers prefer CSP)',
          location: { endpoint: targetUrl },
          remediation: 'Add Content-Security-Policy: frame-ancestors \'self\' alongside X-Frame-Options',
        });
      }
    } catch (error) {
      console.error(`Clickjacking test error: ${error instanceof Error ? error.message : 'Unknown'}`);
    }

    return { findings, tokenUsage: 20 };
  }

  private async testServerFingerprint(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];

    try {
      const response = await this.makeRequest(targetUrl, { method: 'HEAD' });

      const fingerprintHeaders: Array<{ header: string; label: string }> = [
        { header: 'server', label: 'Server' },
        { header: 'x-powered-by', label: 'X-Powered-By' },
        { header: 'x-aspnet-version', label: 'X-AspNet-Version' },
        { header: 'x-generator', label: 'X-Generator' },
      ];

      for (const { header, label } of fingerprintHeaders) {
        const value = response.headers[header];
        if (typeof value === 'string' && value.length > 0) {
          findings.push({
            id: `fingerprint_${header}_${Date.now()}`,
            type: 'information_disclosure',
            severity: header === 'server' ? 'informational' : 'medium',
            title: `Technology Disclosed via ${label} Header`,
            description: `The ${label} header reveals: ${value}`,
            location: { endpoint: targetUrl },
            remediation: `Remove or obfuscate the ${label} header to prevent technology fingerprinting`,
          });
        }
      }

      // Check HTML for meta generator tag
      if (response.body) {
        const getResponse = await this.makeRequest(targetUrl, { method: 'GET' });
        const generatorMatch = getResponse.body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
        if (generatorMatch) {
          findings.push({
            id: `fingerprint_meta_generator_${Date.now()}`,
            type: 'information_disclosure',
            severity: 'informational',
            title: 'Technology Disclosed via Meta Generator Tag',
            description: `HTML meta generator tag reveals: ${generatorMatch[1]}`,
            location: { endpoint: targetUrl },
            remediation: 'Remove the meta generator tag from HTML output',
          });
        }
      }
    } catch (error) {
      console.error(`Server fingerprint test error: ${error instanceof Error ? error.message : 'Unknown'}`);
    }

    return { findings, tokenUsage: 20 };
  }

  private async testSslCipherAnalysis(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];

    try {
      const urlObj = new URL(targetUrl);
      if (urlObj.protocol !== 'https:') {
        return { findings, tokenUsage: 5 };
      }

      const port = urlObj.port ? parseInt(urlObj.port) : 443;
      const hostname = urlObj.hostname;

      const weakCipherSuites: Array<{ ciphers: string; label: string; severity: 'critical' | 'high' | 'medium' }> = [
        { ciphers: 'NULL', label: 'NULL ciphers (no encryption)', severity: 'critical' },
        { ciphers: 'EXPORT', label: 'Export-grade ciphers', severity: 'high' },
        { ciphers: 'RC4', label: 'RC4 ciphers', severity: 'high' },
        { ciphers: 'DES:3DES', label: 'DES/3DES ciphers', severity: 'medium' },
      ];

      for (const suite of weakCipherSuites) {
        try {
          const supported = await this.testCipherSupport(hostname, port, suite.ciphers);
          if (supported) {
            findings.push({
              id: `cipher_${suite.ciphers.replace(/[^a-z0-9]/gi, '_').toLowerCase()}_${Date.now()}`,
              type: 'security_misconfiguration',
              severity: suite.severity,
              title: `Weak Cipher Suite Supported: ${suite.label}`,
              description: `${hostname} accepts connections with ${suite.label}, which are considered insecure`,
              location: { endpoint: targetUrl },
              remediation: `Disable ${suite.label} in TLS configuration. Use only strong cipher suites (AES-GCM, ChaCha20-Poly1305)`,
            });
          }
        } catch (_error) {
          // Cipher not supported (expected for most)
        }
      }
    } catch (error) {
      console.error(`SSL cipher analysis error: ${error instanceof Error ? error.message : 'Unknown'}`);
    }

    return { findings, tokenUsage: 40 };
  }

  private testCipherSupport(hostname: string, port: number, ciphers: string): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = tls.connect(
        {
          host: hostname,
          port,
          ciphers,
          rejectUnauthorized: false,
          servername: hostname,
        },
        () => {
          socket.end();
          resolve(true);
        }
      );

      socket.setTimeout(5000);
      socket.on('timeout', () => { socket.destroy(); resolve(false); });
      socket.on('error', () => { resolve(false); });
    });
  }

  private async testErrorHandling(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];
    const baseUrl = targetUrl.replace(/\/+$/, '');

    const stackTracePatterns = [
      /at\s+Object\./i,
      /at\s+Module\./i,
      /Traceback\s+\(most recent/i,
      /Exception\s+in\s+thread/i,
      /System\.(\w+)Exception/,
      /Line\s+\d+/i,
      /stack\s*trace/i,
      /\/[a-z].*\.(js|py|rb|php|java|cs):\d+/i,
    ];

    const versionPatterns = [
      /PHP\/[\d.]+/,
      /Apache\/[\d.]+/,
      /nginx\/[\d.]+/,
      /Express\/[\d.]+/,
      /ASP\.NET\s+[\d.]+/,
      /IIS\/[\d.]+/,
    ];

    // Test 1: Request a non-existent path (404 handler)
    const randomPath = `/${crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2)}`;
    try {
      const response = await this.makeRequest(`${baseUrl}${randomPath}`, { method: 'GET', timeout: 5000 });

      for (const pattern of stackTracePatterns) {
        if (pattern.test(response.body)) {
          findings.push({
            id: `error_stacktrace_404_${Date.now()}`,
            type: 'information_disclosure',
            severity: 'medium',
            title: 'Stack Trace Leaked in 404 Error Page',
            description: 'The 404 error page contains stack trace information that reveals application internals',
            location: { endpoint: `${baseUrl}${randomPath}` },
            remediation: 'Configure custom error pages that do not expose stack traces or internal paths',
          });
          break;
        }
      }

      for (const pattern of versionPatterns) {
        const match = response.body.match(pattern);
        if (match) {
          findings.push({
            id: `error_version_leak_${Date.now()}`,
            type: 'information_disclosure',
            severity: 'low',
            title: `Technology Version Leaked in Error Page: ${match[0]}`,
            description: `The error page reveals technology version: ${match[0]}`,
            location: { endpoint: `${baseUrl}${randomPath}` },
            remediation: 'Configure error pages to not reveal server technology or version information',
          });
          break;
        }
      }
    } catch (_error) {
      // Connection errors are acceptable
    }

    // Test 2: Trigger potential 500 with malformed parameters
    try {
      const response = await this.makeRequest(`${baseUrl}/?id=%22%3E%3Cscript%3E&foo[]=bar`, { method: 'GET', timeout: 5000 });

      if (response.statusCode >= 500) {
        const hasTrace = stackTracePatterns.some(p => p.test(response.body));
        if (hasTrace) {
          findings.push({
            id: `error_stacktrace_500_${Date.now()}`,
            type: 'information_disclosure',
            severity: 'medium',
            title: 'Stack Trace Leaked in 500 Error Response',
            description: 'Malformed input triggers a server error that exposes stack trace information',
            location: { endpoint: `${baseUrl}/?id=...` },
            remediation: 'Implement proper input validation and configure custom error pages for 5xx errors',
          });
        }
      }
    } catch (_error) {
      // Expected
    }

    return { findings, tokenUsage: 25 };
  }

  private async testOpenRedirect(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];
    const baseUrl = targetUrl.replace(/\/+$/, '');
    const evilUrl = 'https://evil.com';

    const redirectParams = ['url', 'next', 'redirect', 'return', 'goto', 'dest'];

    for (const param of redirectParams) {
      try {
        const testUrl = `${baseUrl}/?${param}=${encodeURIComponent(evilUrl)}`;
        const response = await this.makeRequest(testUrl, {
          method: 'GET',
          timeout: 5000,
          maxRedirects: 0,
        });

        // Check if redirect Location header points to evil.com
        if (response.statusCode >= 300 && response.statusCode < 400) {
          const location = response.redirectUrl || '';
          if (location.includes('evil.com')) {
            findings.push({
              id: `open_redirect_${param}_${Date.now()}`,
              type: 'security_misconfiguration',
              severity: 'medium',
              title: `Open Redirect via ?${param} Parameter`,
              description: `The application redirects to arbitrary external URLs via the ?${param} parameter. Redirect target: ${location}`,
              location: { endpoint: testUrl },
              remediation: 'Validate redirect destinations against an allowlist of trusted URLs. Never redirect to user-supplied URLs without validation',
            });
            break; // One finding is sufficient
          }
        }

        // Check if evil.com appears in response body within href or script
        if (response.body.includes('evil.com')) {
          const inHref = /href=["'][^"']*evil\.com/i.test(response.body);
          const inScript = /<script[^>]*>[^<]*evil\.com/i.test(response.body);
          if (inHref || inScript) {
            findings.push({
              id: `open_redirect_reflected_${param}_${Date.now()}`,
              type: 'security_misconfiguration',
              severity: 'medium',
              title: `Reflected URL in Page via ?${param} Parameter`,
              description: `User-supplied URL is reflected in the page ${inScript ? 'within a script tag' : 'as a link href'}, potentially enabling phishing`,
              location: { endpoint: testUrl },
              remediation: 'Sanitize and validate all URL parameters before reflecting them in page content',
            });
            break;
          }
        }
      } catch (_error) {
        // Expected for most params
      }
    }

    return { findings, tokenUsage: 30 };
  }

  private async testMixedContent(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];

    try {
      const urlObj = new URL(targetUrl);
      if (urlObj.protocol !== 'https:') {
        return { findings, tokenUsage: 5 };
      }

      const response = await this.makeRequest(targetUrl, { method: 'GET' });
      const body = response.body;

      // Match http:// URLs in src/href attributes of script, link, img, iframe tags
      const mixedContentPattern = /<(?:script|link|img|iframe)[^>]+(?:src|href)=["']http:\/\/(?!xmlns|www\.w3\.org|schema\.org)[^"']+["']/gi;
      const matches = body.match(mixedContentPattern);

      if (matches && matches.length > 0) {
        const uniqueMatches = [...new Set(matches)].slice(0, 5); // Limit to 5 examples
        findings.push({
          id: `mixed_content_${Date.now()}`,
          type: 'security_misconfiguration',
          severity: 'medium',
          title: `Mixed Content: ${matches.length} HTTP Resource(s) on HTTPS Page`,
          description: `The HTTPS page loads ${matches.length} resource(s) over plain HTTP, which can be intercepted or modified by attackers. Examples: ${uniqueMatches.join(', ').substring(0, 300)}`,
          location: { endpoint: targetUrl },
          remediation: 'Update all resource URLs to use HTTPS, or use protocol-relative URLs (//). Add Content-Security-Policy: upgrade-insecure-requests',
        });
      }
    } catch (error) {
      console.error(`Mixed content test error: ${error instanceof Error ? error.message : 'Unknown'}`);
    }

    return { findings, tokenUsage: 20 };
  }

  private async testWafDetection(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];

    const payloads = [
      { payload: "' OR 1=1--", label: 'SQL injection' },
      { payload: '<script>alert(1)</script>', label: 'XSS' },
      { payload: '../../etc/passwd', label: 'path traversal' },
    ];

    const wafSignatures: Array<{ pattern: RegExp | string; name: string; location: 'header' | 'body' }> = [
      { pattern: /cloudflare/i, name: 'Cloudflare', location: 'header' },
      { pattern: /akamai/i, name: 'Akamai', location: 'header' },
      { pattern: /mod_security/i, name: 'ModSecurity', location: 'header' },
      { pattern: /awselb/i, name: 'AWS WAF/ELB', location: 'header' },
      { pattern: 'cf-ray', name: 'Cloudflare', location: 'header' },
      { pattern: 'x-sucuri-id', name: 'Sucuri', location: 'header' },
      { pattern: /blocked|access denied|forbidden.*security/i, name: 'Generic WAF', location: 'body' },
    ];

    let wafDetected = false;
    let wafName = 'Unknown';

    for (const { payload } of payloads) {
      try {
        const testUrl = `${targetUrl.replace(/\/+$/, '')}/?test=${encodeURIComponent(payload)}`;
        const response = await this.makeRequest(testUrl, { method: 'GET', timeout: 5000, maxRedirects: 0 });

        // WAF typically responds with 403, 406, or 429
        if ([403, 406, 429].includes(response.statusCode)) {
          wafDetected = true;
        }

        // Check headers and body for WAF signatures
        for (const sig of wafSignatures) {
          if (sig.location === 'header') {
            const headerStr = JSON.stringify(response.headers);
            if (typeof sig.pattern === 'string') {
              if (response.headers[sig.pattern]) {
                wafDetected = true;
                wafName = sig.name;
              }
            } else if (sig.pattern.test(headerStr)) {
              wafDetected = true;
              wafName = sig.name;
            }
          } else if (sig.location === 'body' && typeof sig.pattern !== 'string') {
            if (sig.pattern.test(response.body)) {
              wafDetected = true;
              if (wafName === 'Unknown') wafName = sig.name;
            }
          }
        }

        if (wafDetected) break;
      } catch (_error) {
        // Connection blocked could also indicate WAF
      }
    }

    if (wafDetected) {
      findings.push({
        id: `waf_detected_${Date.now()}`,
        type: 'information_disclosure',
        severity: 'informational',
        title: `Web Application Firewall Detected: ${wafName}`,
        description: `A WAF (${wafName}) is protecting the application. This is a positive security control but may affect testing accuracy`,
        location: { endpoint: targetUrl },
      });
    } else {
      findings.push({
        id: `waf_not_detected_${Date.now()}`,
        type: 'security_misconfiguration',
        severity: 'informational',
        title: 'No Web Application Firewall Detected',
        description: 'No WAF was detected protecting the application. Consider deploying a WAF for defense-in-depth',
        location: { endpoint: targetUrl },
        remediation: 'Deploy a Web Application Firewall (WAF) to provide additional protection against common web attacks',
      });
    }

    return { findings, tokenUsage: 30 };
  }

  private async testAuthenticationCheck(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];

    try {
      const response = await this.makeRequest(targetUrl, { method: 'GET' });
      const body = response.body;

      // Find forms containing password fields
      const formPattern = /<form[^>]*>([\s\S]*?)<\/form>/gi;
      let formMatch;

      while ((formMatch = formPattern.exec(body)) !== null) {
        const formTag = formMatch[0];
        const formContent = formMatch[1];

        // Check if form contains a password field
        if (!/type=["']password["']/i.test(formContent)) continue;

        // Check if form action uses HTTPS
        const actionMatch = formTag.match(/action=["']([^"']+)["']/i);
        if (actionMatch) {
          const actionUrl = actionMatch[1];
          if (actionUrl.startsWith('http://')) {
            findings.push({
              id: `auth_insecure_form_action_${Date.now()}`,
              type: 'security_misconfiguration',
              severity: 'medium',
              title: 'Login Form Submits Over HTTP',
              description: `A login form submits credentials to an insecure HTTP URL: ${actionUrl}`,
              location: { endpoint: targetUrl },
              remediation: 'Ensure all login forms submit credentials over HTTPS',
            });
          }
        }

        // Check for autocomplete on password fields
        const passwordFields = formContent.match(/<input[^>]+type=["']password["'][^>]*>/gi) || [];
        for (const field of passwordFields) {
          if (!/autocomplete=["']off["']/i.test(field) && !/autocomplete=["']new-password["']/i.test(field)) {
            findings.push({
              id: `auth_autocomplete_${Date.now()}`,
              type: 'security_misconfiguration',
              severity: 'low',
              title: 'Password Field Allows Autocomplete',
              description: 'Password input field does not disable autocomplete, which may allow browsers to store credentials',
              location: { endpoint: targetUrl },
              remediation: 'Add autocomplete="off" or autocomplete="new-password" to password input fields',
            });
            break; // One finding per form
          }
        }

        // Check for CAPTCHA
        const hasCaptcha = /recaptcha|hcaptcha|turnstile|captcha/i.test(body);
        if (!hasCaptcha) {
          findings.push({
            id: `auth_no_captcha_${Date.now()}`,
            type: 'security_misconfiguration',
            severity: 'low',
            title: 'Login Form Missing CAPTCHA Protection',
            description: 'No CAPTCHA (reCAPTCHA, hCaptcha, Turnstile) detected on login form, increasing brute-force risk',
            location: { endpoint: targetUrl },
            remediation: 'Add CAPTCHA or rate limiting to login forms to prevent automated brute-force attacks',
          });
        }

        break; // Only analyze first login form
      }
    } catch (error) {
      console.error(`Authentication check error: ${error instanceof Error ? error.message : 'Unknown'}`);
    }

    return { findings, tokenUsage: 25 };
  }

  private async testSessionAnalysis(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];

    const sessionCookieNames = [
      'phpsessid', 'jsessionid', 'connect.sid', 'asp.net_sessionid',
      'sessionid', 'session_id', 'sid', 'session', 'laravel_session',
    ];

    try {
      // First request to get initial session cookies
      const response1 = await this.makeRequest(targetUrl, { method: 'GET' });
      const cookies1 = this.getSetCookieHeaders(response1.headers);

      // Second request to compare
      const response2 = await this.makeRequest(targetUrl, { method: 'GET' });
      const cookies2 = this.getSetCookieHeaders(response2.headers);

      // Analyze session cookies from both responses
      const allCookies = [...cookies1, ...cookies2];

      for (const cookieStr of allCookies) {
        const nameValue = cookieStr.split(';')[0];
        const cookieName = nameValue.split('=')[0].trim().toLowerCase();
        const cookieValue = nameValue.split('=').slice(1).join('=').trim();

        if (!sessionCookieNames.includes(cookieName)) continue;

        // Check token entropy (length and character set)
        if (cookieValue.length < 16) {
          findings.push({
            id: `session_short_token_${Date.now()}`,
            type: 'security_misconfiguration',
            severity: 'high',
            title: `Session Token Too Short: ${cookieName}`,
            description: `Session cookie "${cookieName}" has a value of only ${cookieValue.length} characters, making it susceptible to brute-force`,
            location: { endpoint: targetUrl },
            remediation: 'Use session tokens of at least 128 bits (32 hex characters) generated by a cryptographically secure random number generator',
          });
        }

        // Check if token uses only numeric characters (low entropy)
        if (/^\d+$/.test(cookieValue)) {
          findings.push({
            id: `session_numeric_token_${Date.now()}`,
            type: 'security_misconfiguration',
            severity: 'high',
            title: `Session Token Uses Only Numeric Characters: ${cookieName}`,
            description: `Session cookie "${cookieName}" uses only digits, significantly reducing entropy and brute-force resistance`,
            location: { endpoint: targetUrl },
            remediation: 'Use alphanumeric session tokens with mixed case generated by a CSPRNG',
          });
        }

        break; // Analyze first session cookie only
      }

      // Session fixation check: compare session values between requests
      for (const cookie1 of cookies1) {
        const name1 = cookie1.split('=')[0].trim().toLowerCase();
        if (!sessionCookieNames.includes(name1)) continue;

        const value1 = cookie1.split(';')[0].split('=').slice(1).join('=').trim();

        for (const cookie2 of cookies2) {
          const name2 = cookie2.split('=')[0].trim().toLowerCase();
          if (name1 !== name2) continue;

          const value2 = cookie2.split(';')[0].split('=').slice(1).join('=').trim();

          // If same session ID issued to two different requests, potential fixation risk
          if (value1 === value2 && value1.length > 0) {
            findings.push({
              id: `session_fixation_risk_${Date.now()}`,
              type: 'security_misconfiguration',
              severity: 'medium',
              title: `Potential Session Fixation: ${name1}`,
              description: `The same session token is reissued across requests. Verify that session IDs are regenerated after authentication`,
              location: { endpoint: targetUrl },
              remediation: 'Regenerate session IDs after login and on privilege escalation. Invalidate old session tokens',
            });
          }
        }
      }
    } catch (error) {
      console.error(`Session analysis error: ${error instanceof Error ? error.message : 'Unknown'}`);
    }

    return { findings, tokenUsage: 30 };
  }

  private async testApiExposure(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];
    const baseUrl = targetUrl.replace(/\/+$/, '');

    const apiEndpoints: Array<{ path: string; description: string; severity: 'medium' | 'informational' }> = [
      { path: '/swagger.json', description: 'Swagger/OpenAPI specification', severity: 'medium' },
      { path: '/swagger-ui.html', description: 'Swagger UI interactive documentation', severity: 'medium' },
      { path: '/openapi.json', description: 'OpenAPI specification', severity: 'medium' },
      { path: '/api-docs', description: 'API documentation endpoint', severity: 'medium' },
      { path: '/graphql', description: 'GraphQL endpoint', severity: 'medium' },
      { path: '/graphiql', description: 'GraphiQL interactive IDE', severity: 'medium' },
      { path: '/api/docs', description: 'API documentation', severity: 'medium' },
      { path: '/v1/', description: 'API v1 endpoint', severity: 'informational' },
      { path: '/v2/', description: 'API v2 endpoint', severity: 'informational' },
      { path: '/.well-known/openid-configuration', description: 'OpenID Connect discovery document', severity: 'informational' },
    ];

    for (const endpoint of apiEndpoints) {
      try {
        const response = await this.makeRequest(`${baseUrl}${endpoint.path}`, {
          method: 'GET',
          timeout: 5000,
        });

        if (response.statusCode === 200 && response.body.length > 0) {
          const contentHint = response.body.substring(0, 100).replace(/[\n\r]/g, ' ').trim();
          findings.push({
            id: `api_exposure_${endpoint.path.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}`,
            type: 'information_disclosure',
            severity: endpoint.severity,
            title: `API Documentation Exposed: ${endpoint.path}`,
            description: `${endpoint.description} is publicly accessible at ${baseUrl}${endpoint.path}. Content preview: ${contentHint}...`,
            location: { endpoint: `${baseUrl}${endpoint.path}` },
            remediation: 'Restrict access to API documentation endpoints. Use authentication or IP allowlisting to protect them',
          });
        }
      } catch (_error) {
        // Expected for most endpoints
      }
    }

    return { findings, tokenUsage: 40 };
  }

  private async testSubdomainHeaders(targetUrl: string): Promise<TestResult> {
    const findings: Finding[] = [];

    try {
      const urlObj = new URL(targetUrl);
      const originalHost = urlObj.hostname;

      const maliciousHosts = ['evil.com', 'localhost', '127.0.0.1'];

      for (const fakeHost of maliciousHosts) {
        try {
          const response = await this.makeRequest(targetUrl, {
            method: 'GET',
            headers: { 'Host': fakeHost },
            timeout: 5000,
          });

          // If server responds 200 to a manipulated Host header, it may be vulnerable
          if (response.statusCode === 200) {
            // Check if the response contains the fake host (reflected in content)
            if (response.body.includes(fakeHost)) {
              findings.push({
                id: `vhost_reflection_${fakeHost.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}`,
                type: 'security_misconfiguration',
                severity: 'medium',
                title: `Host Header Reflected in Response`,
                description: `Setting Host header to "${fakeHost}" results in the value being reflected in the response body. This may enable cache poisoning or phishing attacks`,
                location: { endpoint: targetUrl },
                remediation: 'Configure the web server to reject requests with unrecognized Host headers. Use a strict virtual host configuration',
              });
              break;
            }

            // Server didn't reject the fake host
            findings.push({
              id: `vhost_accepted_${fakeHost.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}`,
              type: 'security_misconfiguration',
              severity: 'low',
              title: `Server Accepts Arbitrary Host Header: ${fakeHost}`,
              description: `The server responds normally when the Host header is set to "${fakeHost}" instead of "${originalHost}"`,
              location: { endpoint: targetUrl },
              remediation: 'Configure a default virtual host that rejects requests with unrecognized Host headers (return 444 in nginx, or use ServerName strictly in Apache)',
            });
            break;
          }
        } catch (_error) {
          // Connection errors with manipulated host are expected
        }
      }
    } catch (error) {
      console.error(`Subdomain headers test error: ${error instanceof Error ? error.message : 'Unknown'}`);
    }

    return { findings, tokenUsage: 20 };
  }

  private inspectCertificate(
    hostname: string,
    port: number
  ): Promise<{ selfSigned: boolean; expired: boolean; expiringSoon: boolean; validTo: string; protocol: string | null }> {
    return new Promise((resolve, reject) => {
      const socket = tls.connect(
        {
          host: hostname,
          port,
          rejectUnauthorized: false,
          servername: hostname,
        },
        () => {
          const cert = socket.getPeerCertificate();
          const protocol = socket.getProtocol();
          socket.end();

          if (!cert || !cert.valid_to) {
            resolve({
              selfSigned: false,
              expired: false,
              expiringSoon: false,
              validTo: 'unknown',
              protocol,
            });
            return;
          }

          const validTo = new Date(cert.valid_to);
          const now = new Date();
          const thirtyDays = 30 * 24 * 60 * 60 * 1000;

          const selfSigned = cert.issuer && cert.subject
            && JSON.stringify(cert.issuer) === JSON.stringify(cert.subject);

          resolve({
            selfSigned: !!selfSigned,
            expired: validTo < now,
            expiringSoon: !!(validTo > now && (validTo.getTime() - now.getTime()) < thirtyDays),
            validTo: cert.valid_to,
            protocol,
          });
        }
      );

      socket.setTimeout(10000);
      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('TLS connection timeout'));
      });
      socket.on('error', (err) => {
        reject(err);
      });
    });
  }

  private makeRequest(
    targetUrl: string,
    options: {
      method?: string;
      headers?: Record<string, string>;
      timeout?: number;
      maxRedirects?: number;
    } = {}
  ): Promise<HttpResponse> {
    const { method = 'GET', headers = {}, timeout = 10000, maxRedirects = 3 } = options;

    return new Promise((resolve, reject) => {
      const urlObj = new URL(targetUrl);
      const isHttps = urlObj.protocol === 'https:';
      const transport = isHttps ? https : http;

      const requestOptions: http.RequestOptions = {
        hostname: urlObj.hostname,
        port: urlObj.port || (isHttps ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method,
        headers: {
          'User-Agent': 'MCP-Shamash-SecurityScanner/1.0',
          ...headers,
        },
        timeout,
      };

      if (isHttps) {
        (requestOptions as https.RequestOptions).rejectUnauthorized = false;
      }

      const req = transport.request(requestOptions, (res) => {
        // Handle redirects
        if (
          res.statusCode &&
          [301, 302, 303, 307, 308].includes(res.statusCode) &&
          res.headers.location &&
          maxRedirects > 0
        ) {
          let redirectUrl = res.headers.location;
          if (redirectUrl.startsWith('/')) {
            redirectUrl = `${urlObj.protocol}//${urlObj.host}${redirectUrl}`;
          }
          res.resume(); // Drain the response
          this.makeRequest(redirectUrl, { ...options, maxRedirects: maxRedirects - 1 })
            .then(resolve)
            .catch(reject);
          return;
        }

        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode || 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf-8'),
            redirectUrl: res.headers.location,
          });
        });
        res.on('error', reject);
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Request timeout after ${timeout}ms`));
      });

      req.on('error', reject);
      req.end();
    });
  }

  private getSetCookieHeaders(headers: http.IncomingHttpHeaders): string[] {
    const raw = headers['set-cookie'];
    if (!raw) return [];
    return Array.isArray(raw) ? raw : [raw];
  }

  private calculateSummary(findings: Finding[]) {
    const summary = {
      vulnerabilities: findings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
    };

    for (const finding of findings) {
      summary[finding.severity]++;
    }

    return summary;
  }

  private getDefaultTests(profile?: string): TestType[] {
    return PROFILE_TESTS[profile || 'standard'] || PROFILE_TESTS['standard'];
  }

  private generateScanId(): string {
    return `website_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}
