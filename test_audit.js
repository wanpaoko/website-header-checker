const path = require('path');
const PhpSecAudit = require(path.resolve('src/cve_database.js'));

let total = 0;
let passed = 0;

function assert(cond, msg) {
  total++;
  if (!cond) {
    console.error(`❌ FAIL: ${msg}`);
  } else {
    passed++;
    console.log(`✅ PASS: ${msg}`);
  }
}

console.log('=== Web Server & Backend Vulnerability Auditor Comprehensive Tests ===\n');

// 1. PHP Version & CVE-2024-4577 Tests
console.log('-- [1] PHP Tests --');
const php812 = PhpSecAudit.auditTarget({
  url: 'https://php-test.local/index.php',
  headers: { 'x-powered-by': 'PHP/8.1.2' }
});
assert(php812.detectedTechs.some(t => t.tech === 'PHP' && t.version === '8.1.2'), 'Detect PHP 8.1.2');
assert(php812.vulnerabilities.some(v => v.id === 'CVE-2024-4577'), 'PHP 8.1.2 matches CVE-2024-4577');
assert(php812.riskLevel === 'CRITICAL', 'PHP 8.1.2 marked CRITICAL');

const php8220 = PhpSecAudit.auditTarget({
  url: 'https://php-test.local/index.php',
  headers: { 'x-powered-by': 'PHP/8.2.20' }
});
assert(!php8220.vulnerabilities.some(v => v.id === 'CVE-2024-4577'), 'PHP 8.2.20 patched CVE-2024-4577');

// 2. Node.js Tests
console.log('\n-- [2] Node.js Tests --');
const node2011 = PhpSecAudit.auditTarget({
  url: 'https://node-app.local/',
  headers: {
    'server': 'Node.js/v20.11.0',
    'x-powered-by': 'Express'
  },
  cookies: 'connect.sid=s%3Aabc123'
});
assert(node2011.detectedTechs.some(t => t.tech === 'NODEJS' && t.version === '20.11.0'), 'Detect Node.js 20.11.0');
assert(node2011.vulnerabilities.some(v => v.id === 'CVE-2024-27980'), 'Node 20.11.0 matches CVE-2024-27980 (HTTP/2 DoS)');
assert(node2011.vulnerabilities.some(v => v.id === 'CVE-2024-21892'), 'Node 20.11.0 matches CVE-2024-21892');

const node2012 = PhpSecAudit.auditTarget({
  url: 'https://node-app.local/',
  headers: { 'server': 'Node.js/v20.12.2' }
});
assert(!node2012.vulnerabilities.some(v => v.id === 'CVE-2024-27980'), 'Node 20.12.2 patched CVE-2024-27980');

const node16 = PhpSecAudit.auditTarget({
  url: 'https://node-old.local/',
  headers: { 'server': 'Node.js/v16.20.2' }
});
assert(node16.vulnerabilities.some(v => v.id === 'NODE-EOL'), 'Node 16.20.2 flagged as EOL');

// 3. Apache HTTP Server Tests
console.log('\n-- [3] Apache Tests --');
const apache49 = PhpSecAudit.auditTarget({
  url: 'https://apache-target.local/',
  headers: { 'server': 'Apache/2.4.49 (Unix)' }
});
assert(apache49.detectedTechs.some(t => t.tech === 'APACHE' && t.version === '2.4.49'), 'Detect Apache 2.4.49');
assert(apache49.vulnerabilities.some(v => v.id === 'CVE-2021-41773'), 'Apache 2.4.49 matches CVE-2021-41773 (Path Traversal / RCE)');
assert(apache49.riskLevel === 'CRITICAL', 'Apache 2.4.49 marked CRITICAL');

const apache52 = PhpSecAudit.auditTarget({
  url: 'https://apache-target.local/',
  headers: { 'server': 'Apache/2.4.52 (Ubuntu)' }
});
assert(apache52.vulnerabilities.some(v => v.id === 'CVE-2023-25690'), 'Apache 2.4.52 matches CVE-2023-25690 (Request Smuggling)');
assert(apache52.vulnerabilities.some(v => v.id === 'CVE-2024-38472'), 'Apache 2.4.52 matches CVE-2024-38472 (mod_rewrite SSRF)');

const apache60 = PhpSecAudit.auditTarget({
  url: 'https://apache-target.local/',
  headers: { 'server': 'Apache/2.4.60 (Unix)' }
});
assert(!apache60.vulnerabilities.some(v => v.id === 'CVE-2024-38472'), 'Apache 2.4.60 patched CVE-2024-38472');

// 4. Nginx Tests
console.log('\n-- [4] Nginx Tests --');
const nginx261 = PhpSecAudit.auditTarget({
  url: 'https://nginx-target.local/',
  headers: { 'server': 'nginx/1.26.1' }
});
assert(nginx261.detectedTechs.some(t => t.tech === 'NGINX' && t.version === '1.26.1'), 'Detect Nginx 1.26.1');
assert(nginx261.vulnerabilities.some(v => v.id === 'CVE-2024-7347'), 'Nginx 1.26.1 matches CVE-2024-7347 (Buffer Underflow)');

const nginx262 = PhpSecAudit.auditTarget({
  url: 'https://nginx-target.local/',
  headers: { 'server': 'nginx/1.26.2' }
});
assert(!nginx262.vulnerabilities.some(v => v.id === 'CVE-2024-7347'), 'Nginx 1.26.2 patched CVE-2024-7347');

const nginx18 = PhpSecAudit.auditTarget({
  url: 'https://nginx-target.local/',
  headers: { 'server': 'nginx/1.18.0' }
});
assert(nginx18.vulnerabilities.some(v => v.id === 'CVE-2021-23017'), 'Nginx 1.18.0 matches CVE-2021-23017 (DNS Resolver overflow)');

// 5. Microsoft IIS Tests
console.log('\n-- [5] Microsoft IIS Tests --');
const iisAudit = PhpSecAudit.auditTarget({
  url: 'https://windows-server.local/',
  headers: { 'server': 'Microsoft-IIS/10.0' }
});
assert(iisAudit.detectedTechs.some(t => t.tech === 'IIS' && t.version === '10.0'), 'Detect Microsoft IIS 10.0');
assert(iisAudit.vulnerabilities.some(v => v.id === 'CVE-2022-21907'), 'IIS 10.0 matches CVE-2022-21907 (http.sys RCE)');

// 6. Apache Tomcat Tests
console.log('\n-- [6] Apache Tomcat Tests --');
const tomcatAudit = PhpSecAudit.auditTarget({
  url: 'https://java-app.local/',
  headers: { 'server': 'Apache Tomcat/9.0.30' },
  cookies: 'JSESSIONID=123456789'
});
assert(tomcatAudit.detectedTechs.some(t => t.tech === 'TOMCAT' && t.version === '9.0.30'), 'Detect Tomcat 9.0.30');
assert(tomcatAudit.vulnerabilities.some(v => v.id === 'CVE-2020-1938'), 'Tomcat 9.0.30 matches Ghostcat CVE-2020-1938');

// 7. Security Headers Checks
console.log('\n-- [7] Security Headers Checks --');
const headerChecks = PhpSecAudit.auditSecurityHeaders({
  'x-powered-by': 'Express',
  'server': 'nginx/1.24.0',
  'strict-transport-security': 'max-age=31536000',
  'content-security-policy': "default-src 'self'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY'
});
const expressWarn = headerChecks.checks.find(c => c.key === 'expose_backend');
assert(expressWarn && expressWarn.status === 'WARN', 'Flag X-Powered-By: Express as WARN');

const serverVerWarn = headerChecks.checks.find(c => c.key === 'server_tokens');
assert(serverVerWarn && serverVerWarn.status === 'WARN', 'Flag server_tokens disclosure as WARN');

// 8. Multi-technology Simultaneous Detection
console.log('\n-- [8] Multi-technology Stack Detection --');
const multiStack = PhpSecAudit.auditTarget({
  url: 'https://enterprise-portal.local/',
  headers: {
    'server': 'Apache/2.4.52 (Ubuntu) OpenSSL/3.0.2',
    'x-powered-by': 'PHP/8.1.2'
  },
  cookies: 'PHPSESSID=session123'
});
assert(multiStack.detectedTechs.length === 2, 'Simultaneously detected 2 technologies (Apache and PHP)');
assert(multiStack.vulnerabilities.some(v => v.tech === 'PHP' && v.id === 'CVE-2024-4577'), 'Contains PHP CVE');
assert(multiStack.vulnerabilities.some(v => v.tech === 'APACHE' && v.id === 'CVE-2023-25690'), 'Contains Apache CVE');

console.log(`\n========================================`);
console.log(`Results: ${passed}/${total} test assertions PASSED.`);
console.log(`========================================`);
process.exit(total === passed ? 0 : 1);
