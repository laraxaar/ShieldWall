'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const BASE_URL = 'http://localhost:5500';
const CONCURRENCY = 15;

const PAYLOADS = [
  // --- ELITE & UNIQUE VECTORS ---
  { 
    name: 'Unique: Fat GET', 
    method: 'GET', 
    url: '/api/v1/user', 
    body: '{"admin": true, "cmd": "rm -rf /"}', 
    cat: 'bypass' 
  },
  { 
    name: 'Unique: Verb Tampering (DEBUG)', 
    method: 'DEBUG', 
    url: '/api/admin?cmd=drop+db', 
    cat: 'bypass' 
  },
  { 
    name: 'Unique: Unicode Homograph', 
    method: 'GET', 
    url: '/?q=%ef%bc%9cscript%ef%bc%9e', // ＜script＞
    cat: 'evasion' 
  },
  { 
    name: 'Elite: JSON Padding Bypass', 
    method: 'POST', 
    body: '{"junk": "' + " ".repeat(50000) + '", "attack": "<script>alert(1)</script>"}', 
    cat: 'evasion' 
  },
  { 
    name: 'Elite: Path Confusion (..;)', 
    method: 'GET', 
    url: '/api/v1/login/..;/admin/settings', 
    cat: 'bypass' 
  },
  { 
    name: 'Elite: Double Method Header', 
    method: 'POST', 
    headers: { 'X-HTTP-Method-Override': 'DELETE' }, 
    url: '/api/user/1', 
    cat: 'logic' 
  },
  { 
    name: 'Elite: Charset Evasion (Latin1)', 
    method: 'POST', 
    headers: { 'Content-Type': 'application/json; charset=latin1' },
    body: Buffer.from('{"test": "<script>"}', 'ascii').toString('latin1'),
    cat: 'evasion' 
  },
  {
    name: 'Elite: Entropy Camouflage',
    method: 'POST',
    body: '{"log": "' + "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(100) + '", "payload": "<script>eval(atob(\'YWxlcnQoMSk=\'))</script>"}',
    cat: 'evasion'
  },
  {
    name: 'Elite: Polyglot Bypass',
    method: 'POST',
    body: '{"test": "s\u00df", "cmd": "\uFF0527 OR \uFF0531=\uFF0531"}', // ß -> ss, ％ -> %
    cat: 'evasion'
  },

  // --- CROSS-REQUEST SPLITTING ---
  { name: 'Cross: Splitting Part 1', url: '/?q=SELECT+username', cat: 'zero-day' },
  { name: 'Cross: Splitting Part 2', url: '/?q=FROM+users', cat: 'zero-day' },

  // --- ZERO-DAY BASELINE ---
  { name: 'Z-Day: JSON Duplicate Keys', method: 'POST', body: '{"id": 1, "id": "admin\'--"}', cat: 'zero-day' },
  { name: 'Z-Day: Null Byte Param', url: '/?q=test%00<script>', cat: 'zero-day' },
  
  // --- FP BASELINE ---
  { name: 'FP: Safe API Call', url: '/api/v1/status', cat: 'fp' }
];

async function runTest(p) {
  return new Promise((resolve) => {
    const startTime = process.hrtime.bigint();
    const options = {
      method: p.method || 'GET',
      headers: {
        'User-Agent': 'ShieldWall-Elite/5.0',
        'X-Forwarded-For': '198.51.100.42', // Simulated attacker IP (prevents localhost whitelist)
        'Content-Type': p.headers?.['Content-Type'] || (p.body ? 'application/json' : 'text/plain'),
        ...p.headers
      }
    };

    const req = http.request(BASE_URL + (p.url || '/'), options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        const latency = Number(process.hrtime.bigint() - startTime) / 1e6;
        resolve({ status: res.statusCode, latency, blocked: res.statusCode >= 400 });
      });
    });

    req.on('error', (e) => resolve({ error: e.message, latency: 0 }));
    if (p.body) req.write(p.body);
    req.end();
  });
}

// Special test for Chunked Smuggling
async function testChunked() {
  console.log('\x1b[33m%s\x1b[0m', 'PHASE 3: Chunked Request Smuggling Check...');
  return new Promise((resolve) => {
    const options = {
      method: 'POST',
      url: '/api/v1/test',
      headers: { 'Transfer-Encoding': 'chunked', 'Content-Type': 'application/json' }
    };

    const req = http.request(BASE_URL + options.url, options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        const blocked = res.statusCode >= 400;
        console.log(blocked ? ' ✅ Blocked Chunked Attack' : ' ❌ Passed Chunked Attack!');
        resolve(blocked);
      });
    });

    // Send payload in chunks: {"test": "<script>"}
    req.write('a\r\n{"test": "\r\n');
    setTimeout(() => {
      req.write('b\r\n<script>"} \r\n');
      req.write('0\r\n\r\n');
      req.end();
    }, 200);

    req.on('error', (e) => resolve(false));
  });
}

async function start() {
  console.log('\x1b[35m%s\x1b[0m', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('\x1b[35m%s\x1b[0m', '🛡️  SHIELDWALL ELITE STRESSER v5.0');
  console.log('\x1b[35m%s\x1b[0m', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  const stats = { total: 0, blocked: 0, bypassed: 0 };

  for (const p of PAYLOADS) {
    const res = await runTest(p);
    stats.total++;
    const status = res.blocked ? '\x1b[32m[BLOCKED]\x1b[0m' : (p.cat === 'fp' ? '\x1b[32m[PASS]\x1b[0m' : '\x1b[31m[BYPASS]\x1b[0m');
    console.log(`${p.cat.toUpperCase().padEnd(10)} | ${p.name.padEnd(30)} | ${status} | ${res.latency.toFixed(2)}ms`);
    if (!res.blocked && p.cat !== 'fp') stats.bypassed++;
    else if (res.blocked && p.cat !== 'fp') stats.blocked++;
  }

  await testChunked();

  console.log('\x1b[35m%s\x1b[0m', '\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`🛡️  Elite Success Rate: ${((stats.blocked / (stats.blocked + stats.bypassed)) * 100).toFixed(1)}%`);
  console.log('\x1b[35m%s\x1b[0m', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
}

start().catch(console.error);
