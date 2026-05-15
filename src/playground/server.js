'use strict';

const http = require('http');
const path = require('path');
const fs = require('fs');
const ShieldWall = require('../index');

class PlaygroundServer {
  constructor(options = {}) {
    this.port = options.port || 5500;
    this.engine = new ShieldWall.ShieldWallEngine({
      mode: 'log', // Never block in playground
      trustProxy: true,
      logging: {
        logFile: path.join(process.cwd(), 'logs', 'waf.log'),
        level: 'debug'
      },
      excludeIPs: ['127.0.0.1', '::1'],
      modules: { smartAnomaly: true, adaptiveBaselines: true }
    });
    this.publicDir = path.join(__dirname, '..', 'dashboard', 'public');
    this.sseClients = [];
  }

  _broadcastSse(data) {
    const payload = `data: ${JSON.stringify(data)}\n\n`;
    this.sseClients.forEach(client => {
      try { client.write(payload); } catch (e) {}
    });
  }

  start() {
    this.server = http.createServer((req, res) => this._handle(req, res));
    this.server.listen(this.port, () => {
      console.log(`🧪 ShieldWall Lab started at http://localhost:${this.port}`);
      console.log(`📝 Logs: logs/waf.log`);
      
      // Auto-start stresser in a separate process
      const { spawn } = require('child_process');
      const stresser = spawn('node', [path.join(__dirname, 'stresser.js')], {
        stdio: 'inherit'
      });
      stresser.on('exit', () => console.log('✅ Initial stress test complete.'));
    });
  }

  async _handle(req, res) {
    // Collect body with size limit (2MB)
    let body = '';
    const MAX_BODY_SIZE = 2 * 1024 * 1024;
    
    await new Promise((resolve, reject) => {
      req.on('data', chunk => {
        body += chunk;
        if (body.length > MAX_BODY_SIZE) {
          res.writeHead(413);
          res.end('Payload Too Large');
          req.destroy();
          reject(new Error('Payload too large'));
        }
      });
      req.on('end', resolve);
    });
    req.body = body;

    // Run through WAF Engine
    const result = await this.engine.analyze(req, res);
    
    // Send live telemetry to the Dashboard via SSE
    this._broadcastSse(result);

    // If blocked, send 403 and return
    if (result.blocked) {
      const status = result.mitigation?.type === 'throttle' ? 429 : 403;
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ 
        error: 'Forbidden by ShieldWall WAF', 
        riskScore: result.riskScore,
        highestSeverity: result.highestSeverity,
        matches: result.matches.map(m => ({ rule: m.rule, severity: m.severity })),
        trace: result.trace 
      }));
      return;
    }

    // --- API & Static Route Handling ---
    const url = req.url.split('?')[0];

    // Slowloris simulation route
    if (url === '/slow') {
      res.writeHead(200);
      res.write('Starting slow response...');
      // In a real WAF, we would time out this connection
      return;
    }

    // Specialized API for the Lab UI
    if (req.method === 'POST' && url === '/api/test') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(result));
      this._broadcastSse(result);
      return;
    }

    if (req.method === 'GET' && url === '/api/live-logs') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive'
      });
      res.write(': connected\n\n'); // Force browser EventSource out of CONNECTING state
      
      this.sseClients.push(res);
      req.on('close', () => {
        this.sseClients = this.sseClients.filter(client => client !== res);
      });
      return;
    }

    // Simulated "Real" App Routes
    let responseBody = '';
    let responseStatus = 200;

    if (url === '/') return this._serveFile('index.html', res);
    
    // Check if the requested URL is a static file in publicDir
    const potentialFile = path.join(this.publicDir, url);
    if (fs.existsSync(potentialFile) && fs.statSync(potentialFile).isFile()) {
      return this._serveFile(url, res);
    }
    
    if (url.startsWith('/api/v1/')) {
      responseBody = JSON.stringify({ status: 'success', data: { message: 'Processed' } });
    } else if (url.startsWith('/static/')) {
      // Simulate XXE target or sensitive file access
      if (url.includes('etc/passwd')) responseBody = 'root:x:0:0:root:/root:/bin/bash';
      else responseBody = 'Static content';
    } else {
      responseStatus = 404;
      responseBody = 'Not Found';
    }

    // --- DLP (Data Loss Prevention) Check ---
    const dlpMatches = this.engine.analyzeResponse(responseBody);
    if (dlpMatches.length > 0) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Blocked by DLP policy', matches: dlpMatches }));
      return;
    }

    res.writeHead(responseStatus, { 'Content-Type': 'application/json' });
    res.end(responseBody);
  }

  _serveFile(file, res) {
    const fullPath = path.join(this.publicDir, file);
    if (fs.existsSync(fullPath)) {
      const ext = path.extname(fullPath);
      const types = { 
        '.html': 'text/html; charset=utf-8', 
        '.js': 'text/javascript; charset=utf-8', 
        '.css': 'text/css; charset=utf-8' 
      };
      res.writeHead(200, { 'Content-Type': types[ext] || 'text/plain; charset=utf-8' });
      res.end(fs.readFileSync(fullPath));
    } else {
      res.writeHead(404);
      res.end('Not found');
    }
  }
}

const lab = new PlaygroundServer();
lab.start();
