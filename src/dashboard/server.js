'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const MIME = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml' };

class Dashboard {
  constructor(options = {}) {
    this.port = options.port || 9090;
    this.host = options.host || 'localhost';
    this.engine = options.engine;
    this.publicDir = path.join(__dirname, 'public');
    this.wsClients = new Set();
    this.server = null;

    if (this.engine) {
      this.engine.on('log', (e) => this.broadcast(JSON.stringify({ type: 'log', data: e })));
      this.engine.on('threat', (e) => this.broadcast(JSON.stringify({ type: 'threat', data: e })));
    }
  }

  start() {
    this.server = http.createServer((req, res) => this._http(req, res));
    this.server.on('upgrade', (req, socket) => this._upgrade(req, socket));
    this.server.listen(this.port, this.host, () => {
      this.engine?.logger.info(`Dashboard at http://${this.host}:${this.port}`);
    });
    this.server.on('error', (err) => this.engine?.logger.error(`Dashboard: ${err.message}`));
  }

  _http(req, res) {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (url.pathname.startsWith('/api/')) return this._api(req, res);

    let file = url.pathname === '/' ? '/index.html' : url.pathname;
    file = path.join(this.publicDir, file);

    // prevent traversal on our own dashboard
    if (!path.resolve(file).startsWith(path.resolve(this.publicDir))) { res.writeHead(403); res.end('Forbidden'); return; }

    fs.readFile(file, (err, data) => {
      if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('Not Found'); return; }
      res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(data);
    });
  }

  _api(req, res) {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');
    const json = (d) => { res.writeHead(200); res.end(JSON.stringify(d)); };
    const err = (m, code = 400) => { res.writeHead(code); res.end(JSON.stringify({ error: m })); };

    if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const data = JSON.parse(body);
          if (pathname === '/api/rules/save') {
            if (!data.filename || !data.content) return err('Missing filename or content');
            const safeFile = path.basename(data.filename);
            const fullPath = path.join(this.engine.options.rulesDir, safeFile);
            fs.writeFileSync(fullPath, data.content, 'utf8');
            this.engine.reloadRules();
            return json({ success: true });
          }
          err('Not found');
        } catch (e) { err('Invalid JSON'); }
      });
      return;
    }

    switch (pathname) {
      case '/api/stats': return json(this.engine?.getStats() || {});
      case '/api/history': return json(this.engine?.logger.getHistory(200) || []);
      case '/api/rules': return json((this.engine?.rules || []).map(r => ({ name: r.name, tags: r.tags, severity: r.meta?.severity, description: r.meta?.description, source: r.sourceFile })));
      case '/api/rules/content': {
        const file = url.searchParams.get('file');
        if (!file) return err('Missing file param');
        const safeFile = path.basename(file);
        const fullPath = path.join(this.engine.options.rulesDir, safeFile);
        try {
          const content = fs.readFileSync(fullPath, 'utf8');
          return json({ content });
        } catch (e) { return err('File not found', 404); }
      }
      case '/api/geo-data': {
        const attacks = this.engine?.logger.getHistory(500).filter(e => e.type === 'attack') || [];
        const geoPoints = attacks.map(a => ({ ip: a.ip, geo: a.geo, severity: a.severity, timestamp: a.timestamp }));
        return json(geoPoints);
      }
      default: err('Not found', 404);
    }
  }

  _upgrade(req, socket) {
    const key = req.headers['sec-websocket-key'];
    if (!key) { socket.destroy(); return; }

    const accept = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-5AB5DC11AD35').digest('base64');
    socket.write(['HTTP/1.1 101 Switching Protocols', 'Upgrade: websocket', 'Connection: Upgrade', `Sec-WebSocket-Accept: ${accept}`, '', ''].join('\r\n'));

    this.wsClients.add(socket);

    if (this.engine) {
      this._wsSend(socket, JSON.stringify({ type: 'init', data: { stats: this.engine.getStats(), recentEvents: this.engine.logger.getHistory(50) } }));
    }

    socket.on('data', (buf) => { try { if (buf.length >= 2 && (buf[0] & 0x0f) === 0x08) { socket.end(); this.wsClients.delete(socket); } } catch {} });
    socket.on('close', () => this.wsClients.delete(socket));
    socket.on('error', () => this.wsClients.delete(socket));
  }

  _wsSend(socket, data) {
    const payload = Buffer.from(data, 'utf-8');
    let frame;
    if (payload.length < 126) { frame = Buffer.alloc(2 + payload.length); frame[0] = 0x81; frame[1] = payload.length; payload.copy(frame, 2); }
    else if (payload.length < 65536) { frame = Buffer.alloc(4 + payload.length); frame[0] = 0x81; frame[1] = 126; frame.writeUInt16BE(payload.length, 2); payload.copy(frame, 4); }
    else { frame = Buffer.alloc(10 + payload.length); frame[0] = 0x81; frame[1] = 127; frame.writeBigUInt64BE(BigInt(payload.length), 2); payload.copy(frame, 10); }
    try { socket.write(frame); } catch { this.wsClients.delete(socket); }
  }

  broadcast(data) { for (const c of this.wsClients) this._wsSend(c, data); }
  stop() { for (const c of this.wsClients) c.destroy(); this.wsClients.clear(); this.server?.close(); }
}

module.exports = Dashboard;
