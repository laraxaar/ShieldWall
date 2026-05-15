'use strict';

const path = require('path');
const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const COLORS = { error: '\x1b[31m', warn: '\x1b[33m', info: '\x1b[36m', debug: '\x1b[90m' };
const SEVERITY_ICONS = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', info: 'ℹ️' };
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

class Logger {
  constructor(options = {}) {
    this.level = LEVELS[options.level] ?? LEVELS.info;
    this.silent = options.silent || false;
    this.jsonOutput = options.json || false;
    this.onEvent = options.onEvent || null;
    this.siemWebhook = options.siemWebhook || process.env.SHIELDWALL_WEBHOOK || null;
    this.logFile = options.logFile || path.join(process.cwd(), 'logs', 'waf.log');
    this.history = [];
    this.maxHistory = options.maxHistory || 1000;

    if (this.logFile) {
      const dir = path.dirname(this.logFile);
      if (!require('fs').existsSync(dir)) require('fs').mkdirSync(dir, { recursive: true });
    }
  }

  _writeToFile(entry) {
    if (!this.logFile) return;
    try {
      const fs = require('fs');
      const text = typeof entry === 'string' ? entry : JSON.stringify(entry);
      fs.appendFileSync(this.logFile, text + '\n');
    } catch (e) {
      console.error('[ShieldWall] Failed to write to log file:', e.message);
    }
  }

  _log(level, message, data = null) {
    if (this.silent || LEVELS[level] > this.level) return;

    const entry = { timestamp: new Date().toISOString(), level, message, ...(data && { data }) };
    this._store(entry);
    
    const icon = level === 'error' ? '🚨' : (level === 'warn' ? '⚠️' : 'ℹ️');
    const c = COLORS[level] || '';
    const bar = '━━━━━━━━━━━━━━━━━━━━';
    
    if (this.jsonOutput) {
      console.log(JSON.stringify(entry));
    } else {
      console.log(`\n${icon} ${BOLD}${c}[SHIELDWALL ${level.toUpperCase()}]${RESET}`);
      console.log(`\x1b[90m${bar}${RESET}`);
      console.log(`📝 Message: ${message}`);
      if (data) {
        console.log(`📦 Data:\n\x1b[90m${JSON.stringify(data, null, 2)}${RESET}`);
      }
      console.log(`\x1b[90m${bar}${RESET}`);
      console.log(`⏰ Timestamp: ${entry.timestamp}\n`);
    }

    this._writeToFile(`[${entry.timestamp}] [${level.toUpperCase()}] ${message} ${data ? JSON.stringify(data) : ''}`);
  }

  /**
   * Detailed Inspection Trace
   * Used for high-fidelity debugging and "logging every sneeze"
   */
  attack(event) {
    const { timestamp, blocked, riskScore, request, matches, trace } = event;
    const icon = blocked ? '🛡️' : '✅';
    const status = blocked ? 'BLOCKED' : 'CLEAN';
    const traceId = Math.random().toString(36).substring(2, 10).toUpperCase();

    const bar = '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━';
    const subBar = '╶──────────────────────────────────────────────────────────╴';

    let output = `\n${bar}\n`;
    output += `${icon}  DETAILED INSPECTION TRACE [${traceId}] - ${status}\n`;
    output += `${bar}\n`;
    output += `📅 Timestamp : ${timestamp}\n`;
    output += `🌐 Client IP : ${request.ip}\n`;
    output += `🛰️  Target    : ${request.method} ${request.url}\n`;
    output += `📊 Risk Score: ${riskScore.toFixed(1)}\n`;
    output += `${subBar}\n`;
    
    output += `🔍 INSPECTION PIPELINE:\n`;
    if (trace && Array.isArray(trace)) {
      for (const step of trace) {
        const ms = String(step.ms || '0.000').padStart(8);
        output += `  [${ms}ms] ‣ ${String(step.step).padEnd(20)} | ${JSON.stringify(step.data)}\n`;
      }
    }

    if (matches && matches.length > 0) {
      output += `${subBar}\n`;
      output += `🧨 DETECTED THREATS:\n`;
      for (const m of matches) {
        output += `  ● [${String(m.severity).toUpperCase()}] ${m.rule} -> ${m.description}\n`;
      }
    }

    output += `${bar}\n`;

    // Console output for Lab visibility (only if debug or blocked)
    if (this.level === 0 || blocked) {
      console.log(output);
    }

    // File logging
    this._writeToFile(output);
  }

  error(msg, data) { this._log('error', msg, data); }
  warn(msg, data)  { this._log('warn', msg, data); }
  info(msg, data)  { this._log('info', msg, data); }
  debug(msg, data) { this._log('debug', msg, data); }

  // Structured security event with WHY/Evidence explanation
  attack(event) {
    const icon = SEVERITY_ICONS[event.severity] || '⚠️';
    const action = event.blocked ? 'BLOCKED' : 'DETECTED';
    const traceId = event.traceId || 'N/A';

    const entry = {
      timestamp: new Date().toISOString(),
      level: 'warn',
      type: 'attack',
      action: event.blocked ? 'blocked' : 'detected',
      rule: event.rule || 'unknown',
      severity: event.severity || 'medium',
      category: event.category || 'unknown',
      ip: event.ip || 'unknown',
      method: event.method || 'GET',
      url: event.url || '/',
      description: event.description || '',
      matchedPattern: event.matchedPattern || null,
      analysis: event.analysis || null,
      traceId,
      geo: event.geo || 'N/A',
      device: event.device || 'N/A',
      traffic: event.traffic || { in: 0, out: 0 },
      ja3: event.ja3 || 'N/A',
      h2: event.h2 || 'H1.1',
      headers: event.headerSignature || 'N/A',
      rawHeaders: event.rawHeaders || [],
      proxyChain: event.proxyChain || 0,
      leakShield: event.leakShield || 'CLEAN',
      signals: event.signals || [],
      payload: event.payload || 'None',
    };

    this._store(entry);

    if (this.siemWebhook) {
      this.exportToSIEM(entry);
    }

    if (!this.silent) {
      if (this.jsonOutput) {
        console.log(JSON.stringify(entry));
      } else {
        const sevColor = event.severity === 'critical' ? '\x1b[31m' : (event.severity === 'high' ? '\x1b[33m' : '\x1b[36m');
        const bar = '━━━━━━━━━━━━━━━━━━━━';
        
        console.log(`\n🔍 ${BOLD}TRACE INSPECTOR:${RESET} \x1b[90m${traceId}${RESET}`);
        console.log(`\x1b[90m${bar}${RESET}`);
        console.log(`🚨 Typ: ${entry.category}-${entry.rule}`);
        console.log(`📊 Severity: ${icon} ${BOLD}${sevColor}${entry.severity.toUpperCase()}${RESET}`);
        console.log(`🌐 IP: ${BOLD}${entry.ip}${RESET}`);
        console.log(`🌍 Geo: ${entry.geo}`);
        console.log(`📱 Device: ${entry.device}`);
        console.log(`📍 Path: ${BOLD}${entry.method} ${entry.url}${RESET}`);
        console.log(`📡 Status: ${event.blocked ? '\x1b[31m403\x1b[0m' : '\x1b[32m200\x1b[0m'} (${event.responseTime || 0}ms)`);
        console.log(`💾 Traffic: In: ${entry.traffic.in} | Out: ${entry.traffic.out}`);
        console.log(`\x1b[90m${bar}${RESET}`);
        console.log(`📝 Reason: ${entry.description}`);
        console.log(`🔗 Referer: ${event.referer || 'none'}`);
        console.log(`🔑 JA3 Fingerprint:\n\x1b[90m${entry.ja3}${RESET}`);
        console.log(`🧩 H2 Order/Hash:\n\x1b[90m${entry.h2}${RESET}`);
        console.log(`🖥️ Geometry: N/A`);
        console.log(`⚡ JS Test: N/A`);
        console.log(`🎭 Gaslight: NONE`);
        console.log(`\x1b[90m${bar}${RESET}`);
        console.log(`🏷️ Header Signature:\n\x1b[90m${entry.headers}${RESET}`);
        console.log(`📑 Raw Headers:`);
        entry.rawHeaders.slice(0, 5).forEach(h => console.log(`\x1b[90m${h}${RESET}`));
        if (entry.rawHeaders.length > 5) console.log(`\x1b[90m... (${entry.rawHeaders.length - 5} more)${RESET}`);
        console.log(`\x1b[90m${bar}${RESET}`);
        console.log(`🎭 Proxy Chain: ${entry.proxyChain} hops`);
        console.log(`☢️ Leak Shield: ${entry.leakShield === 'CLEAN' ? '\x1b[32mCLEAN\x1b[0m' : '\x1b[31mLEAK\x1b[0m'}`);
        console.log(`\x1b[90m${bar}${RESET}`);
        console.log(`🔍 Signals:`);
        if (entry.signals.length) {
          entry.signals.forEach(s => console.log(` \x1b[90m•\x1b[0m ${s}`));
        } else {
          console.log(` \x1b[90mNone\x1b[0m`);
        }
        console.log(`\x1b[90m${bar}${RESET}`);
        console.log(`☣️ Trigger Payload:`);
        console.log(`\x1b[90m${entry.payload}${RESET}`);
        console.log(`\x1b[90m${bar}${RESET}`);
        console.log(`⏰ Timestamp: ${entry.timestamp}\n`);

        // Write to TXT log file with ASCII box (no colors)
        const textBar = '━━━━━━━━━━━━━━━━━━━━';
        let logText = `\n🔍 TRACE INSPECTOR: ${traceId}\n`;
        logText += `${textBar}\n`;
        logText += `🚨 Typ: ${entry.category}-${entry.rule}\n`;
        logText += `📊 Severity: ${entry.severity.toUpperCase()}\n`;
        logText += `🌐 IP: ${entry.ip}\n`;
        logText += `🌍 Geo: ${entry.geo}\n`;
        logText += `📱 Device: ${entry.device}\n`;
        logText += `📍 Path: ${entry.method} ${entry.url}\n`;
        logText += `📡 Status: ${event.blocked ? '403' : '200'} (${event.responseTime || 0}ms)\n`;
        logText += `💾 Traffic: In: ${entry.traffic.in} | Out: ${entry.traffic.out}\n`;
        logText += `${textBar}\n`;
        logText += `📝 Reason: ${entry.description}\n`;
        logText += `🔗 Referer: ${event.referer || 'none'}\n`;
        logText += `🔑 JA3 Fingerprint: ${entry.ja3}\n`;
        logText += `☣️ Trigger Payload: ${entry.payload}\n`;
        logText += `${textBar}\n`;
        
        if (event.trace && event.trace.length) {
          logText += `🔍 DETAILED INSPECTION TRACE:\n`;
          event.trace.forEach(t => {
            logText += ` [${t.ms.padStart(7)}ms] ${t.step.padEnd(20)} | ${JSON.stringify(t.data)}\n`;
          });
          logText += `${textBar}\n`;
        }

        logText += `⏰ Timestamp: ${entry.timestamp}\n`;
        this._writeToFile(logText);
      }
    }
  }

  _store(entry) {
    this.history.push(entry);
    if (this.history.length > this.maxHistory) this.history.shift();
    if (this.onEvent) this.onEvent(entry);
  }

  getHistory(count = 100) { return this.history.slice(-count); }

  getStats() {
    const attacks = this.history.filter(e => e.type === 'attack');
    const stats = {
      total: attacks.length,
      blocked: attacks.filter(e => e.action === 'blocked').length,
      detected: attacks.filter(e => e.action === 'detected').length,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      byCategory: {},
      topIPs: {},
      topRules: {},
    };
    for (const a of attacks) {
      if (stats.bySeverity[a.severity] !== undefined) stats.bySeverity[a.severity]++;
      stats.byCategory[a.category] = (stats.byCategory[a.category] || 0) + 1;
      stats.topIPs[a.ip] = (stats.topIPs[a.ip] || 0) + 1;
      stats.topRules[a.rule] = (stats.topRules[a.rule] || 0) + 1;
    }
    return stats;
  }

  clearHistory() { this.history = []; }

  async exportToSIEM(entry) {
    if (!this.siemWebhook) return;
    try {
      const http = require('http');
      const https = require('https');
      const client = this.siemWebhook.startsWith('https') ? https : http;
      const url = new URL(this.siemWebhook);
      
      const payload = JSON.stringify({
        username: 'ShieldWall WAF',
        embeds: [{
          title: `🛡️ Security Alert: ${entry.rule}`,
          color: entry.severity === 'critical' ? 0xff0000 : (entry.severity === 'high' ? 0xffaa00 : 0x00aaff),
          fields: [
            { name: 'IP', value: entry.ip, inline: true },
            { name: 'Method', value: entry.method, inline: true },
            { name: 'Path', value: entry.url, inline: true },
            { name: 'Reason', value: entry.description },
            { name: 'Trace ID', value: entry.traceId },
          ],
          timestamp: entry.timestamp
        }]
      });

      const req = client.request(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
      });
      req.on('error', () => {}); // Silent catch
      req.write(payload);
      req.end();
    } catch (e) {}
  }
}

module.exports = Logger;
