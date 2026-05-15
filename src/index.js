'use strict';

/*
 * ShieldWall — YARA-like WAF Engine for Node.js
 *
 * DISCLAIMER: This project is provided "as-is" without warranty.
 * It requires adaptation for production use.  The authors accept
 * no responsibility for vulnerabilities in applications using it.
 */

const ShieldWallEngine = require('./core/engine');
const { parseRules, parseRuleFile, loadRulesFromDir } = require('./core/rule-parser');
const { decodeRequest, fullDecode } = require('./core/decoder');
const Logger = require('./core/logger');
const ReportingEngine = require('./core/reporting');

function shieldwall(options = {}) {
  const engine = new ShieldWallEngine(options);

  let rateLimiter = null;
  if (options.rateLimit) {
    try {
      const RateLimiter = require('./modules/rate-limiter');
      rateLimiter = new RateLimiter(typeof options.rateLimit === 'object' ? options.rateLimit : {});
    } catch (err) { engine.logger.warn(`Rate limiter: ${err.message}`); }
  }

  let bruteForce = null;
  if (options.bruteForce) {
    try {
      const BruteForceGuard = require('./modules/brute-force');
      bruteForce = new BruteForceGuard(typeof options.bruteForce === 'object' ? options.bruteForce : {});
    } catch (err) { engine.logger.warn(`Brute-force: ${err.message}`); }
  }

  let headerSecurity = null;
  if (options.headers !== false) {
    try {
      const h = require('./modules/header-security');
      headerSecurity = h.createMiddleware(typeof options.headers === 'object' ? options.headers : {});
    } catch (err) { engine.logger.warn(`Headers: ${err.message}`); }
  }

  let honeypotInjector = null;
  if (options.honeypot !== false) {
    try {
      const hp = require('./modules/honeypot');
      honeypotInjector = hp.injectMiddleware(typeof options.honeypot === 'object' ? options.honeypot : {});
    } catch (err) { engine.logger.warn(`Honeypot: ${err.message}`); }
  }

  if (options.dashboard) {
    try {
      const Dashboard = require('./dashboard/server');
      const cfg = typeof options.dashboard === 'object' ? options.dashboard : {};
      new Dashboard({ port: cfg.port || 9090, host: cfg.host || 'localhost', engine }).start();
    } catch (err) { engine.logger.warn(`Dashboard: ${err.message}`); }
  }

    const middleware = async function shieldwallMiddleware(req, res, next) {
    if (headerSecurity) headerSecurity(req, res);

    if (bruteForce) {
      const bf = bruteForce.check(req);
      if (bf.blocked) {
        engine.logger.attack({ blocked: true, rule: 'brute_force', severity: 'high', category: 'brute-force', ip: bf.ip, method: req.method, url: req.url, description: bf.reason });
        if (res.status) {
          res.status(429).json({ error: 'Too Many Failed Attempts', retryAfter: Math.ceil(bf.retryAfter / 1000) });
        } else {
          res.writeHead(429, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Too Many Failed Attempts', retryAfter: Math.ceil(bf.retryAfter / 1000) }));
        }
        return;
      }
    }

    if (rateLimiter) {
      const rl = rateLimiter.check(req);
      if (rl.limited) {
        engine.logger.attack({ blocked: true, rule: 'rate_limit', severity: 'medium', category: 'rate-limit', ip: rl.ip, method: req.method, url: req.url, description: `Rate limit exceeded (${rl.count}/${rl.max})` });
        if (res.status) {
          res.status(429).json({ error: 'Too Many Requests', retryAfter: Math.ceil(rl.retryAfter / 1000) });
        } else {
          res.writeHead(429, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Too Many Requests', retryAfter: Math.ceil(rl.retryAfter / 1000) }));
        }
        return;
      }
    }

    const result = await engine.analyze(req, res);
    req.shieldwall = { analyzed: true, blocked: result.blocked, matches: result.matches, severity: result.highestSeverity || 'none' };

    // Handle Active Mitigation
    if (result.mitigation && !result.blocked) {
      if (result.mitigation.type === 'challenge') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(result.mitigation.html);
        return;
      }
      if (result.mitigation.type === 'redirect') {
        res.writeHead(302, { 'Location': result.mitigation.url });
        res.end();
        return;
      }
    }

    if (result.blocked && result.matches.length) {
      const code = engine.options.blockStatusCode || 403;
      const response = engine.getBlockResponse(result.matches, result.highestSeverity);
      if (res.status) {
        res.status(code).setHeader('X-ShieldWall', 'blocked').send(response);
      } else {
        res.writeHead(code, { 'Content-Type': 'application/json', 'X-ShieldWall': 'blocked' });
        res.end(response);
      }
      return;
    }

    if (bruteForce) {
      const origEnd = res.end.bind(res);
      res.end = function(chunk, encoding) { bruteForce.recordResponse(req, res.statusCode); return origEnd(chunk, encoding); };
    }

    if (honeypotInjector) honeypotInjector(req, res, () => {});

    res.setHeader('X-ShieldWall', 'pass');
    next();
  };

  middleware.engine = engine;
  middleware.getStats = () => engine.getStats();
  middleware.reloadRules = () => engine.reloadRules();
  middleware.on = (event, cb) => engine.on(event, cb);
  middleware.getReport = (days) => engine.getReport(days);
  middleware.getStoredReports = () => engine.getStoredReports();

  return middleware;
}

module.exports = shieldwall;
module.exports.shieldwall = shieldwall;
module.exports.ShieldWallEngine = ShieldWallEngine;
module.exports.parseRules = parseRules;
module.exports.parseRuleFile = parseRuleFile;
module.exports.loadRulesFromDir = loadRulesFromDir;
module.exports.decodeRequest = decodeRequest;
module.exports.fullDecode = fullDecode;
module.exports.Logger = Logger;
module.exports.ReportingEngine = ReportingEngine;
