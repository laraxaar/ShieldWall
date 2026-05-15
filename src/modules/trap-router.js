'use strict';

/**
 * @file trap-router.js
 * @description Active Reconnaissance Traps & Honeypots
 * 
 * ROLE IN ARCHITECTURE:
 * Deploys deceptive endpoints that legitimate users never access.
 * Triggers severe reputation taint for IPs that stumble into these traps.
 */

const crypto = require('crypto');

const RECON_TRAP_PATHS = [
  '/.env', '/.git/config', '/wp-login.php', '/admin/config',
  '/actuator/health', '/graphql', '/.well-known/security.txt',
  '/api/v1/debug', '/console'
];

// Unique token that scanners cannot distinguish from a real path
const TRAP_TOKEN = 'shw_trp_' + crypto.randomBytes(8).toString('hex');

function createTrapMiddleware(reputationTracker) {
  return function trapRouter(req, res, next) {
    const path = req.path || (req.url ? req.url.split('?')[0] : '/');

    // 1. Check known scanner trap paths
    if (RECON_TRAP_PATHS.some(p => path.startsWith(p))) {
      if (reputationTracker && typeof reputationTracker.recordReconAttempt === 'function') {
        reputationTracker.recordReconAttempt(req.ip || req.connection?.remoteAddress, path, 404);
      }
      return res.status(404).send('Not Found');
    }

    // 2. Invisible Polygraph (Bots parsing robots.txt)
    if (path === '/robots.txt') {
      res.type('text/plain');
      res.send(`User-agent: *\nDisallow: /${TRAP_TOKEN}/\n`);
      return;
    }

    // 3. Honeypot tripwire (Followed trap link from robots.txt)
    if (path.includes(TRAP_TOKEN)) {
      if (reputationTracker && typeof reputationTracker.recordReconAttempt === 'function') {
        reputationTracker.recordReconAttempt(req.ip || req.connection?.remoteAddress, path, 403);
      }
      return res.status(403).send('Forbidden');
    }

    next();
  };
}

module.exports = { createTrapMiddleware, TRAP_TOKEN };
