'use strict';

const crypto = require('crypto');

/**
 * Default paths commonly scanned by attackers looking for vulnerabilities.
 * @type {string[]}
 */
const DEFAULT_RECON_TRAP_PATHS = [
  '/.env', '/.git/config', '/wp-login.php', '/admin/config',
  '/actuator/health', '/graphql', '/.well-known/security.txt',
  '/phpmyadmin', '/admin', '/user/login', '/manager/html',
  '/remoting/jmx', '/jmx-console', '/web-console',
  '/debug', '/backup', '/test'
];

/**
 * Unique token that scanners cannot distinguish from a real path.
 * @type {string}
 */
const TRAP_TOKEN = 'shw_trp_' + crypto.randomBytes(8).toString('hex');

/**
 * Fake data (Decoys) served for specific paths to mislead attackers and waste their time.
 * @type {Object<string, string>}
 */
const DECOY_RESPONSES = {
  '/.env': 'DB_HOST=127.0.0.1\nDB_USER=root\nDB_PASSWORD=admin123\nAWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE',
  '/.git/config': '[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n[remote "origin"]\n\turl = https://github.com/fake/repo.git'
};

/**
 * Regular expression to identify legitimate search engine bots (e.g., Google, Yandex).
 * @type {RegExp}
 */
const LEGIT_BOTS_REGEX = /(Googlebot|Bingbot|Slurp|DuckDuckBot|Baiduspider|YandexBot|facebookexternalhit)/i;

/**
 * Regular expression to detect common attack patterns in URLs (SQLi, XSS, LFI).
 * @type {RegExp}
 */
const ATTACK_PATTERS_REGEX = /(\bUNION\b.*\bSELECT\b|<script>|alert\(|\.\.\/|etc\/passwd|;cat|wget\s)/i;

/**
 * Creates an advanced middleware function for active reconnaissance traps, honeypots, and attack mitigation.
 * This middleware detects probing attempts, serves decoy content, slows down scanners (Tarpit),
 * and integrates with a reputation tracker to record malicious activity.
 *
 * @param {object} reputationTracker - An object with a `recordReconAttempt` method.
 * @param {object} [options] - Configuration options for the middleware.
 * @param {boolean} [options.enableTarpit=false] - If true, delays responses to scanners to trap them in slow requests.
 * @param {boolean} [options.enableDecoys=true] - If true, serves fake content for specific trap paths (e.g., fake .env files).
 * @param {number} [options.tarpitDelayMs=20000] - Delay in milliseconds for the Tarpit feature.
 * @param {string[]} [options.trapPaths=DEFAULT_RECON_TRAP_PATHS] - Custom array of paths to monitor.
 * @param {boolean} [options.trustProxy=false] - If true, trusts X-Forwarded-For header for client IP extraction.
 * @param {boolean} [options.blockLegitBots=false] - If true, does not bypass legitimate search engine bots.
 * @returns {function} An Express-style middleware function.
 */
function createTrapMiddleware(reputationTracker, options = {}) {
  const {
    enableTarpit = false,
    enableDecoys = true,
    tarpitDelayMs = 20000,
    trapPaths = DEFAULT_RECON_TRAP_PATHS,
    trustProxy = false,
    blockLegitBots = false
  } = options;

  if (!reputationTracker || typeof reputationTracker.recordReconAttempt !== 'function') {
    console.warn('TrapRouter: reputationTracker is not provided or does not have recordReconAttempt method. Recon attempts will not be recorded.');
  }

  // In-memory store for micro-rate-limiting (for production, consider Redis)
  const trapHits = new Map();
  const RATE_LIMIT_WINDOW_MS = 10000; // 10 seconds
  const RATE_LIMIT_MAX_HITS = 3;      // 3 hits = block

  // Compile regex once for performance and case-insensitivity (flag 'i')
  const escapedPaths = trapPaths.map(p => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const trapPathRegex = new RegExp(`^(${escapedPaths.join('|')})`, 'i');

  /**
   * Normalizes the URL path by removing trailing slashes and converting to lowercase.
   * @param {string} p - The raw URL path.
   * @returns {string} The normalized URL path.
   */
  const normalizePath = (p) => (p.endsWith('/') && p.length > 1 ? p.slice(0, -1) : p).toLowerCase();

  /**
   * Extracts the real client IP address, accounting for reverse proxies if enabled.
   * @param {object} req - The Express request object.
   * @returns {string} The client's IP address.
   */
  const getClientIp = (req) => {
    if (trustProxy) {
      const xff = req.headers['x-forwarded-for'];
      if (xff) {
        return xff.split(',')[0].trim(); // Get the first IP in the chain
      }
    }
    return req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress;
  };

  /**
   * Safely calls the reputation tracker's record method, catching any internal errors.
   * @param {string} ip - The client's IP address.
   * @param {string} path - The requested path.
   * @param {number} status - The HTTP status code returned.
   * @param {string} [reason] - The reason for triggering the trap.
   */
  const safeRecord = (ip, path, status, reason) => {
    if (reputationTracker?.recordReconAttempt) {
      try {
        reputationTracker.recordReconAttempt(ip, path, status, reason);
      } catch (err) {
        console.error('TrapRouter: Error during recordReconAttempt:', err);
      }
    }
  };

  /**
   * In-memory rate limiter for trap hits. Automatically blocks IPs hitting too many traps.
   * @param {string} ip - The client's IP address.
   * @returns {boolean} True if the rate limit has been exceeded.
   */
  const checkRateLimit = (ip) => {
    const now = Date.now();
    if (!trapHits.has(ip)) trapHits.set(ip, []);
    
    const hits = trapHits.get(ip).filter(time => now - time < RATE_LIMIT_WINDOW_MS);
    hits.push(now);
    trapHits.set(ip, hits);

    return hits.length > RATE_LIMIT_MAX_HITS;
  };

  /**
   * Express middleware function that intercepts and processes incoming requests.
   * Checks for attack patterns, suspicious methods, trap tokens, and recon paths.
   * 
   * @param {object} req - The Express request object.
   * @param {object} res - The Express response object.
   * @param {function} next - The next middleware function in the stack.
   */
  return function trapRouter(req, res, next) {
    const rawPath = req.path || (req.url ? req.url.split('?')[0] : '/');
    const path = normalizePath(rawPath);
    const clientIp = getClientIp(req);
    const userAgent = req.headers['user-agent'] || '';

    // 1. Detect attack patterns in Query String (SQLi, XSS, LFI)
    // Scanners often probe parameters with classic injection payloads.
    if (req.url && ATTACK_PATTERS_REGEX.test(req.url)) {
      safeRecord(clientIp, req.url, 403, 'Attack_Pattern_In_URL');
      res.removeHeader('X-Powered-By');
      return res.status(403).send('Forbidden');
    }

    // 2. Bypass for legitimate search engine bots
    // We want to trap attackers, not penalize Google or Yandex.
    if (!blockLegitBots && LEGIT_BOTS_REGEX.test(userAgent)) {
      return next(); 
    }

    // 3. Detect suspicious HTTP methods
    // Methods like TRACE or CONNECT are rarely used legitimately but often used in probing.
    const suspiciousMethods = ['TRACE', 'TRACK', 'CONNECT'];
    if (suspiciousMethods.includes(req.method.toUpperCase())) {
      safeRecord(clientIp, path, 405, 'Suspicious_Method');
      res.removeHeader('X-Powered-By');
      return res.status(405).send('Method Not Allowed');
    }

    // 4. Honeypot tripwire (Followed trap link from robots.txt)
    // If a request includes the TRAP_TOKEN, it indicates a scanner followed the bait.
    if (path.includes(TRAP_TOKEN.toLowerCase())) {
      safeRecord(clientIp, path, 403, 'Trap_Token_Triggered');
      res.removeHeader('X-Powered-By');
      return res.status(403).send('Forbidden');
    }

    // 5. Check known scanner trap paths and serve Decoys
    // These are paths commonly scanned by attackers. We can serve fake content or 404.
    if (trapPathRegex.test(path)) {
      // If the scanner hits 3 traps in 10 seconds, block them immediately.
      if (checkRateLimit(clientIp)) {
        safeRecord(clientIp, path, 429, 'Rate_Limit_Exceeded');
        return res.status(429).send('Too Many Requests');
      }

      safeRecord(clientIp, path, 200, 'Recon_Trap_Path');
      res.removeHeader('X-Powered-By');

      // If Tarpit is enabled, force the scanner to wait, locking their connection.
      if (enableTarpit) {
        return setTimeout(() => {
          if (enableDecoys && DECOY_RESPONSES[path]) {
            return res.status(200).send(DECOY_RESPONSES[path]);
          }
          return res.status(404).send('Not Found');
        }, tarpitDelayMs);
      }

      // Without Tarpit, respond immediately with decoy or 404
      if (enableDecoys && DECOY_RESPONSES[path]) {
        return res.status(200).send(DECOY_RESPONSES[path]);
      }
      return res.status(404).send('Not Found');
    }

    // 6. Invisible Polygraph (Bots parsing robots.txt)
    // This serves a robots.txt file that includes a disallowed TRAP_TOKEN path,
    // enticing scanners to visit it.
    if (path === '/robots.txt') {
      res.type('text/plain');
      res.send(`User-agent: *\nDisallow: /${TRAP_TOKEN}/\n`);
      return;
    }

    next();
  };
}

module.exports = { createTrapMiddleware, TRAP_TOKEN, DEFAULT_RECON_TRAP_PATHS };