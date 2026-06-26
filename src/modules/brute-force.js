'use strict';

// Brute-force protection with progressive backoff on auth endpoints

class BruteForceGuard {
  constructor(options = {}) {
    this.maxAttempts = options.maxAttempts || 5;
    this.windowMs = options.windowMs || 15 * 60_000;
    this.blockDurationMs = options.blockDurationMs || 15 * 60_000;
    this.maxBlockDurationMs = options.maxBlockDurationMs || 24 * 60 * 60_000;
    this.progressiveBackoff = options.progressiveBackoff !== false;
    this.trustProxy = options.trustProxy || false;

    this.sensitivePaths = new Set(
      (options.sensitivePaths || ['/login', '/api/auth', '/api/login', '/signin', '/api/signin'])
        .map(p => p.toLowerCase())
    );
    this.failedCodes = new Set(options.failedCodes || [401, 403, 422]);
    this.accountMaxAttempts = options.accountMaxAttempts || 10;

    // FIX: BUG_29 — Add global limits to prevent OOM during distributed attacks
    this.maxStateSize = options.maxStateSize || 50000;
    this.maxAccountStateSize = options.maxAccountStateSize || 100000;

    this._state = new Map();
    this._accountState = new Map();
    this._cleanup = setInterval(() => this._gc(), 60_000);
    this._cleanup.unref?.();
  }

  check(req) {
    const ip = this._ip(req);
    const path = (req.path || req.url?.split('?')[0] || '').toLowerCase();
    if (!this._isSensitive(path)) return { blocked: false, ip };

    const entry = this._state.get(ip);
    if (!entry) return { blocked: false, ip };

    const now = Date.now();
    if (entry.blockUntil && now < entry.blockUntil) {
      return { blocked: true, ip, reason: `Blocked after ${entry.attempts.length} failed attempts`, retryAfter: entry.blockUntil - now, attempts: entry.attempts.length };
    }
    if (entry.blockUntil) { entry.blockUntil = null; entry.attempts = []; }
    return { blocked: false, ip };
  }

  checkAccount(accountId) {
    if (!accountId) return { blocked: false };
    
    const now = Date.now();
    const entry = this._accountState.get(accountId);
    if (!entry) return { blocked: false };

    entry.attempts = entry.attempts.filter(ts => now - ts < this.windowMs);

    if (entry.attempts.length >= this.accountMaxAttempts) {
      return { 
        blocked: true, 
        reason: `Account locked after ${entry.attempts.length} failed attempts globally`,
        retryAfter: this.blockDurationMs
      };
    }
    return { blocked: false };
  }

  /**
   * Records failed authentication attempts and applies progressive backoff blocking.
   * FIX: BABU_26 — Enforce global size limits to prevent OOM during distributed attacks.
   * @param {Object} req - HTTP request object.
   * @param {number} statusCode - HTTP response status code.
   * @param {string} accountId - Optional account identifier (email, username, etc.).
   */
  recordResponse(req, statusCode, accountId = null) {
    const ip = this._ip(req);
    const path = (req.path || req.url?.split('?')[0] || '').toLowerCase();
    if (!this._isSensitive(path)) return;

    // FIX: BUG_26 — Enforce global limits before adding new entries
    if (this._state.size >= this.maxStateSize) {
      const oldest = this._state.keys().next().value;
      this._state.delete(oldest);
    }

    if (accountId && this.failedCodes.has(statusCode)) {
      // FIX: BUG_26 — Enforce account state limit
      if (this._accountState.size >= this.maxAccountStateSize) {
        const oldest = this._accountState.keys().next().value;
        this._accountState.delete(oldest);
      }
      let accEntry = this._accountState.get(accountId);
      if (!accEntry) { accEntry = { attempts: [] }; this._accountState.set(accountId, accEntry); }
      accEntry.attempts.push(Date.now());
    }

    // Successful auth resets the counter
    if (!this.failedCodes.has(statusCode)) { this._state.delete(ip); return; }

    const now = Date.now();
    let entry = this._state.get(ip);
    if (!entry) { entry = { attempts: [], blockUntil: null, blockCount: 0 }; this._state.set(ip, entry); }

    entry.attempts = entry.attempts.filter(ts => now - ts < this.windowMs);
    entry.attempts.push(now);

    if (entry.attempts.length >= this.maxAttempts) {
      entry.blockCount++;
      const mult = this.progressiveBackoff ? Math.pow(2, entry.blockCount - 1) : 1;
      entry.blockUntil = now + Math.min(this.blockDurationMs * mult, this.maxBlockDurationMs);
    }
  }

  /**
   * Express middleware for brute-force protection.
   * FIX: BUG_28 — Race condition in res.end hooking. Uses atomic Object.defineProperty
   * to prevent multiple concurrent requests from hooking the same response object.
   * @returns {Function} Express middleware function.
   */
  middleware() {
    const guard = this;
    return function(req, res, next) {
      const rIp = guard.check(req);
      
      let accountId = null;
      if (req.body && typeof req.body === 'object') {
        accountId = req.body.email || req.body.username || req.body.account || null;
      }
      
      const rAcc = guard.checkAccount(accountId);
      
      if (rIp.blocked || rAcc.blocked) {
        const retryAfter = rIp.blocked ? rIp.retryAfter : rAcc.retryAfter;
        // TARPIT: Add a 2-5 second delay to ruin bruteforce throughput
        const delay = 2000 + Math.random() * 3000;
        setTimeout(() => {
          res.status(429).setHeader('Retry-After', Math.ceil(retryAfter / 1000));
          res.json({ error: 'Too Many Failed Attempts', retryAfter: Math.ceil(retryAfter / 1000) });
        }, delay);
        return;
      }
      // FIX: BUG_28 — Atomic hooking of res.end to prevent race conditions
      if (!res._bruteHooked) {
        try {
          Object.defineProperty(res, '_bruteHooked', {
            value: true,
            writable: false,
            configurable: false
          });
          const origEnd = res.end.bind(res);
          res.end = function(c, e) { guard.recordResponse(req, res.statusCode, accountId); return origEnd(c, e); };
        } catch (e) {
          // Property already defined by another request (race condition handled)
        }
      }
      next();
    };
  }

  _isSensitive(path) {
    for (const s of this.sensitivePaths) { if (path === s || path.startsWith(s + '/')) return true; }
    return false;
  }

  /**
   * Extracts client IP from request with optional proxy support.
   * FIX: BUG_27 — IP spoofing via X-Forwarded-For. Added IP format validation
   * to prevent injection of arbitrary strings.
   * @param {Object} req - HTTP request object.
   * @returns {string} Validated IP address or 'unknown'.
   */
  _ip(req) {
    // Use x-forwarded-for only if explicitly trusted (behind proxy)
    if (this.trustProxy && req.headers?.['x-forwarded-for']) {
      const ips = req.headers['x-forwarded-for'].split(',').map(ip => ip.trim());
      const validIP = ips.find(ip => this._isValidIP(ip));
      if (validIP) return validIP;
    }
    return req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || 'unknown';
  }

  /**
   * Validates if a string is a valid IPv4 or IPv6 address.
   * FIX: BUG_27 — Helper function for IP validation.
   * @param {string} ip - The IP string to validate.
   * @returns {boolean} True if valid IP format.
   */
  _isValidIP(ip) {
    if (!ip || typeof ip !== 'string') return false;
    // IPv4 regex
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipv4Regex.test(ip)) return true;
    // IPv6 regex (simplified)
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv6Regex.test(ip);
  }

  _gc() {
    const now = Date.now();
    for (const [ip, e] of this._state) {
      e.attempts = e.attempts.filter(ts => now - ts < this.windowMs);
      if (!e.attempts.length && (!e.blockUntil || now >= e.blockUntil)) this._state.delete(ip);
    }
    for (const [acc, e] of this._accountState) {
      e.attempts = e.attempts.filter(ts => now - ts < this.windowMs);
      if (!e.attempts.length) this._accountState.delete(acc);
    }
  }

  getBlockedIPs() {
    const now = Date.now(), list = [];
    for (const [ip, e] of this._state) { if (e.blockUntil && now < e.blockUntil) list.push({ ip, until: new Date(e.blockUntil).toISOString() }); }
    return list;
  }

  reset(ip) { this._state.delete(ip); }
  destroy() { clearInterval(this._cleanup); this._state.clear(); }
}

module.exports = BruteForceGuard;
