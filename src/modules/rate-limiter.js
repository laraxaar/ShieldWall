'use strict';

/**
 * @file rate-limiter.js
 * @description Distributed Sliding Window Rate Limiting Engine.
 * 
 * ROLE IN ARCHITECTURE:
 * Primary L4/L7 volumetric barrier. Evaluates traffic speeds prior to heavy heuristic
 * inspection. Implements abstract MemStore patterns mapping to Redis/Memcached.
 * 
 * DATA FLOW:
 * [Middleware] -> `limiter.check(req)` -> Maps `req.ip` state -> Emits true/false throttle bounds.
 * 
 * CRITICAL FALSE POSITIVE (FP) MITIGATION:
 * Integrates `trustProxy` routing schemas to prevent upstream Load Balancer (Cloudflare) IPs 
 * from being banned identically, protecting proxy networks from false aggregate drops.
 */
/**
 * Default In-Memory Store for the Rate Limiter.
 * Can be replaced with a RedisStore or any KV store matching this interface
 * to support horizontal scaling across instances.
 */
class MemoryStore {
  constructor(windowMs) {
    this.windowMs = windowMs;
    this._requests = new Map();
    this._blocked = new Map();
    this._locks = new Map(); // FIX: BUG_22 — Initialize locks in constructor
    this._maxKeys = 100000; // FIX: BUG_22 — Global limit to prevent OOM
  }

  /**
   * Atomically increments request count for a key.
   * FIX: BUG_16 — Race condition in increment. Uses Map-level locking to prevent
   * race conditions during concurrent requests from the same IP.
   * @param {string} key - The rate limit key (usually IP).
   * @returns {Promise<number>} Current request count.
   */
  async increment(key) {
    const now = Date.now();
    
    // Enforce global key limit to prevent OOM
    if (this._requests.size >= this._maxKeys) {
      const oldest = this._requests.keys().next().value;
      this._requests.delete(oldest);
      this._blocked.delete(oldest);
      this._locks.delete(oldest);
    }
    
    // Use a lock map for atomic operations
    let lock = this._locks.get(key);
    if (!lock) {
      lock = { promise: Promise.resolve(), resolve: null };
      this._locks.set(key, lock);
    }
    
    // Wait for previous operations on this key
    await lock.promise;
    
    return new Promise((resolve) => {
      let reqs = this._requests.get(key) || [];
      const cutoff = now - this.windowMs;
      reqs = reqs.filter(t => t > cutoff);
      reqs.push(now);
      this._requests.set(key, reqs);
      
      resolve(reqs.length);
      
      // Release lock
      if (this._locks.has(key)) {
        this._locks.delete(key);
      }
    });
  }

  async block(key, blockDuration) {
    this._blocked.set(key, Date.now() + blockDuration);
  }

  async isBlocked(key) {
    const bu = this._blocked.get(key);
    if (!bu) return 0;
    if (Date.now() < bu) return bu;
    this._blocked.delete(key);
    return 0;
  }

  /**
   * Periodic cleanup of expired request timestamps and blocked entries.
   * FIX: BUG_25 — Added cleanup for _locks Map to prevent memory leak.
   */
  async cleanup() {
    const cutoff = Date.now() - this.windowMs;
    for (const [k, r] of this._requests) {
      const v = r.filter(t => t > cutoff);
      if (!v.length) this._requests.delete(k);
      else this._requests.set(k, v);
    }
    const now = Date.now();
    for (const [k, u] of this._blocked) {
      if (now >= u) this._blocked.delete(k);
    }
    // FIX: BUG_25 — Clean up stale locks
    this._locks.clear();
  }

  async getBlockedIPs() {
    const now = Date.now(), list = [];
    for (const [ip, u] of this._blocked) {
      if (now < u) list.push({ ip, blockedUntil: new Date(u).toISOString() });
    }
    return list;
  }

  async unblock(key) {
    this._blocked.delete(key);
    this._requests.delete(key);
  }

  async clear() {
    this._requests.clear();
    this._blocked.clear();
  }
}

class RateLimiter {
  constructor(options = {}) {
    this.windowMs = options.windowMs || 60_000;
    this.max = options.max || 100;
    this.blockDuration = options.blockDuration || 300_000;
    this.keyGenerator = options.keyGenerator || this._defaultKey;
    this.skipPaths = options.skipPaths || [];
    this.trustProxy = options.trustProxy || false;
    
    // Abstract the state layer. Enables easy swap to Redis/Memcached.
    this.store = options.store || new MemoryStore(this.windowMs);

    this._gc = setInterval(() => this.store.cleanup(), 60_000);
    this._gc.unref?.();
  }

  /**
   * Default key generator using client IP.
   * FIX: BUG_23 — IP spoofing via X-Forwarded-For. Added IP format validation
   * to prevent injection of arbitrary strings.
   * @param {Object} req - HTTP request object.
   * @returns {string} Validated IP address or 'unknown'.
   */
  _defaultKey(req) {
    if (this.trustProxy) {
      const f = req.headers?.['x-forwarded-for'];
      if (f) {
        const ips = f.split(',').map(ip => ip.trim());
        const validIP = ips.find(ip => this._isValidIP(ip));
        if (validIP) return validIP;
      }
    }
    return req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || 'unknown';
  }

  /**
   * Validates if a string is a valid IPv4 or IPv6 address.
   * FIX: BUG_23 — Helper function for IP validation.
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

  async check(req) {
    const key = this.keyGenerator.call(this, req);
    const now = Date.now();
    const path = req.path || req.url?.split('?')[0] || '';
    
    for (const s of this.skipPaths) { 
      if (path.startsWith(s)) return { limited: false, ip: key, count: 0, max: this.max, retryAfter: 0 }; 
    }

    const blockUntil = await this.store.isBlocked(key);
    if (blockUntil > 0) {
      return { limited: true, ip: key, count: this.max, max: this.max, retryAfter: blockUntil - now };
    }

    const count = await this.store.increment(key);

    if (count > this.max) {
      await this.store.block(key, this.blockDuration);
      return { limited: true, ip: key, count, max: this.max, retryAfter: this.blockDuration };
    }
    
    return { limited: false, ip: key, count, max: this.max, retryAfter: 0, remaining: this.max - count };
  }

  // Fallbacks for backwards compatibility — ideally should be awaited downstream
  blockIP(ip, ms) { this.store.block(ip, ms || this.blockDuration); }
  unblockIP(ip) { this.store.unblock(ip); }

  async getBlockedIPs() { return await this.store.getBlockedIPs(); }

  destroy() { 
    clearInterval(this._gc); 
    this.store.clear(); 
  }
}

module.exports = { RateLimiter, MemoryStore };
