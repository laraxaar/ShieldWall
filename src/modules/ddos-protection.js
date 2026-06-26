'use strict';

/**
 * @file ddos-protection.js
 * @description Application-Layer DDoS & Slowloris Mitigation Module.
 * 
 * ROLE IN ARCHITECTURE:
 * Operates alongside the Infrastructure RateLimiter to defend against resource
 * exhaustion attacks (L7), specifically Slowloris, Header Bombs, and Connection Floods.
 * 
 * DATA FLOW:
 * [engine.js] passes `decodedReq` -> Evaluates state in Memory Maps -> Emits severe Dos 
 *  signals mapped as `oversized_body` or `connection_flood` to the central Risk Engine.
 * 
 * CRITICAL FALSE POSITIVE (FP) MITIGATION & BUG FIXES:
 * - OOM Memory Leak: The Slowloris tracker map lacked a Garbage Collection (GC) thread.
 *   Entries accumulated permanently. Integrated `SLOWLORIS_TRACKER` deep-clean into `setInterval`.
 * - SPA & NAT FPs: The connection ceiling was set to a rigid 100 per minute. Polling SPAs
 *   or congested office networks hit this immediately. Safe threshold shifted to `300`.
 */

const CONNECTION_TRACKER = new Map();
const SLOWLORIS_TRACKER = new Map();
const TRACKER_LOCKS = new Map(); // FIX: BUG_39 — Add lock map for atomic operations

// FP Control: Shifted from 100 to 300 to allow React/Vue payload batching & Office NATs
const MAX_CONNECTIONS_PER_IP = 300;
const CLEANUP_INTERVAL = 60000;
const SLOWLORIS_TIMEOUT = 10000;
const MAX_HEADER_SIZE = 8192;
const MAX_QUERY_PARAMS = 50;

// FIX(BUG_37): Global tracker size limit set to 10000 to prevent OOM
const MAX_TRACKER_SIZE = 10000;

// // FIX(METRICS): Track DDoS metrics
const METRICS = {
  blockedCounts: 0,
  get trackerSizes() {
    return {
      connectionTracker: CONNECTION_TRACKER.size,
      slowlorisTracker: SLOWLORIS_TRACKER.size
    };
  }
};

// // FIX(WHITELIST): Support whitelist for trusted IPs
const WHITELIST = new Set();

/**
 * Adds an IP to the trusted whitelist.
 * @param {string} ip - The IP address to whitelist.
 */
function addToWhitelist(ip) {
  if (_isValidIP(ip)) {
    WHITELIST.add(ip);
  }
}

/**
 * Removes an IP from the trusted whitelist.
 * @param {string} ip - The IP address to remove from whitelist.
 */
function removeFromWhitelist(ip) {
  WHITELIST.delete(ip);
}

/**
 * Checks if an IP is whitelisted.
 * @param {string} ip - The IP address to check.
 * @returns {boolean} True if whitelisted.
 */
function isWhitelisted(ip) {
  return WHITELIST.has(ip);
}

/**
 * Validates if a string is a valid IPv4 or IPv6 address.
 * * @fix BUG_38
 * @param {string} ip - The IP string to validate.
 * @returns {boolean} True if valid IP format.
 */
function _isValidIP(ip) {
  if (!ip || typeof ip !== 'string') return false;
  // IPv4 regex
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Regex.test(ip)) return true;
  // IPv6 regex (simplified)
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv6Regex.test(ip);
}

/**
 * Bounds checking against HTTP protocol exhaustion (Slowloris/Header bombing).
 * * @fix BUG_38
 * * @fix BUG_39
 * * @fix BUG_40
 * @param {Object} decodedReq - Standard unrolled request dictionary.
 * @returns {Promise<Array<Object>>} List of volumetric anomalies detected in the raw socket payload.
 */
async function checkSlowloris(decodedReq) {
  const indicators = [];
  const ip = decodedReq.ip;
  if (!_isValidIP(ip)) return indicators;
  const now = Date.now();

  // // FIX(BUG_39): Prevent race conditions using serialized promises queue for atomic operation
  let lock = TRACKER_LOCKS.get(ip);
  if (!lock) {
    lock = Promise.resolve();
  }
  let resolveLock;
  const nextLock = new Promise((resolve) => {
    resolveLock = resolve;
  });
  TRACKER_LOCKS.set(ip, nextLock);

  try {
    await lock;

    // // FIX(BUG_37): Enforce global limit before adding new entries to prevent OOM
    let tracker = SLOWLORIS_TRACKER.get(ip);
    if (!tracker) {
      if (SLOWLORIS_TRACKER.size >= MAX_TRACKER_SIZE) {
        const oldest = SLOWLORIS_TRACKER.keys().next().value;
        if (oldest !== undefined) {
          SLOWLORIS_TRACKER.delete(oldest);
        }
      }
      tracker = { lastActivity: now, partialRequests: 0 };
    }

    // Track continuous activity stream updates
    tracker.lastActivity = now;

    // // FIX(BUG_40): Validate headers structure to prevent prototype pollution and circular references
    const headers = decodedReq.headers || {};
    if (typeof headers !== 'object' || headers === null || Array.isArray(headers)) {
      return indicators;
    }

    for (const key of Object.keys(headers)) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        indicators.push({
          type: 'protocol_anomaly:prototype_pollution',
          detail: `Dangerous header key detected: ${key}`
        });
        return indicators;
      }
      const val = headers[key];
      if (typeof val === 'object' && val !== null) {
        if (!Array.isArray(val)) {
          indicators.push({
            type: 'protocol_anomaly:circular_reference',
            detail: `Nested object in headers detected (potential prototype pollution/DoS)`
          });
          return indicators;
        }
        for (const item of val) {
          if (typeof item === 'object' && item !== null) {
            indicators.push({
              type: 'protocol_anomaly:circular_reference',
              detail: `Nested object in headers array detected`
            });
            return indicators;
          }
        }
      } else if (typeof val === 'function') {
        indicators.push({
          type: 'protocol_anomaly:function_header',
          detail: `Function value in headers detected`
        });
        return indicators;
      }
    }

    // L7 Defenses: Memory exhaustion sizing heuristics
    try {
      const headerSize = JSON.stringify(headers).length;
      if (headerSize > MAX_HEADER_SIZE) {
        indicators.push({
          type: 'oversized_headers',
          detail: `Aggregated Header blob size ${headerSize}B violates Max Limit (${MAX_HEADER_SIZE}B)`,
        });
      }
    } catch (e) {
      // Handle circular references or other stringify errors
      indicators.push({
        type: 'oversized_headers',
        detail: `Header serialization failed (possible circular reference)`,
      });
    }

    const queryKeys = Object.keys(decodedReq.query || {});
    if (queryKeys.length > MAX_QUERY_PARAMS) {
      indicators.push({
        type: 'parameter_flood',
        detail: `Hyper-fragmented URL parameters: ${queryKeys.length} items`,
      });
    }

    const contentLength = parseInt(decodedReq.headers['content-length'] || '0', 10);
    if (contentLength > 100 * 1024 * 1024) { // 100MB static cutoff (Application-level)
      indicators.push({
        type: 'oversized_body',
        detail: `Content-Length ${contentLength}B exceeds absolute safety threshold`,
      });
    }

    SLOWLORIS_TRACKER.set(ip, tracker);
    return indicators;
  } finally {
    if (TRACKER_LOCKS.get(ip) === nextLock) {
      TRACKER_LOCKS.delete(ip);
    }
    resolveLock();
  }
}

/**
 * High-velocity metric tracking. Unlike structural Rate Limiting, this detects pure burst floods.
 * @param {Object} decodedReq - Request interface mapping.
 * @returns {Array<Object>} Threat descriptors if anomalous volumes are breached.
 */
function checkConnectionFlood(decodedReq) {
  const ip = decodedReq.ip;
  const now = Date.now();
  const windowMs = 60000; // 1-minute tracking window

  // // FIX(BUG_37): Enforce global limit before adding new entries to prevent OOM
  let tracker = CONNECTION_TRACKER.get(ip);
  if (!tracker) {
    if (CONNECTION_TRACKER.size >= MAX_TRACKER_SIZE) {
      const oldest = CONNECTION_TRACKER.keys().next().value;
      if (oldest !== undefined) {
        CONNECTION_TRACKER.delete(oldest);
      }
    }
    tracker = { requests: [] };
  }

  tracker.requests = tracker.requests.filter(ts => now - ts < windowMs);
  tracker.requests.push(now);

  CONNECTION_TRACKER.set(ip, tracker);

  if (tracker.requests.length > MAX_CONNECTIONS_PER_IP) {
    return [{
      type: 'connection_flood',
      detail: `Volumetric Spike: ${tracker.requests.length} socket pulses per min (Safe: ${MAX_CONNECTIONS_PER_IP})`,
    }];
  }

  return [];
}

/**
 * Main execution routing. Bridges local Memory telemetry against Engine Risk layers.
 * * @fix BUG_38
 * @param {Object} decodedReq - Standard target payload object.
 * @returns {Promise<Array>} Risk matches pushed structurally to engine.js.
 */
async function check(decodedReq) {
  const matches = [];
  const allIndicators = [];
  const ip = decodedReq.ip;

  // // FIX(BUG_38): Reject immediately if the IP is missing or format is invalid
  if (!ip || !_isValidIP(ip)) {
    return [{
      rule: 'ddos_protection:invalid_ip',
      tags: ['dos', 'ddos', 'spoofing'],
      severity: 'critical',
      category: 'dos',
      description: `IP Spoofing / Invalid IP format: ${ip || 'missing'}`,
      author: 'shieldwall-core',
      sourceFile: 'builtin:ddos-protection',
      matchedPatterns: [{
         name: 'invalid_ip',
         matched: ip || 'missing',
      }],
    }];
  }

  // // FIX(WHITELIST): Ignore DDoS checks for whitelisted IPs
  if (isWhitelisted(ip)) {
    return matches;
  }

  const slowlorisIndicators = await checkSlowloris(decodedReq);
  allIndicators.push(...slowlorisIndicators);

  const floodIndicators = checkConnectionFlood(decodedReq);
  allIndicators.push(...floodIndicators);

  if (allIndicators.length > 0) {
    // // FIX(METRICS): Increment metrics block counter
    METRICS.blockedCounts++;

    const hasOversized = allIndicators.some(i => 
      i.type === 'oversized_body' || i.type === 'oversized_headers'
    );
    // Severe memory-breaking attacks map to critical. Simple network bursts map to high.
    const severity = hasOversized ? 'critical' : 'high';
    
    matches.push({
      rule: 'ddos_protection',
      tags: ['dos', 'ddos', 'flood'],
      severity,
      category: 'dos',
      description: `L7 Volumetric Threat: ${allIndicators.map(i => i.type).join(', ')}`,
      author: 'shieldwall-core', // Ownership corrected from personal alias
      sourceFile: 'builtin:ddos-protection',
      matchedPatterns: allIndicators.map(i => ({
         name: i.type,
         matched: i.detail,
      })),
    });
  }
  
  return matches;
}

/**
 * Background Garbage Collection (GC) Tick.
 * CRITICAL FIX: Mitigates OOM leakage by sweeping both Connection and Slowloris state sets.
 */
setInterval(() => {
  const now = Date.now();
  
  // Clean burst tracking Maps
  for (const [ip, tracker] of CONNECTION_TRACKER.entries()) {
    tracker.requests = tracker.requests.filter(ts => now - ts < 60000);
    if (tracker.requests.length === 0) {
      CONNECTION_TRACKER.delete(ip);
    }
  }

  // Clean stale/orphaned Slowloris allocations
  for (const [ip, sTracker] of SLOWLORIS_TRACKER.entries()) {
    if (now - sTracker.lastActivity > SLOWLORIS_TIMEOUT + 5000) {
      SLOWLORIS_TRACKER.delete(ip);
    }
  }

}, CLEANUP_INTERVAL);

module.exports = {
  check,
  METRICS,
  WHITELIST,
  addToWhitelist,
  removeFromWhitelist
};
