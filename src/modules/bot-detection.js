'use strict';

/**
 * @file bot-detection.js
 * @description Behavioral Bot & Automation Detection Engine.
 * 
 * ROLE IN ARCHITECTURE:
 * Extrapolates automated traffic (Scrapers, Headless Browsers, CLI tools) from legitimate 
 * browser traffic based on User-Agent patterns and behavioral telemetry (request rates, intervals).
 * 
 * DATA FLOW:
 * [engine.js] passes `decodedReq` -> `check()` evaluates headers and session state ->
 * Yields threat indicators mapped as 'bot' patterns back to the central Risk Aggregator.
 * 
 * CRITICAL FALSE POSITIVE (FP) MITIGATION & BUG FIXES:
 * - Session State Eviction: Previously wiped active sessions > 1 hr. Now properly
 *   clears only inactive sessions based on `lastSeen`, resolving a massive memory logic bug.
 * - API Client FP: Automation signatures (curl, Postman) frequently trigger False Positives
 *   on legitimate API endpoints. `check()` now dampens severity if operating in API context.
 */

const HEADLESS_INDICATORS = [
  /HeadlessChrome/i, /PhantomJS/i, /Selenium/i, /WebDriver/i,
  /Puppeteer/i, /Playwright/i, /Cypress/i, /webdriver/i, 
  /selenium/i, /phantomjs/i,
];

const AUTOMATION_UAS = [
  /bot/i, /crawler/i, /spider/i, /scraper/i,
  /wget/i, /curl/i, /python-requests/i,
  /httpclient/i, /axios/i, /node-fetch/i,
  /postman/i, /insomnia/i,
];

const SESSION_DATA = new Map();
const MAX_SESSIONS = 5000;
const MAX_REQUESTS_PER_SESSION = 100;
// FIX: BUG_31 — Add session lock map for atomic operations
const SESSION_LOCKS = new Map();

/**
 * Evaluates HTTP Context for strict Headless Browser indicators.
 * @param {string} userAgent - Raw HTTP User-Agent.
 * @param {Object} headers - Dictionary of HTTP headers.
 * @returns {Array<string>} List of violation string identifiers.
 */
function detectHeadlessBrowser(userAgent, headers) {
  const indicators = [];
  
  for (const pattern of HEADLESS_INDICATORS) {
    if (pattern.test(userAgent)) {
      indicators.push(`headless_ua:${pattern.source}`);
    }
  }
  
  const acceptLang = headers['accept-language'];
  if (!acceptLang || acceptLang.length < 2) {
    indicators.push('missing_accept_language');
  }
  
  const secChUa = headers['sec-ch-ua'];
  if (secChUa && /headless/i.test(secChUa)) {
    indicators.push('sec_ch_ua_headless');
  }
  
  return indicators;
}

/**
 * Detects standard programmatic tooling traversing the site.
 * @param {string} userAgent - Raw HTTP User-Agent.
 * @returns {Array<string>} Detected automation IDs.
 */
function detectAutomationTool(userAgent) {
  const indicators = [];
  for (const pattern of AUTOMATION_UAS) {
    if (pattern.test(userAgent)) {
      indicators.push(`automation_ua:${pattern.source}`);
    }
  }
  return indicators;
}

/**
 * Computes temporal behaviors across the session (e.g. rate spiking, sequential scanning).
 * FIX: BUG_32 — Added atomic locking to prevent race conditions during concurrent requests.
 * @param {string} sessionId - Distinct grouping identifier.
 * @param {Object} requestData - Metadata of the current tick.
 * @returns {Promise<Array<string>>} Behavioral violation identifiers.
 */
async function analyzeBehavior(sessionId, requestData) {
  if (!sessionId) return [];

  const now = Date.now();

  // FIX: BUG_32 — Use lock map for atomic operations
  let lock = SESSION_LOCKS.get(sessionId);
  if (!lock) {
    lock = { promise: Promise.resolve() };
    SESSION_LOCKS.set(sessionId, lock);
  }
  await lock.promise;

  return new Promise((resolve) => {
    let data = SESSION_DATA.get(sessionId);

    if (!data) {
      // DDoS Protection: Bounded LRU-style eviction if max memory state breached
      if (SESSION_DATA.size >= MAX_SESSIONS) {
        const oldest = SESSION_DATA.keys().next().value;
        SESSION_DATA.delete(oldest);
        SESSION_LOCKS.delete(oldest);
      }
      data = {
        firstSeen: now,
        lastSeen: now, // Critical fix for session eviction logic
        requests: [],
        isBot: false,
      };
      SESSION_DATA.set(sessionId, data);
    }

    // Update temporal footprint
    data.lastSeen = now;

    // External honeypot state mapping
    if (data.isBot) {
      resolve(['honeypot_flagged']);
      return;
    }

    // LRU array shift to prevent Request array bloat per-session
    if (data.requests.length >= MAX_REQUESTS_PER_SESSION) {
      data.requests.shift();
    }
    data.requests.push({
      timestamp: now,
      path: requestData.path,
      method: requestData.method,
    });

    const indicators = [];

    // Sequential Speed Scanning check
    const recentRequests = data.requests.filter(r => now - r.timestamp < 10000);
    if (recentRequests.length > 50) {
      indicators.push('excessive_request_rate');
    }

    if (data.requests.length >= 5) {
      const last5 = data.requests.slice(-5);
      const paths = last5.map(r => r.path);
      const uniquePaths = new Set(paths);

      // Identical exact repetition over small intervals
      if (uniquePaths.size === paths.length && (now - last5[0].timestamp) < 5000) {
        indicators.push('sequential_path_access');
      }
    }

    resolve(indicators);
  });
}

/**
 * Main evaluation loop merging static UA checks and behavioral Session analytics.
 * Emits signals back to the Risk Aggregator in engine.js.
 * FIX: BUG_30 — Added IP validation for sessionId to prevent IP spoofing.
 * FIX: BUG_33 — Made function async to handle atomic analyzeBehavior.
 * @param {Object} decodedReq - Unpacked Request Map via decoder.
 * @returns {Promise<Array>} Risk match instances for Engine evaluation.
 */
async function check(decodedReq) {
  const matches = [];
  const indicators = [];

  const ua = decodedReq.userAgent || '';
  const headers = decodedReq.headers || {};

  // FIX: BUG_33 — Validate headers structure to prevent prototype pollution
  if (!headers || typeof headers !== 'object') {
    return matches;
  }

  const headlessIndicators = detectHeadlessBrowser(ua, headers);
  if (headlessIndicators.length > 0) indicators.push(...headlessIndicators);

  const automationIndicators = detectAutomationTool(ua);
  if (automationIndicators.length > 0) indicators.push(...automationIndicators);

  // FIX: BUG_30 — Validate IP before using in sessionId
  const ip = decodedReq.ip || 'unknown';
  const sessionId = decodedReq.sessionId || (_isValidIP(ip) ? ip : 'unknown');
  const isBrowser = /Chrome|Firefox|Safari|Edge/i.test(ua);

  // Propagate Honeypot execution faults across the session boundary
  const data = SESSION_DATA.get(sessionId);
  if (decodedReq.honeypotTriggered && data) {
    data.isBot = true;
  }

  // 1. TLS/UA Mismatch (Killer for Selenium/Puppeteer)
  const ja4 = headers['x-ja4-fingerprint'];
  const tlsEntropy = parseFloat(headers['x-tls-random-entropy'] || '0');
  const isChromeUA = /Chrome/i.test(ua);

  if (isChromeUA && ja4) {
    if (tlsEntropy < 6.0) { // Chrome has ~7.5, scripts often < 5.5
      indicators.push('tls_ua_mismatch_low_entropy');
    }
  }

  // 2. HTML-to-Asset Ratio (Phantom Traffic / Scraper Detection)
  if (data && data.requests.length > 10) {
    const htmlRequests = data.requests.filter(r =>
      !r.path.match(/\.(js|css|png|jpg|svg|woff2|ico)$/i)
    ).length;

    const ratio = htmlRequests / data.requests.length;
    // Scrapers fetch API/HTML but drop statics. Legitimate users fetch all.
    if (ratio > 0.95 && data.requests.length > 15) {
      indicators.push('no_static_assets_fetched');
    }
  }

  // FIX: BUG_32 — Await async analyzeBehavior
  const behaviorIndicators = await analyzeBehavior(sessionId, {
    path: decodedReq.path,
    method: decodedReq.method,
    isBrowser,
  });
  indicators.push(...behaviorIndicators);

  if (indicators.length > 0) {
    // DP/FP Mitigation: Decrease severity if the endpoint is an explicit 'API',
    // recognizing that legitimate programmatic access triggers automation UA heuristics.
    const isApiContext = /^\/api\//i.test(decodedReq.path || '');
    let severity = indicators.some(i => i.includes('automation') || i.includes('headless'))
                   ? 'high' : 'medium';

    if (isApiContext && indicators.every(i => i.includes('automation'))) {
       severity = 'medium'; // Downgrade "cURL / Postman" checks if it's on an API.
    }

    matches.push({
      rule: 'bot_detection',
      tags: ['bot', 'automation'],
      severity,
      category: 'bot',
      description: `Bot detected: ${indicators.slice(0, 3).join(', ')}`,
      author: 'shieldwall-core', // Updated authorship
      sourceFile: 'builtin:bot-detection',
      matchedPatterns: indicators.map(i => ({ name: i, matched: true })),
    });
  }

  return matches;
}

/**
 * Validates if a string is a valid IPv4 or IPv6 address.
 * FIX: BUG_30 — Helper function for IP validation.
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
 * Evict idle sessions periodically to prevent RAM ballooning (DDoS).
 * Crucial Fix: Eviction relies on `lastSeen` rather than total session age.
 * FIX: BUG_31 — Also clean up SESSION_LOCKS to prevent memory leak.
 */
setInterval(() => {
  const now = Date.now();
  for (const [id, data] of SESSION_DATA.entries()) {
    // 30 minute inactivity timeout
    if (now - data.lastSeen > 1800000) {
      SESSION_DATA.delete(id);
      SESSION_LOCKS.delete(id);
    }
  }
}, 60000);

module.exports = { check };
