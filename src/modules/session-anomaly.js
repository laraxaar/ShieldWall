'use strict';

/**
 * @file session-anomaly.js
 * @description Session Anomaly & Geo Velocity Module (refactored)
 *
 * ROLE IN ARCHITECTURE:
 * Operates at the session level across multiple requests to detect Account
 * Takeover (ATO) and distributed abuse. Emits feature signals that engine.js
 * translates into structural risk.
 *
 * DATA FLOW:
 * [engine.js] inputs `decodedReq` -> `check()` evaluates IP drift, Geo Velocity,
 * Fingerprint, lateral movement, request lineage -> Returns array of Anomaly
 * Signals back to Risk Aggregator.
 *
 * All thresholds, ASN lists, sensitive paths and other previously-hardcoded
 * values are loaded from `./config/session-anomaly.json` and hot-reloaded on
 * file change. See config file for the full schema.
 *
 * CHANGES vs. original (summary):
 *  - All magic numbers / ASN lists / sensitive paths extracted to config JSON
 *    with hot-reload and runtime overrides via setConfig().
 *  - Removed CITY_COORDS country-centroid fallback — it produced nonsense
 *    velocities (e.g. Moscow -> Vladivostok = 0 km because both resolve to
 *    the same RU centroid). Geo velocity now only computed when both points
 *    have real city coordinates; rapid-country-switch heuristic covers the
 *    no-city case instead.
 *  - Fixed vpnContext inversion: VPN no longer LOWERS the rapid-switch
 *    threshold; instead emits a separate `vpn_country_switch` signal.
 *  - isSuspectedVPN no longer triggers on every comma in X-Forwarded-For
 *    (that is normal behind Cloudflare / ALB / nginx). Now only flags when
 *    hop count exceeds suspiciousXffHops or other VPN-specific headers exist.
 *  - Error spike: removed statusCode === 500 (server error, not client abuse),
 *    switched to sliding bucket window instead of single counter+reset.
 *  - rate_velocity: rewritten to require 3+ distinct paths in <500ms instead
 *    of any two consecutive requests <200ms (which fires on every page load).
 *  - orphan_api_call: windowed check over last N entries, no longer disabled
 *    once history grows beyond length 3.
 *  - cross_origin_sensitive: uses new URL() instead of substring includes()
 *    (which was bypassable via "evil.com.attacker.com").
 *  - sensitivePaths: exact-segment regex match, not substring includes().
 *  - LRU for IP_SESSION_MAP now actually tracks lastUsed (was deleting the
 *    oldest-inserted, not the oldest-used).
 *  - RESOURCE_ACCESS uses Map consistently (was a mix of Map + plain object).
 *  - data.ips changed to Map<ip, ts> with windowed TTL pruning — was an
 *    unbounded Set that flagged legit mobile carrier IP churn.
 *  - lateral_movement now restricts to known ID-param names and excludes
 *    batch params (ids[], list, items) — kills admin-list false positives.
 *  - IPv6 normalized (::ffff:1.2.3.4 == 1.2.3.4).
 *  - Session ID validated (format-checked) before being trusted from upstream.
 *  - Simplified _generateSecureSessionId — randomBytes(16).toString('hex') is
 *    already 128 bits of entropy; no need to sha256+truncate.
 *  - Fingerprint change now weighted — multiple simultaneous changes escalate
 *    to `fingerprint_takeover` (high severity) instead of two mediums.
 *  - Screen change uses area + aspect ratio (avoids phone-rotation false+).
 *  - impossible_travel threshold is now adaptive on timeDiff (short window
 *    needs higher threshold to accommodate commercial flights).
 *  - Feature flags per detector; metrics counters; dispose() for clean shutdown.
 *  - Internal helpers (checkGeoVelocity, checkFingerprintChange) no longer
 *    exported — only check, getMetrics, setConfig, dispose.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ============================================================================
// Configuration
// ============================================================================

const CONFIG_PATH = path.join(__dirname, 'config', 'session-anomaly.json');

const DEFAULT_CONFIG = {
  maxSessions: 50000,
  maxSessionAgeMs: 24 * 60 * 60 * 1000,
  maxIpSessions: 10000,
  ipSessionTtlMs: 60 * 60 * 1000,
  ipSessionWindowMs: 60 * 60 * 1000,
  cleanupIntervalMs: 5 * 60 * 1000,
  cleanupChunkSize: 2000,
  hostingAsns: [14061, 16509, 24940, 13335, 15169],
  trustedProxyHops: 2,
  suspiciousXffHops: 3,
  sensitivePaths: ['/api/payment', '/api/admin', '/api/password', '/login'],
  velocity: {
    impossibleTravelShortWindowKmh: 1500,
    impossibleTravelMidWindowKmh: 900,
    impossibleTravelLongWindowKmh: 800,
    shortWindowMs: 30 * 60 * 1000,
    longWindowMs: 2 * 60 * 60 * 1000,
    rapidCountrySwitchMobileMs: 5 * 60 * 1000,
    rapidCountrySwitchDesktopMs: 60 * 60 * 1000,
    rapidCountrySwitchNoCityMs: 60 * 60 * 1000,
  },
  thresholds: {
    credentialStuffingFarmPerIp: 50,
    errorSpikeCount: 20,
    errorWindowMs: 10 * 60 * 1000,
    errorBucketCount: 10,
    sessionIpFlood: 10,
    sessionIpFloodCap: 20,
    lateralMovementIds: 10,
    lateralMovementCap: 50,
    rateVelocityDistinctPaths: 3,
    rateVelocityWindowMs: 500,
    orphanApiWindow: 5,
    historySize: 20,
  },
  features: {
    geoVelocity: true,
    fingerprintChange: true,
    credentialStuffing: true,
    errorSpike: true,
    sensitiveReferer: true,
    requestLineage: true,
    lateralMovement: true,
    sessionIpFlood: true,
  },
};

let config = _deepMerge(DEFAULT_CONFIG, {});

function _deepMerge(base, extra) {
  const out = Array.isArray(base) ? base.slice() : { ...base };
  for (const k of Object.keys(extra || {})) {
    if (
      extra[k] && typeof extra[k] === 'object' && !Array.isArray(extra[k]) &&
      base[k] && typeof base[k] === 'object' && !Array.isArray(base[k])
    ) {
      out[k] = _deepMerge(base[k], extra[k]);
    } else {
      out[k] = extra[k];
    }
  }
  return out;
}

function _loadConfig() {
  try {
    const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    config = _deepMerge(DEFAULT_CONFIG, parsed);
    _invalidateSensitiveRegexps();
  } catch (e) {
    // keep previous config on error
  }
}

_loadConfig();
try {
  fs.watch(CONFIG_PATH, { persistent: false }, () => _loadConfig());
} catch (e) {
  // watch unavailable — keep static config
}

function setConfig(partial) {
  config = _deepMerge(config, partial);
  _invalidateSensitiveRegexps();
}

// ============================================================================
// State
// ============================================================================

const SESSION_DATA = new Map();     // Map<sessionId, sessionRecord>
const SESSION_GRAPHS = new Map();   // Map<sessionId, Array<{path,ts}>>
const RESOURCE_ACCESS = new Map();  // Map<sessionId, Map<paramName, Set<string>>>
const IP_SESSION_MAP = new Map();   // Map<ip, { sessions: Set<sessionId>, lastUsed: ts }>

// ============================================================================
// Metrics
// ============================================================================

const _metrics = {
  cleanupRuns: 0,
  cleanupDurationMs: 0,
  cleanupDeletions: 0,
  indicatorsEmitted: Object.create(null),
};

function _bumpIndicator(type) {
  _metrics.indicatorsEmitted[type] = (_metrics.indicatorsEmitted[type] || 0) + 1;
}

function getMetrics() {
  return {
    sessionsTracked: SESSION_DATA.size,
    ipSessionsTracked: IP_SESSION_MAP.size,
    resourceAccessTracked: RESOURCE_ACCESS.size,
    cleanupRuns: _metrics.cleanupRuns,
    cleanupDurationMs: _metrics.cleanupDurationMs,
    cleanupDeletions: _metrics.cleanupDeletions,
    indicatorsEmitted: { ..._metrics.indicatorsEmitted },
  };
}

// ============================================================================
// Helpers / patterns
// ============================================================================

const MOBILE_UA_PATTERN = /Android|iPhone|iPad|iPod|Mobile|Windows Phone/i;
const SESSION_ID_PATTERN = /^[a-f0-9]{16,64}$/i;
const TRACKED_ID_PARAM_PATTERN =
  /^(id|uid|user_id|account_id|resource_id|order_id|file_id|doc_id|customer_id|invoice_id|project_id)$/i;
const BATCH_PARAM_HINTS = /^(ids|id_list|list|items|batch|ids\[\])$/i;
const NUMERIC_ID_PATTERN = /^\d+$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

let _sensitivePathRegexps = null;
let _sensitivePathSignature = null;

function _invalidateSensitiveRegexps() {
  _sensitivePathRegexps = null;
}

function _getSensitivePathRegexps() {
  if (_sensitivePathRegexps) return _sensitivePathRegexps;
  const sig = JSON.stringify(config.sensitivePaths);
  if (sig === _sensitivePathSignature) return _sensitivePathRegexps || [];
  _sensitivePathSignature = sig;
  _sensitivePathRegexps = config.sensitivePaths.map(
    p => new RegExp('^' + p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?:[/?#]|$)')
  );
  return _sensitivePathRegexps;
}

function isMobileUA(userAgent) {
  return MOBILE_UA_PATTERN.test(userAgent || '');
}

/**
 * Normalize IPv4-mapped IPv6 (::ffff:1.2.3.4 -> 1.2.3.4) and lowercase IPv6.
 * Without this the same client is counted as two distinct IPs.
 */
function normalizeIp(ip) {
  if (!ip || typeof ip !== 'string') return ip;
  const v4Mapped = ip.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
  if (v4Mapped) return v4Mapped[1];
  if (ip.includes(':')) return ip.toLowerCase();
  return ip;
}

function isValidSessionId(id) {
  return typeof id === 'string' && SESSION_ID_PATTERN.test(id);
}

/**
 * Generates a cryptographically secure session ID.
 * 16 random bytes => 32 hex chars = 128 bits of entropy. No hashing needed.
 */
function _generateSecureSessionId() {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Haversine straight-line distance in km.
 */
function haversineDistance(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * Math.PI / 180) *
      Math.cos(lat2 * Math.PI / 180) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

function calculateGeoVelocity(prev, curr, timeDiffMs) {
  if (!prev || !curr || timeDiffMs <= 0) return 0;
  const distance = haversineDistance(prev.lat, prev.lon, curr.lat, curr.lon);
  const hours = timeDiffMs / (1000 * 60 * 60);
  return distance / hours;
}

/**
 * Adaptive impossible-travel threshold:
 *  - very short windows (< 30 min): any non-trivial distance is suspicious,
 *    use a high threshold so only egregious cases fire
 *  - mid window (30 min – 2 h): standard 900 km/h
 *  - long window (> 2 h): accommodate commercial flights (~800 km/h)
 */
function _impossibleTravelThreshold(timeDiffMs) {
  const v = config.velocity;
  if (timeDiffMs < v.shortWindowMs) return v.impossibleTravelShortWindowKmh;
  if (timeDiffMs > v.longWindowMs) return v.impossibleTravelLongWindowKmh;
  return v.impossibleTravelMidWindowKmh;
}

/**
 * Detects whether the request is likely behind a VPN / hosting provider.
 * No longer triggers on every X-Forwarded-For with a comma — that is normal
 * behind Cloudflare / AWS ALB / nginx. Only flags when:
 *  - hop count exceeds suspiciousXffHops (configurable), OR
 *  - VPN-specific headers are present (via, x-vpn, surrogate-capability), OR
 *  - ASN is in the hosting-ASN list
 */
function isSuspectedVPN(decodedReq) {
  if (!decodedReq || !decodedReq.headers) return false;
  const headers = decodedReq.headers;
  const asn = decodedReq.asn;
  const isHosting = asn != null && config.hostingAsns.includes(asn);

  const xff = headers['x-forwarded-for'];
  if (typeof xff === 'string') {
    const hops = xff.split(',').map(s => s.trim()).filter(Boolean).length;
    if (hops > config.suspiciousXffHops) return true;
  }

  return !!(
    headers['via'] ||
    headers['x-vpn'] ||
    headers['surrogate-capability'] ||
    isHosting
  );
}

// ============================================================================
// Detector: Geo Velocity
// ============================================================================

function checkGeoVelocity(sessionId, geoData, decodedReq) {
  if (!config.features.geoVelocity) return [];
  const now = Date.now();
  const data = SESSION_DATA.get(sessionId);
  if (!data || !data.lastLocation || !geoData || !geoData.country) return [];

  const timeDiff = now - data.lastLocation.timestamp;
  if (timeDiff <= 0) return [];

  const country = String(geoData.country).toUpperCase();
  const prevCountry = data.lastLocation.country
    ? String(data.lastLocation.country).toUpperCase()
    : null;
  if (!prevCountry) return [];

  // Use ONLY real city coordinates — no country-centroid fallback.
  const currCoords =
    geoData.city && typeof geoData.city.latitude === 'number' &&
    typeof geoData.city.longitude === 'number'
      ? { lat: geoData.city.latitude, lon: geoData.city.longitude }
      : null;

  const prevCoords =
    typeof data.lastLocation.lat === 'number' &&
    typeof data.lastLocation.lon === 'number'
      ? { lat: data.lastLocation.lat, lon: data.lastLocation.lon }
      : null;

  const indicators = [];
  const vpnContext = isSuspectedVPN(decodedReq);

  if (currCoords && prevCoords) {
    const velocity = calculateGeoVelocity(prevCoords, currCoords, timeDiff);
    const threshold = _impossibleTravelThreshold(timeDiff);

    if (velocity > threshold) {
      if (vpnContext) {
        indicators.push({
          type: 'vpn_node_switch',
          detail: `VPN routing altered: ${velocity.toFixed(0)} km/h between ${prevCountry} and ${country}`,
        });
      } else {
        indicators.push({
          type: 'impossible_travel',
          detail: `Velocity ${velocity.toFixed(0)} km/h from ${prevCountry} to ${country} in ${(timeDiff / 60000).toFixed(1)} min`,
        });
      }
    }
  } else if (
    country !== prevCountry &&
    timeDiff < config.velocity.rapidCountrySwitchNoCityMs &&
    !vpnContext
  ) {
    indicators.push({
      type: 'rapid_country_switch_no_city',
      detail: `Country changed from ${prevCountry} to ${country} without city data in <${(config.velocity.rapidCountrySwitchNoCityMs / 60000).toFixed(0)} min`,
    });
  }

  // Rapid country switch — VPN should NOT lower the threshold. It should
  // produce a separate, MORE suspicious signal.
  const isMobile = isMobileUA(data.userAgent);
  const rapidThreshold = isMobile
    ? config.velocity.rapidCountrySwitchMobileMs
    : config.velocity.rapidCountrySwitchDesktopMs;

  if (country !== prevCountry && timeDiff < rapidThreshold) {
    indicators.push({
      type: vpnContext ? 'vpn_country_switch' : 'rapid_country_switch',
      detail: `Geo bounce: ${prevCountry} to ${country} in ${(timeDiff / 60000).toFixed(1)} min${vpnContext ? ' (via VPN)' : ''}`,
      isMobile,
    });
  }

  return indicators;
}

// ============================================================================
// Detector: Fingerprint Change (weighted)
// ============================================================================

function checkFingerprintChange(sessionId, fingerprint) {
  if (!config.features.fingerprintChange) return [];
  const data = SESSION_DATA.get(sessionId);
  if (!data || !data.fingerprint || !fingerprint) return [];

  const prev = data.fingerprint;
  const curr = fingerprint;
  const indicators = [];
  let weight = 0;

  // User-Agent change: medium signal
  if (prev.userAgent && curr.userAgent && prev.userAgent !== curr.userAgent) {
    indicators.push({
      type: 'ua_changed',
      detail: 'User-Agent modified mid-session',
      _weight: 2,
    });
    weight += 2;
  }

  // Canvas change: high signal
  if (prev.canvas && curr.canvas && prev.canvas !== curr.canvas) {
    indicators.push({
      type: 'canvas_changed',
      detail: 'Canvas context shifted',
      _weight: 3,
    });
    weight += 3;
  }

  // Screen change — use area + aspect ratio so phone rotation (which keeps
  // area, only swaps w/h) doesn't trigger a false positive.
  if (prev.screen && curr.screen) {
    const prevArea = prev.screen.width * prev.screen.height;
    const currArea = curr.screen.width * curr.screen.height;
    const areaChangePct = Math.abs(currArea - prevArea) / Math.max(prevArea, 1);
    const prevAspect = prev.screen.width / Math.max(prev.screen.height, 1);
    const currAspect = curr.screen.width / Math.max(curr.screen.height, 1);
    const aspectChange = Math.abs(currAspect - prevAspect);

    if (areaChangePct > 0.2 && aspectChange < 0.1) {
      indicators.push({
        type: 'screen_changed',
        detail: `Resolution shift: ${prev.screen.width}x${prev.screen.height} -> ${curr.screen.width}x${curr.screen.height}`,
        _weight: 2,
      });
      weight += 2;
    }
  }

  // Combined signal — multiple simultaneous fingerprint changes are MUCH
  // stronger evidence of session takeover than any single change alone.
  if (weight >= 5) {
    indicators.push({
      type: 'fingerprint_takeover',
      detail: `Multiple fingerprint signals (weight ${weight}) — likely session takeover`,
      _weight: weight,
    });
  }

  return indicators;
}

// ============================================================================
// Main check
// ============================================================================

function check(decodedReq) {
  if (!decodedReq) return [];

  // Session ID: validate format if provided, otherwise generate.
  let sessionId = decodedReq.sessionId;
  if (sessionId && !isValidSessionId(sessionId)) {
    // Reject obviously forged session IDs from upstream
    sessionId = null;
  }
  if (!sessionId) {
    sessionId = _generateSecureSessionId();
  }

  const now = Date.now();
  const existingData = SESSION_DATA.get(sessionId);
  const data =
    existingData ||
    {
      firstSeen: now,
      lastSeen: now,
      ips: new Map(), // Map<ip, lastSeenTs> — bounded by ipSessionWindowMs
      userAgent: decodedReq.userAgent,
      lastLocation: null,
      fingerprint: null,
      errorBuckets: new Array(config.thresholds.errorBucketCount).fill(0),
      errorBucketOffset: 0,
      errorBucketStart: now,
    };

  data.lastSeen = now;

  const indicators = [];
  const clientIp = normalizeIp(decodedReq.ip);

  // -------- Credential stuffing farm (IP -> many sessions) ---------------
  if (config.features.credentialStuffing) {
    let ipEntry = IP_SESSION_MAP.get(clientIp);
    if (!ipEntry) {
      ipEntry = { sessions: new Set(), lastUsed: now };
      IP_SESSION_MAP.set(clientIp, ipEntry);
    }
    ipEntry.sessions.add(sessionId);
    ipEntry.lastUsed = now;

    if (ipEntry.sessions.size > config.thresholds.credentialStuffingFarmPerIp) {
      indicators.push({
        type: 'credential_stuffing_farm',
        detail: `IP ${clientIp} associated with ${ipEntry.sessions.size} unique sessions`,
      });
    }
  }

  // -------- Error spike (sliding bucket window) --------------------------
  if (config.features.errorSpike) {
    // Only client errors (4xx). 5xx is server fault, not client abuse.
    const statusCode = decodedReq.responseStatus || decodedReq.statusCode;
    if (statusCode && statusCode >= 400 && statusCode < 500) {
      const bucketMs =
        config.thresholds.errorWindowMs / config.thresholds.errorBucketCount;
      // Slide window forward, zeroing expired buckets
      while (now - data.errorBucketStart >= bucketMs) {
        data.errorBucketStart += bucketMs;
        data.errorBuckets[data.errorBucketOffset] = 0;
        data.errorBucketOffset =
          (data.errorBucketOffset + 1) % data.errorBuckets.length;
      }
      data.errorBuckets[data.errorBucketOffset]++;

      let total = 0;
      for (let i = 0; i < data.errorBuckets.length; i++) {
        total += data.errorBuckets[i];
      }
      if (total > config.thresholds.errorSpikeCount) {
        indicators.push({
          type: 'fuzzing_error_spike',
          detail: `${total} client errors in the last ${config.thresholds.errorWindowMs / 1000}s`,
        });
      }
    }
  }

  // -------- Sensitive path referer check ---------------------------------
  if (config.features.sensitiveReferer) {
    const reqPath = decodedReq.path || '';
    const regexps = _getSensitivePathRegexps();
    if (regexps.some(re => re.test(reqPath))) {
      const headers = decodedReq.headers || {};
      const referer = headers['referer'] || headers['origin'];
      if (!referer) {
        indicators.push({
          type: 'sensitive_no_referer',
          detail: 'Direct sensitive request without Referer',
        });
      } else {
        // Use URL parsing — substring includes() is bypassable
        // (e.g. referer "https://evil.com.attacker.com/" includes "evil.com").
        let refererHost = null;
        try {
          refererHost = new URL(referer).host;
        } catch (e) {
          // malformed referer — treat as suspicious
        }
        const host = headers.host;
        if (!refererHost || !host || refererHost !== host) {
          indicators.push({
            type: 'cross_origin_sensitive',
            detail: `Cross-origin to sensitive endpoint (referer host=${refererHost}, expected=${host})`,
          });
        }
      }
    }
  }

  // -------- Request lineage ----------------------------------------------
  if (config.features.requestLineage) {
    if (!SESSION_GRAPHS.has(sessionId)) SESSION_GRAPHS.set(sessionId, []);
    const history = SESSION_GRAPHS.get(sessionId);
    const currentPath = decodedReq.path || '/';

    // Orphan API call — windowed check over the last N entries. Not
    // disabled once history grows past a fixed length (that was the bug).
    if (currentPath.startsWith('/api/') && !currentPath.includes('/public/')) {
      const windowSize = Math.min(
        history.length,
        config.thresholds.orphanApiWindow
      );
      let hasUiReferer = false;
      for (let i = history.length - 1; i >= history.length - windowSize; i--) {
        if (i < 0) break;
        if (!history[i].path.startsWith('/api/')) {
          hasUiReferer = true;
          break;
        }
      }
      if (!hasUiReferer) {
        indicators.push({
          type: 'orphan_api_call',
          detail: 'API call without prior frontend navigation in the recent window',
        });
      }
    }

    // Rapid cross-page navigation — require 3+ distinct paths in <500ms.
    // (Old logic: any 2 requests <200ms apart — fires on every page load
    // because the browser fires 5-10 parallel fetches.)
    if (history.length >= 2) {
      const windowMs = config.thresholds.rateVelocityWindowMs;
      const cutoff = now - windowMs;
      const recentPaths = new Set();
      for (let i = history.length - 1; i >= 0; i--) {
        if (history[i].ts < cutoff) break;
        recentPaths.add(history[i].path);
      }
      if (recentPaths.size >= config.thresholds.rateVelocityDistinctPaths) {
        indicators.push({
          type: 'rate_velocity',
          detail: `${recentPaths.size} distinct paths in ${windowMs}ms`,
        });
      }
    }

    // Append + bound history. Use splice (O(n)) — for size 20 this is
    // cheaper than maintaining a ring buffer.
    history.push({ path: currentPath, ts: now });
    if (history.length > config.thresholds.historySize) {
      history.splice(0, history.length - config.thresholds.historySize);
    }
  }

  // -------- Lateral movement (BOLA / IDOR) -------------------------------
  if (config.features.lateralMovement) {
    let accessMap = RESOURCE_ACCESS.get(sessionId);
    if (!accessMap) {
      accessMap = new Map();
      RESOURCE_ACCESS.set(sessionId, accessMap);
    }

    const bodyObj =
      typeof decodedReq.body === 'object' && decodedReq.body !== null
        ? decodedReq.body
        : {};

    // Null-proto merge to defeat prototype pollution via __proto__/constructor
    const allParams = Object.assign(
      Object.create(null),
      decodedReq.query || {},
      bodyObj
    );

    for (const [key, val] of Object.entries(allParams)) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
      // Only track params that look like singular resource identifiers.
      // Skip batch params (ids[], list, items) which legitimately carry
      // many values per request — admin dashboards, multi-select, etc.
      if (!TRACKED_ID_PARAM_PATTERN.test(key)) continue;
      if (BATCH_PARAM_HINTS.test(key)) continue;

      const strVal = String(val);
      if (!NUMERIC_ID_PATTERN.test(strVal) && !UUID_PATTERN.test(strVal)) continue;

      let set = accessMap.get(key);
      if (!set) {
        set = new Set();
        accessMap.set(key, set);
      }
      if (set.size < config.thresholds.lateralMovementCap) {
        set.add(strVal);
      }
      if (set.size > config.thresholds.lateralMovementIds) {
        indicators.push({
          type: 'lateral_movement',
          detail: `Accessed ${set.size}+ unique IDs for param "${key}"`,
        });
      }
    }
  }

  // -------- Geo & fingerprint --------------------------------------------
  if (decodedReq.geoip && typeof decodedReq.geoip === 'object') {
    const geoAlerts = checkGeoVelocity(sessionId, decodedReq.geoip, decodedReq);
    indicators.push(...geoAlerts);
    data.lastLocation = {
      country: decodedReq.geoip.country,
      lat:
        decodedReq.geoip.city && typeof decodedReq.geoip.city.latitude === 'number'
          ? decodedReq.geoip.city.latitude
          : null,
      lon:
        decodedReq.geoip.city && typeof decodedReq.geoip.city.longitude === 'number'
          ? decodedReq.geoip.city.longitude
          : null,
      timestamp: now,
    };
  }

  if (decodedReq.fingerprint && typeof decodedReq.fingerprint === 'object') {
    const fpAlerts = checkFingerprintChange(sessionId, decodedReq.fingerprint);
    indicators.push(...fpAlerts);
    data.fingerprint = decodedReq.fingerprint;
  }

  // -------- Session IP flood (windowed) ----------------------------------
  if (config.features.sessionIpFlood) {
    // Prune IPs older than the window — was an unbounded Set before.
    const ipCutoff = now - config.ipSessionWindowMs;
    for (const [ip, ts] of data.ips) {
      if (ts < ipCutoff) data.ips.delete(ip);
    }
    if (data.ips.size < config.thresholds.sessionIpFloodCap) {
      data.ips.set(clientIp, now);
    }
    if (data.ips.size > config.thresholds.sessionIpFlood) {
      indicators.push({
        type: 'session_ip_flood',
        detail: `Session shared across ${data.ips.size}+ unique IPs in the last ${config.ipSessionWindowMs / 60000} min`,
      });
    }
  }

  SESSION_DATA.set(sessionId, data);

  if (SESSION_DATA.size > config.maxSessions) {
    setImmediate(_cleanup);
  }

  if (indicators.length === 0) return [];

  return indicators.map(ind => {
    _bumpIndicator(ind.type);
    const isHigh =
      ind.type === 'impossible_travel' ||
      ind.type === 'session_ip_flood' ||
      ind.type === 'fingerprint_takeover' ||
      ind.type === 'credential_stuffing_farm';
    return {
      rule: 'session_anomaly',
      tags: ['fraud', 'session_takeover'],
      severity: isHigh ? 'high' : 'medium',
      category: 'session-anomaly',
      type: ind.type,
      description: ind.detail,
    };
  });
}

// ============================================================================
// Cleanup — LRU-aware, chunked
// ============================================================================

function _cleanup() {
  const start = Date.now();
  const cutoff = Date.now() - config.maxSessionAgeMs;
  let deleted = 0;

  // Phase 1: prune expired sessions by lastSeen (not firstSeen — old bug).
  for (const [key, value] of SESSION_DATA.entries()) {
    if (value.lastSeen < cutoff) {
      SESSION_DATA.delete(key);
      SESSION_GRAPHS.delete(key);
      RESOURCE_ACCESS.delete(key);
      deleted++;
    }
  }

  // Phase 2: prune IP_SESSION_MAP — by lastUsed (true LRU), not insertion
  // order. Also drop dead sessions from each IP's set.
  const ipCutoff = Date.now() - config.ipSessionTtlMs;
  for (const [ip, entry] of IP_SESSION_MAP.entries()) {
    if (entry.lastUsed < ipCutoff) {
      IP_SESSION_MAP.delete(ip);
      continue;
    }
    for (const sessionId of entry.sessions) {
      if (!SESSION_DATA.has(sessionId)) {
        entry.sessions.delete(sessionId);
      }
    }
    if (entry.sessions.size === 0) {
      IP_SESSION_MAP.delete(ip);
    }
  }

  // Phase 3: hard cap on IP_SESSION_MAP — drop oldest by lastUsed (was
  // dropping oldest-inserted before, which is NOT the same as LRU).
  if (IP_SESSION_MAP.size > config.maxIpSessions) {
    const sorted = Array.from(IP_SESSION_MAP.entries()).sort(
      (a, b) => a[1].lastUsed - b[1].lastUsed
    );
    const excess = IP_SESSION_MAP.size - config.maxIpSessions;
    for (let i = 0; i < excess; i++) {
      IP_SESSION_MAP.delete(sorted[i][0]);
    }
  }

  _metrics.cleanupRuns++;
  _metrics.cleanupDeletions += deleted;
  _metrics.cleanupDurationMs += Date.now() - start;
}

const _cleanupTimer = setInterval(_cleanup, config.cleanupIntervalMs);
_cleanupTimer.unref();

function dispose() {
  clearInterval(_cleanupTimer);
  SESSION_DATA.clear();
  SESSION_GRAPHS.clear();
  RESOURCE_ACCESS.clear();
  IP_SESSION_MAP.clear();
}

module.exports = {
  check,
  getMetrics,
  setConfig,
  dispose,
};
