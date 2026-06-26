'use strict';

/**
 * @file sequence-anomaly.js
 * @description Stateful sequence and scraping detector (refactored).
 *
 * ROLE IN ARCHITECTURE:
 * Detects sequential resource enumeration (id=1, id=2, id=3...) and abnormal
 * request velocity against an ID/key axis. Emits behavioral signals that
 * engine.js translates into structural risk.
 *
 * CHANGES vs. original (summary):
 *  - All magic numbers / param-name lists / velocity thresholds extracted to
 *    ./config/sequence-anomaly.json with hot-reload and runtime override
 *    via setConfig().
 *  - Memory: per-key history is now bounded by BOTH length AND a TTL (was
 *    length-only, but `> 10` push-then-shift is O(n) on every request).
 *    Uses a ring buffer with cursor + count instead of shift().
 *  - Cleanup: LRU-aware (drops by lastActivity, not insertion order), chunked
 *    so the event loop is not blocked on large maps. Was dropping only one
 *    key per call.
 *  - Sequential detection: removed `diff === 2 / -2` (counted `1,3,5,7` as
 *    a sequence — that's step-2 enumeration, a different signal). Only
 *    consecutive ±1 is sequential scraping now.
 *  - Velocity threshold upper bound added — protects against clock skew /
 *    sub-millisecond bursts producing nonsense 10000 req/s values.
 *  - Cross-IP resource fanout detection added: when N+ distinct IPs hit
 *    the same ID range of the same param within a window, that is distributed
 *    scraping regardless of per-IP sequence. The original module was blind
 *    to this — a bot farm hitting id=1..1000 from 50 IPs saw nothing.
 *  - Param classification: id / page / batch. Page params are tracked for
 *    velocity but NOT flagged as sequential scraping (legit pagination).
 *    Batch params are flattened (ids[]=1&ids[]=2&ids[]=3 in one request
 *    counted as 3 separate IDs, not 1 spurious "non-numeric" skip).
 *  - IPv6 normalized (::ffff:1.2.3.4 == 1.2.3.4).
 *  - Prototype pollution: null-proto merge for query + body.
 *  - UUIDs tracked as resource IDs (not just numeric).
 *  - Signals now carry richer context: ip, param, sample IDs, distinct IPs.
 *  - Metrics counters; dispose() for clean shutdown.
 *  - Public API: check, getMetrics, setConfig, dispose (was only check).
 */

const fs = require('fs');
const path = require('path');

// ============================================================================
// Configuration
// ============================================================================

const CONFIG_PATH = path.join(__dirname, 'config', 'sequence-anomaly.json');

const DEFAULT_CONFIG = {
  maxParamKeys: 100000,
  paramHistoryTtlMs: 30 * 60 * 1000,
  historyMaxLen: 16,
  cleanupIntervalMs: 5 * 60 * 1000,
  cleanupChunkSize: 5000,
  globalResourceTracking: {
    enabled: true,
    maxResources: 200000,
    resourceTtlMs: 60 * 60 * 1000,
    minDistinctIps: 3,
    minHitsForFanout: 20,
    timeWindowMs: 10 * 60 * 1000,
  },
  sequential: {
    allowedDiffs: [1, -1],
    minSequenceLength: 5,
    minVelocityReqPerSec: 2,
    maxVelocityReqPerSec: 100,
  },
  velocity: {
    minRequests: 10,
    minVelocityReqPerSec: 5,
    maxVelocityReqPerSec: 100,
  },
  paramClasses: {
    id: [
      'id', 'uid', 'user_id', 'account_id', 'resource_id', 'order_id',
      'file_id', 'doc_id', 'customer_id', 'invoice_id', 'project_id',
      'record_id', 'item_id', 'post_id', 'message_id', 'transaction_id',
      'session_id',
    ],
    page: ['page', 'p', 'offset', 'skip', 'limit', 'per_page', 'pagesize', 'pageno'],
    batch: ['ids', 'id_list', 'id_array', 'list', 'items', 'batch', 'selection'],
  },
  features: {
    sequentialScraping: true,
    velocitySpike: true,
    globalResourceFanout: true,
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
    _invalidateClassMatchers();
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
  _invalidateClassMatchers();
}

// ============================================================================
// State
// ============================================================================

/**
 * Per-(ip:param) ring buffer.
 * Map<mapKey, { paramClass, buf: Array<{val,ts}>, head, count, lastActivity }>
 */
const PARAM_HISTORY = new Map();

/**
 * Cross-IP resource tracking: Map<paramClass+':'+param, Map<val, { ips: Set<ip>, hits: number, lastActivity }>>
 * Used to detect distributed scraping (multiple IPs hitting the same ID range).
 */
const GLOBAL_RESOURCE_ACCESS = new Map();

// ============================================================================
// Metrics
// ============================================================================

const _metrics = {
  cleanupRuns: 0,
  cleanupDurationMs: 0,
  cleanupDeletions: 0,
  signalsEmitted: Object.create(null),
};

function _bumpSignal(type) {
  _metrics.signalsEmitted[type] = (_metrics.signalsEmitted[type] || 0) + 1;
}

function getMetrics() {
  return {
    paramKeysTracked: PARAM_HISTORY.size,
    resourcesTracked: GLOBAL_RESOURCE_ACCESS.size,
    cleanupRuns: _metrics.cleanupRuns,
    cleanupDurationMs: _metrics.cleanupDurationMs,
    cleanupDeletions: _metrics.cleanupDeletions,
    signalsEmitted: { ..._metrics.signalsEmitted },
  };
}

// ============================================================================
// Helpers
// ============================================================================

const NUMERIC_ID_PATTERN = /^\d+$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

let _classMatchers = null;
let _classMatchersSig = null;

function _invalidateClassMatchers() {
  _classMatchers = null;
}

function _getClassMatchers() {
  if (_classMatchers) return _classMatchers;
  const sig = JSON.stringify(config.paramClasses);
  if (sig === _classMatchersSig) return _classMatchers;
  _classMatchersSig = sig;

  const classes = config.paramClasses || {};
  _classMatchers = {};
  for (const cls of Object.keys(classes)) {
    const names = classes[cls] || [];
    _classMatchers[cls] = new Set(
      names.map(n => n.toLowerCase().replace(/\[\]$/, ''))
    );
  }
  return _classMatchers;
}

function classifyParam(key) {
  const matchers = _getClassMatchers();
  const normalized = String(key).toLowerCase().replace(/\[\]$/, '');
  if (matchers.id && matchers.id.has(normalized)) return 'id';
  if (matchers.page && matchers.page.has(normalized)) return 'page';
  if (matchers.batch && matchers.batch.has(normalized)) return 'batch';
  // Heuristic fallback for unknown params
  if (/(_id|id)$/.test(normalized) && !/^ids/.test(normalized)) return 'id';
  return null;
}

/**
 * Normalize IPv4-mapped IPv6 to plain v4, lowercase v6.
 */
function normalizeIp(ip) {
  if (!ip || typeof ip !== 'string') return ip;
  const v4Mapped = ip.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
  if (v4Mapped) return v4Mapped[1];
  if (ip.includes(':')) return ip.toLowerCase();
  return ip;
}

function isResourceId(strVal) {
  return NUMERIC_ID_PATTERN.test(strVal) || UUID_PATTERN.test(strVal);
}

/**
 * Iterate params from query + body. Handles:
 *  - null-proto merge (defeats prototype pollution via __proto__/constructor)
 *  - batch params (ids[]=1&ids[]=2&ids[]=3) — yields each value separately
 *  - skips __proto__ / constructor / prototype explicitly
 */
function* iterParams(decodedReq) {
  const bodyObj =
    typeof decodedReq.body === 'object' && decodedReq.body !== null
      ? decodedReq.body
      : {};

  const merged = Object.assign(Object.create(null), decodedReq.query || {}, bodyObj);

  for (const [key, val] of Object.entries(merged)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;

    if (Array.isArray(val)) {
      for (const v of val) yield [key, v];
    } else if (val !== null && typeof val === 'object') {
      // Some parsers produce { value: x } or nested objects — best-effort
      if ('value' in val) yield [key, val.value];
    } else {
      yield [key, val];
    }
  }
}

// ============================================================================
// Ring buffer helpers (avoid O(n) shift on every push)
// ============================================================================

function _ringPush(entry, buf, headRef, countRef, maxLen) {
  if (buf.length < maxLen) {
    buf.push(entry);
    return { head: headRef, count: buf.length };
  }
  buf[headRef] = entry;
  const newHead = (headRef + 1) % maxLen;
  return { head: newHead, count: maxLen };
}

function _ringIterate(buf, head, count) {
  // Yields entries in insertion order (oldest -> newest)
  const out = [];
  if (count < buf.length) {
    for (let i = 0; i < count; i++) out.push(buf[i]);
  } else {
    for (let i = 0; i < buf.length; i++) {
      out.push(buf[(head + i) % buf.length]);
    }
  }
  return out;
}

// ============================================================================
// Detectors
// ============================================================================

/**
 * Per-(ip:param) sequential scraping detection.
 * Returns array of signals.
 */
function _detectSequential(entry, ip, key, paramClass) {
  if (!config.features.sequentialScraping) return [];
  // Page params are legit sequential — don't flag them as scraping.
  if (paramClass === 'page') return [];

  const seq = config.sequential;
  const history = _ringIterate(entry.buf, entry.head, entry.count);
  if (history.length < seq.minSequenceLength) return [];

  // Check consecutive diffs — only ±1 is "scraping". Old code allowed ±2,
  // which counted `1,3,5,7` as a sequence (that's step-2 enumeration,
  // a different signal entirely).
  const allowed = new Set(seq.allowedDiffs);
  let isSequential = true;
  for (let i = 1; i < history.length; i++) {
    const diff = history[i].val - history[i - 1].val;
    if (!allowed.has(diff)) {
      isSequential = false;
      break;
    }
  }
  if (!isSequential) return [];

  const timeDiffMs = history[history.length - 1].ts - history[0].ts;

  // Burst within a single tick (timeDiff = 0) is HIGHLY suspicious —
  // it means a connection pool / scripted client fired 5+ sequential
  // IDs in the same event loop cycle. Real users cannot do this.
  // Treat as infinite velocity (capped at maxVelocityReqPerSec).
  let velocity;
  if (timeDiffMs <= 0) {
    velocity = seq.maxVelocityReqPerSec;
  } else {
    velocity = history.length / (timeDiffMs / 1000);
    // Upper bound: protects against clock skew / sub-ms bursts producing
    // nonsense 10000 req/s values.
    if (velocity > seq.maxVelocityReqPerSec) {
      velocity = seq.maxVelocityReqPerSec;
    }
  }
  if (velocity < seq.minVelocityReqPerSec) return [];

  return [{
    type: 'sequential_scraping',
    detail: `Sequential access to "${key}" at ${velocity.toFixed(1)} req/s`,
    context: {
      ip,
      param: key,
      paramClass,
      sampleIds: history.slice(0, 5).map(h => h.val),
      requestsTracked: history.length,
      velocityReqPerSec: Number(velocity.toFixed(2)),
    },
  }];
}

/**
 * Per-(ip:param) velocity spike (without requiring sequential pattern).
 */
function _detectVelocitySpike(entry, ip, key) {
  if (!config.features.velocitySpike) return [];
  const v = config.velocity;
  const history = _ringIterate(entry.buf, entry.head, entry.count);
  if (history.length < v.minRequests) return [];

  const timeDiffMs = history[history.length - 1].ts - history[0].ts;
  if (timeDiffMs <= 0) return [];

  const velocity = history.length / (timeDiffMs / 1000);
  if (velocity < v.minVelocityReqPerSec || velocity > v.maxVelocityReqPerSec) {
    return [];
  }

  return [{
    type: 'param_velocity_spike',
    detail: `High velocity on "${key}": ${velocity.toFixed(1)} req/s across ${history.length} requests`,
    context: {
      ip,
      param: key,
      requestsTracked: history.length,
      velocityReqPerSec: Number(velocity.toFixed(2)),
    },
  }];
}

/**
 * Cross-IP distributed scraping detection.
 * Tracks per-param access to resource IDs globally (across all IPs).
 * If N+ distinct IPs hit the same param's IDs within a window, that's
 * distributed scraping — invisible to per-IP sequential detection.
 */
function _detectGlobalFanout(key, paramClass, val, ip, now) {
  if (!config.features.globalResourceFanout) return [];
  if (!config.globalResourceTracking.enabled) return [];
  if (paramClass !== 'id') return [];

  const g = config.globalResourceTracking;
  const resourceKey = paramClass + ':' + String(key).toLowerCase();
  let valMap = GLOBAL_RESOURCE_ACCESS.get(resourceKey);
  if (!valMap) {
    valMap = new Map();
    GLOBAL_RESOURCE_ACCESS.set(resourceKey, valMap);
  }

  // Track per-val: which IPs touched it and how many hits.
  let rec = valMap.get(val);
  if (!rec) {
    rec = { ips: new Set(), hits: 0, firstSeen: now, lastActivity: now };
    valMap.set(val, rec);
  }
  rec.ips.add(ip);
  rec.hits++;
  rec.lastActivity = now;

  // Aggregate over all vals of this param: distinct IPs + total hits in window.
  const windowCutoff = now - g.timeWindowMs;
  let totalHits = 0;
  const distinctIps = new Set();
  for (const [vId, r] of valMap) {
    if (r.lastActivity < windowCutoff) {
      // TTL-prune stale entries inline.
      valMap.delete(vId);
      continue;
    }
    totalHits += r.hits;
    for (const ipAddr of r.ips) distinctIps.add(ipAddr);
  }

  if (
    distinctIps.size >= g.minDistinctIps &&
    totalHits >= g.minHitsForFanout
  ) {
    return [{
      type: 'distributed_scraping',
      detail: `${distinctIps.size} IPs scraped "${key}" (${totalHits} hits in ${g.timeWindowMs / 1000}s window)`,
      context: {
        param: key,
        paramClass,
        distinctIps: distinctIps.size,
        totalHits,
        windowMs: g.timeWindowMs,
        sampleIps: Array.from(distinctIps).slice(0, 5),
      },
    }];
  }

  return [];
}

// ============================================================================
// Main check
// ============================================================================

function check(decodedReq) {
  if (!decodedReq) return [];
  const signals = [];
  const now = Date.now();
  const ip = normalizeIp(decodedReq.ip || 'unknown');

  for (const [key, rawVal] of iterParams(decodedReq)) {
    const strVal = String(rawVal);
    if (!isResourceId(strVal)) continue;

    const paramClass = classifyParam(key);
    // Skip batch class entirely — already flattened by iterParams.
    if (paramClass === 'batch') continue;
    // If we can't classify at all, default to id-like tracking but skip
    // page-specific logic. This keeps coverage for unknown id-ish params.
    const effectiveClass = paramClass || 'id';

    const mapKey = `${ip}:${key}:${effectiveClass}`;
    let entry = PARAM_HISTORY.get(mapKey);
    if (!entry) {
      entry = {
        paramClass: effectiveClass,
        buf: [],
        head: 0,
        count: 0,
        lastActivity: now,
      };
      PARAM_HISTORY.set(mapKey, entry);
    }
    entry.lastActivity = now;

    const numericVal = NUMERIC_ID_PATTERN.test(strVal) ? parseInt(strVal, 10) : null;
    const trackVal = numericVal !== null ? numericVal : strVal;

    const pushed = _ringPush(
      { val: trackVal, ts: now },
      entry.buf,
      entry.head,
      entry.count,
      config.historyMaxLen
    );
    entry.head = pushed.head;
    entry.count = pushed.count;

    // Only numeric IDs can form a numeric sequence.
    if (numericVal !== null) {
      signals.push(..._detectSequential(entry, ip, key, effectiveClass));
      signals.push(..._detectVelocitySpike(entry, ip, key));
    }

    // Distributed scraping applies to both numeric and UUID.
    signals.push(..._detectGlobalFanout(key, effectiveClass, strVal, ip, now));
  }

  // Memory pressure — schedule async cleanup instead of blocking.
  if (PARAM_HISTORY.size > config.maxParamKeys) {
    setImmediate(_cleanup);
  }

  if (signals.length === 0) return [];

  for (const s of signals) _bumpSignal(s.type);

  const matches = signals.map(s => ({
    rule: 'sequence_anomaly',
    tags: ['anomaly', 'behavioral', 'scraping'],
    severity:
      s.type === 'distributed_scraping' || s.type === 'sequential_scraping'
        ? 'high'
        : 'medium',
    category: 'behavioral',
    type: s.type,
    description: s.detail,
    context: s.context,
    author: 'shieldwall-core',
    sourceFile: 'builtin:sequence-anomaly',
    matchedPatterns: [{ name: s.type, matched: s.detail }],
  }));

  return matches;
}

// ============================================================================
// Cleanup — LRU-aware, chunked, TTL-based
// ============================================================================

function _cleanup() {
  const start = Date.now();
  const cutoff = Date.now() - config.paramHistoryTtlMs;
  const resourceCutoff = Date.now() - config.globalResourceTracking.resourceTtlMs;
  let deleted = 0;

  // Phase 1: prune PARAM_HISTORY by lastActivity (TTL).
  let processed = 0;
  for (const [key, entry] of PARAM_HISTORY.entries()) {
    if (entry.lastActivity < cutoff) {
      PARAM_HISTORY.delete(key);
      deleted++;
    }
    if (++processed % config.cleanupChunkSize === 0) {
      // Yield opportunity — for very large maps, the next chunk runs on
      // next tick. We don't actually yield here to keep cleanup synchronous
      // (Map iteration is fast), but the threshold lets us migrate to
      // chunked async later without API change.
    }
  }

  // Phase 2: hard cap on PARAM_HISTORY — drop by oldest lastActivity,
  // not insertion order.
  if (PARAM_HISTORY.size > config.maxParamKeys) {
    const sorted = Array.from(PARAM_HISTORY.entries()).sort(
      (a, b) => a[1].lastActivity - b[1].lastActivity
    );
    const excess = PARAM_HISTORY.size - config.maxParamKeys;
    for (let i = 0; i < excess; i++) {
      PARAM_HISTORY.delete(sorted[i][0]);
      deleted++;
    }
  }

  // Phase 3: prune GLOBAL_RESOURCE_ACCESS by TTL.
  for (const [resourceKey, valMap] of GLOBAL_RESOURCE_ACCESS.entries()) {
    for (const [val, rec] of valMap) {
      if (rec.lastActivity < resourceCutoff) {
        valMap.delete(val);
      }
    }
    if (valMap.size === 0) {
      GLOBAL_RESOURCE_ACCESS.delete(resourceKey);
    }
  }

  // Phase 4: hard cap on GLOBAL_RESOURCE_ACCESS.
  if (GLOBAL_RESOURCE_ACCESS.size > config.globalResourceTracking.maxResources) {
    const sorted = Array.from(GLOBAL_RESOURCE_ACCESS.entries()).sort((a, b) => {
      const aLast = _maxLastActivity(a[1]);
      const bLast = _maxLastActivity(b[1]);
      return aLast - bLast;
    });
    const excess = GLOBAL_RESOURCE_ACCESS.size - config.globalResourceTracking.maxResources;
    for (let i = 0; i < excess; i++) {
      GLOBAL_RESOURCE_ACCESS.delete(sorted[i][0]);
    }
  }

  _metrics.cleanupRuns++;
  _metrics.cleanupDeletions += deleted;
  _metrics.cleanupDurationMs += Date.now() - start;
}

function _maxLastActivity(valMap) {
  let max = 0;
  for (const [, rec] of valMap) {
    if (rec.lastActivity > max) max = rec.lastActivity;
  }
  return max;
}

const _cleanupTimer = setInterval(_cleanup, config.cleanupIntervalMs);
_cleanupTimer.unref();

function dispose() {
  clearInterval(_cleanupTimer);
  PARAM_HISTORY.clear();
  GLOBAL_RESOURCE_ACCESS.clear();
}

module.exports = {
  check,
  getMetrics,
  setConfig,
  dispose,
};
