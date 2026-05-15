'use strict';

/**
 * @file adaptive-baselines.js
 * @description Learns "normal" request profiles (param counts, names) per endpoint.
 *
 * FIXES APPLIED:
 * - Memory leak: knownParams capped at MAX_KNOWN_PARAMS, baselines map at MAX_BASELINES
 * - EWMA: avgParams uses exponential weighted moving average instead of cumulative mean
 * - LRU eviction: oldest baselines evicted when map is full
 * - Continuous learning: baselines keep adapting after threshold (with slower alpha)
 * - Stale cleanup: 30-minute inactivity eviction timer
 */

const MAX_BASELINES = 2000;
const MAX_KNOWN_PARAMS = 500;
const LEARNING_THRESHOLD = 50;
const EWMA_ALPHA_LEARN = 0.1;
const EWMA_ALPHA_DETECT = 0.01;

const BASELINES = new Map();

function getBaseline(path) {
  if (BASELINES.has(path)) {
    const b = BASELINES.get(path);
    b.lastSeen = Date.now();
    // Move to end for LRU ordering
    BASELINES.delete(path);
    BASELINES.set(path, b);
    return b;
  }

  // LRU eviction when full
  if (BASELINES.size >= MAX_BASELINES) {
    const oldest = BASELINES.keys().next().value;
    BASELINES.delete(oldest);
  }

  const b = {
    count: 0,
    avgParams: 0,
    knownParams: new Map(),
    methods: new Set(),
    lastSeen: Date.now(),
  };
  BASELINES.set(path, b);
  return b;
}

function check(decodedReq) {
  const path = decodedReq.path || '/';
  const baseline = getBaseline(path);

  // body may be a string after engine.js normalization — extract keys only if object
  const bodyObj = (typeof decodedReq.body === 'object' && decodedReq.body !== null)
    ? decodedReq.body : {};
  const currentParamsMap = { ...(decodedReq.query || {}), ...bodyObj };
  const currentParams = Object.keys(currentParamsMap);
  const currentCount = currentParams.length;

  const matches = [];
  const signals = [];

  // Always update baseline with EWMA
  baseline.count++;
  const alpha = baseline.count <= LEARNING_THRESHOLD ? EWMA_ALPHA_LEARN : EWMA_ALPHA_DETECT;
  baseline.avgParams = (baseline.count === 1)
    ? currentCount
    : baseline.avgParams * (1 - alpha) + currentCount * alpha;

  function getType(val) {
    if (/^-?\d+$/.test(val)) return 'int';
    if (/^-?\d+\.\d+$/.test(val)) return 'float';
    if (/^eyJ/.test(val)) return 'jwt';
    if (/^[a-f0-9]{32,}$/i.test(val)) return 'hash';
    return 'string';
  }

  // Track params with cap to prevent unbounded Map growth
  for (const p of currentParams) {
    if (!baseline.knownParams.has(p)) {
      if (baseline.knownParams.size < MAX_KNOWN_PARAMS) {
        baseline.knownParams.set(p, { types: new Set(), avgLen: 0 });
      }
    }
    const paramProfile = baseline.knownParams.get(p);
    if (paramProfile) {
      const valStr = String(currentParamsMap[p] || '');
      const currentType = getType(valStr);

      if (baseline.count >= LEARNING_THRESHOLD) {
        if (paramProfile.types.size > 0 && !paramProfile.types.has(currentType) && currentType === 'string') {
          signals.push({ type: 'param_type_anomaly', detail: `Param "${p}" changed type from ${[...paramProfile.types].join(',')} to string` });
        }
        if (valStr.length > paramProfile.avgLen * 5 + 20) {
          signals.push({ type: 'param_length_anomaly', detail: `Param "${p}" length ${valStr.length} vs avg ${Math.round(paramProfile.avgLen)}` });
        }
      }

      paramProfile.types.add(currentType);
      paramProfile.avgLen = paramProfile.avgLen === 0 ? valStr.length : paramProfile.avgLen * (1 - alpha) + valStr.length * alpha;
    }
  }

  baseline.methods.add(decodedReq.method);

  // Learning phase — no detection yet
  if (baseline.count < LEARNING_THRESHOLD) {
    return [];
  }

  // ── Detection phase ──

  // Param count anomaly (3x+ more than EWMA average, min floor of 5)
  if (currentCount > Math.max(baseline.avgParams * 3, 5)) {
    signals.push({
      type: 'param_count_anomaly',
      detail: `Expected ~${Math.round(baseline.avgParams)}, got ${currentCount}`,
    });
  }

  // Unknown parameters (mass assignment / fuzzing)
  const unknownParams = currentParams.filter(p => !baseline.knownParams.has(p));
  if (unknownParams.length > 3) {
    signals.push({
      type: 'unknown_params_anomaly',
      detail: `Detected ${unknownParams.length} unknown parameters: ${unknownParams.slice(0, 3).join(',')}`,
    });
  }

  // Unusual method
  if (!baseline.methods.has(decodedReq.method)) {
    signals.push({
      type: 'unusual_method_anomaly',
      detail: `Method ${decodedReq.method} never seen before on this path`,
    });
  }

  if (signals.length > 0) {
    matches.push({
      rule: 'adaptive_baselines',
      tags: ['anomaly', 'behavioral'],
      severity: signals.length > 1 ? 'high' : 'medium',
      category: 'behavioral',
      description: `Structural anomaly detected: ${signals.map(s => s.type).join(', ')}`,
      author: 'shieldwall-core',
      sourceFile: 'builtin:adaptive-baselines',
      matchedPatterns: signals.map(s => ({ name: s.type, matched: s.detail })),
    });
  }

  return matches;
}

// Periodic cleanup of stale baselines (30 min inactivity)
const _cleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [path, baseline] of BASELINES.entries()) {
    if (now - baseline.lastSeen > 1800000) {
      BASELINES.delete(path);
    }
  }
}, 60000);

// Prevent timer from keeping process alive
if (_cleanupInterval.unref) _cleanupInterval.unref();

module.exports = { check, getBaseline };
