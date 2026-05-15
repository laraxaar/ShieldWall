'use strict';

/**
 * @file sequence-anomaly.js
 * @description Stateful sequence and scraping detector.
 */

const PARAM_HISTORY = new Map();

function check(decodedReq) {
  const signals = [];
  const bodyObj = (typeof decodedReq.body === 'object' && decodedReq.body !== null) ? decodedReq.body : {};
  const allParams = { ...(decodedReq.query || {}), ...bodyObj };
  const ip = decodedReq.ip || 'unknown';

  for (const [key, val] of Object.entries(allParams)) {
    if (!/^\d+$/.test(String(val))) continue;

    const mapKey = `${ip}:${key}`;
    if (!PARAM_HISTORY.has(mapKey)) PARAM_HISTORY.set(mapKey, []);
    const history = PARAM_HISTORY.get(mapKey);
    
    history.push({ val: parseInt(val, 10), ts: Date.now() });

    if (history.length > 10) history.shift();

    if (history.length >= 5) {
      let isSequential = true;
      for (let i = 1; i < history.length; i++) {
        const diff = history[i].val - history[i - 1].val;
        if (diff !== 1 && diff !== -1 && diff !== 2 && diff !== -2) {
          isSequential = false;
          break;
        }
      }

      const timeDiff = history[history.length - 1].ts - history[0].ts;
      if (timeDiff > 0) {
        const velocity = history.length / (timeDiff / 1000);
        if (isSequential && velocity > 2) {
          signals.push({ type: 'sequential_scraping', detail: `Sequential access to param "${key}" at ${velocity.toFixed(1)} req/s` });
        }
      }
    }
  }

  // Cleanup map to prevent memory leaks (could use interval like baselines)
  if (PARAM_HISTORY.size > 10000) {
    const oldest = PARAM_HISTORY.keys().next().value;
    PARAM_HISTORY.delete(oldest);
  }

  const matches = [];
  if (signals.length > 0) {
    matches.push({
      rule: 'sequence_anomaly',
      tags: ['anomaly', 'behavioral', 'scraping'],
      severity: 'high',
      category: 'behavioral',
      description: `Stateful behavioral anomaly: ${signals.map(s => s.type).join(', ')}`,
      author: 'shieldwall-core',
      sourceFile: 'builtin:sequence-anomaly',
      matchedPatterns: signals.map(s => ({ name: s.type, matched: s.detail })),
    });
  }

  return matches;
}

module.exports = { check };
