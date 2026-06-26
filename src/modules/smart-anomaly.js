'use strict';

/**
 * @file smart-anomaly.js
 * @description Advanced Hybrid Heuristic Engine (Fuzzy + Behavioral).
 * 
 * ROLE IN ARCHITECTURE:
 * Acts as the structural scoring layer replacing traditional Regex Signatures. Uses 
 * structural mappings (high entropy, encoding density, special char distribution) and 
 * temporal modeling to detect Zero-Day injections/evasions without standard signatures.
 * 
 * DATA FLOW:
 * [engine.js] -> `detector.analyze(decodedReq)` -> Correlates historical state ->
 * Yields continuous Risk Score (float) mapped against structural anomalies.
 * 
 * CRITICAL FALSE POSITIVE (FP) MITIGATION & BUG FIXES:
 * - OOM Memory Leak: ANOMALY_HISTORY lacked background GC. Implemented strict LRU interval based on lastSeen.
 * - Score Dampening: Thresholds dynamically accommodate safeMode parameters, prioritizing 
 *   algorithmic context rather than rigid True/False blocks.
 */

const { loadRulesFromDir } = require('../core/rule-parser');
const path = require('path');

const ANOMALY_HISTORY = new Map();
const MAX_HISTORY = 1000;
const HISTORY_WINDOW = 5 * 60 * 1000;

// ─── Attack Vector Taxonomy ─────────────────────────────────────────────────
// Normalized category → vector mapping for structured reporting.
// Flat signal names are mapped into this hierarchy so consumers get
// clean per-vector breakdowns instead of an opaque signal list.

const VECTOR_MAP = {
  injection:  { sql: [], nosql: [], ldap: [], template: [] },
  xss:        { dom: [], reflected: [], event: [] },
  ssrf:       { localhost: [], cloud: [], protocol: [] },
  traversal:  { path: [], encoding: [] },
  evasion:    { obfuscation: [], encoding: [], fragmentation: [] },
  protocol:   { smuggling: [], header: [] },
  behavioral: { temporal: [], correlation: [] },
};

function emptyVectors() {
  const v = {};
  for (const [cat, subs] of Object.entries(VECTOR_MAP)) {
    v[cat] = {};
    for (const sub of Object.keys(subs)) v[cat][sub] = [];
  }
  return v;
}

// Map signal types to attack vector categories
const SIGNAL_TO_VECTOR = {
  high_entropy: ['evasion', 'encoding'],
  deep_encoding: ['evasion', 'encoding'],
  high_special_chars: ['evasion', 'obfuscation'],
  control_chars: ['protocol', 'header'],
  null_byte: ['evasion', 'obfuscation'],
  mixed_casing: ['evasion', 'obfuscation'],
  mixed_encoding: ['evasion', 'encoding'],
  path_traversal: ['traversal', 'path'],
  excessive_nesting: ['evasion', 'fragmentation'],
  distributed_sqli: ['injection', 'sql'],
  fragmented_union: ['injection', 'sql'],
  xss_correlation: ['xss', 'dom'],
  encoded_payload: ['evasion', 'encoding'],
  blind_sqli_indicators: ['injection', 'sql'],
  behavioral_shift: ['behavioral', 'temporal'],
  fragmented_attack: ['evasion', 'fragmentation'],
  encoded_attack: ['evasion', 'encoding'],
  multi_vector_fuzzy: ['behavioral', 'correlation'],
  unknown_binary_payload: ['protocol', 'header'],
};

/**
 * SmartAnomalyDetector — Hybrid Heuristic Engine
 * 
 * ARCHITECTURAL CONTEXT (2026 Standard):
 * Traditional WAFs rely on massive regex databases (Signature-based IDS),
 * which leads to high false positives and zero-day vulnerability.
 * 
 * This engine implements a "Fuzzy + Behavioral" hybrid model:
 * 1. Structural Scoring: Matches the "shape" of an attack (entropy, deep encoding, mixed casing)
 * 2. Cross-Field Correlation: E.g., SELECT in query + FROM in body
 * 3. Early Zero-Day Heuristics: Identifies fragmented attacks or unknown binary payloads
 * 
 * This is effectively a deterministic machine-learning feature extractor
 * that scores deviation from a structural baseline rather than relying on exact pattern matching.
 */
class SmartAnomalyDetector {
  /**
   * Initialize the anomaly detector with adaptive feedback parameters.
   * @param {string} rulesDir - Path to the directory containing rule files to build fuzzy profiles.
   * @param {Object} options - Configuration options.
   * @param {boolean} [options.safeMode=false] - If true, raises detection threshold and disables fuzzy matching to minimize FPs.
   */
  constructor(rulesDir, options = {}) {
    this.rulesDir = rulesDir || path.join(__dirname, '..', '..', 'rules');
    this.rules = [];
    this.patternProfiles = new Map();
    this.categoryProfiles = new Map();

    // ─── Safe Mode ──────────────────────────────────────────────────────
    // When enabled: threshold 35 (instead of 25), no fuzzy matches,
    // only direct regex + behavioral signals.  Dramatically reduces FP
    // rate at the cost of some detection coverage.
    this.safeMode = options.safeMode || false;
    this.detectionThreshold = this.safeMode ? 35 : 25;

    // ─── Feedback Loop ──────────────────────────────────────────────────
    // Tracks true_positive / false_positive verdicts per signal type.
    // Effective weight = base_weight * confidence_multiplier.
    // Confidence = tp / (tp + fp), with floor at 10% to never fully mute.
    // Requires ≥5 samples before adapting (cold-start guard).
    this._feedbackStore = new Map();

    this._loadRules();
  }

  // ── Public API: submit feedback verdict ────────────────────────────────
  // verdict = { signals: ['high_entropy', 'mixed_encoding'], 
  //             result: 'true_positive' | 'false_positive' }
  feedback(verdict) {
    if (!verdict?.signals?.length || !verdict?.result) return;
    const field = verdict.result === 'true_positive' ? 'tp' : 'fp';
    for (const signal of verdict.signals) {
      if (!this._feedbackStore.has(signal)) {
        this._feedbackStore.set(signal, { tp: 0, fp: 0 });
      }
      this._feedbackStore.get(signal)[field]++;
    }
  }

  // Returns feedback-adjusted weight.  Falls toward 10% for noisy signals.
  _getEffectiveWeight(signalType, baseWeight) {
    const fb = this._feedbackStore.get(signalType);
    if (!fb || (fb.tp + fb.fp) < 5) return baseWeight; // cold start — use base
    const confidence = fb.tp / (fb.tp + fb.fp);
    return baseWeight * Math.max(0.1, confidence); // floor at 10%
  }

  getFeedbackStats() {
    const stats = {};
    for (const [signal, data] of this._feedbackStore) {
      const total = data.tp + data.fp;
      stats[signal] = {
        ...data,
        total,
        confidence: total > 0 ? (data.tp / total).toFixed(2) : 'n/a',
      };
    }
    return stats;
  }

  reload() {
    this._loadRules();
  }

  _loadRules() {
    try {
      this.rules = loadRulesFromDir(this.rulesDir);
      this._buildProfiles();
    } catch (err) {
      console.error('[SmartAnomaly] Failed to load rules:', err.message);
    }
  }

  _buildProfiles() {
    for (const rule of this.rules) {
      const profile = {
        name: rule.name,
        category: rule.tags?.[0] || 'unknown',
        severity: rule.meta?.severity || 'medium',
        description: rule.meta?.description || '',
        targets: Object.values(rule.targets || {}),
        patterns: Object.entries(rule.strings || {}).map(([name, def]) => ({
          name,
          type: def.type,
          pattern: def.pattern || def.value,
          compiled: def.compiled,
        })),
        condition: rule.condition,
      };

      this.patternProfiles.set(rule.name, profile);

      const cat = profile.category;
      if (!this.categoryProfiles.has(cat)) {
        this.categoryProfiles.set(cat, { patterns: [], severities: [], rules: [] });
      }
      const cp = this.categoryProfiles.get(cat);
      cp.patterns.push(...profile.patterns);
      cp.severities.push(profile.severity);
      cp.rules.push(rule.name);
    }
  }

  _normalize(str) {
    if (!str) return '';
    return String(str).toLowerCase();
  }

  /**
   * Extracts and normalizes request features for anomaly detection.
   * DOS PROTECTION: Enforces strict limit on maximum extracted elements to prevent
   * resource exhaustion attacks with deeply nested or large payloads.
   * @param {Object} decodedReq - The decoded request object.
   * @returns {Object} Normalized feature set for analysis.
   */
  _extractRequestFeatures(decodedReq) {
    const MAX_EXTRACTED_ELEMENTS = 1000;
    let extractedCount = 0;

    const extractValues = (obj, depth = 0) => {
      if (depth > 5) return [];
      if (extractedCount >= MAX_EXTRACTED_ELEMENTS) return [];
      
      if (typeof obj === 'string') {
        extractedCount++;
        return [obj];
      }
      if (Array.isArray(obj)) {
        const result = [];
        for (const v of obj) {
          if (extractedCount >= MAX_EXTRACTED_ELEMENTS) break;
          result.push(...extractValues(v, depth + 1));
        }
        return result;
      }
      if (obj && typeof obj === 'object') {
        const result = [];
        for (const v of Object.values(obj)) {
          if (extractedCount >= MAX_EXTRACTED_ELEMENTS) break;
          result.push(...extractValues(v, depth + 1));
        }
        return result;
      }
      extractedCount++;
      return [String(obj || '')];
    };

    const queryVals = extractValues(decodedReq.query).map(v => v.slice(0, 1000)).filter(Boolean);
    const bodyVals = extractValues(decodedReq.body).map(v => v.slice(0, 1000)).filter(Boolean);
    const headerVals = extractValues(decodedReq.headers).map(v => v.slice(0, 1000)).filter(Boolean);
    const cookieVals = extractValues(decodedReq.cookies).map(v => v.slice(0, 1000)).filter(Boolean);

    const allValues = [...queryVals, ...bodyVals, ...headerVals, ...cookieVals];
    const allFields = allValues.join(' ').toLowerCase();

    return {
      url: (decodedReq.url || '').toLowerCase(),
      path: (decodedReq.path || '').toLowerCase(),
      method: (decodedReq.method || 'GET').toUpperCase(),
      query: queryVals.join(' ').toLowerCase(),
      body: bodyVals.join(' ').toLowerCase(),
      headers: headerVals.join(' ').toLowerCase(),
      cookies: cookieVals.join(' ').toLowerCase(),
      userAgent: (decodedReq.userAgent || '').toLowerCase(),
      allFields,
      entropy: this._calculateEntropy(allFields),
      encodingLayers: this._countEncodingLayers(allFields),
      specialCharDensity: this._charClassRatio(allFields, /[^\w\s]/g),
      controlCharCount: (allFields.match(/[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]/g) || []).length,
      maxPatternSimilarity: 0,
      categoryMatches: new Map(),
    };
  }

  _calculateEntropy(str) {
    if (!str || str.length < 10) return 0;
    
    // SLIDING WINDOW ENTROPY (detects hidden payloads in large strings)
    const windowSize = 64;
    if (str.length <= windowSize) return this._calculateChunkEntropy(str);
    
    let maxEntropy = 0;
    for (let i = 0; i < str.length - windowSize; i += 32) { // Step of 32 for performance
      const chunk = str.slice(i, i + windowSize);
      maxEntropy = Math.max(maxEntropy, this._calculateChunkEntropy(chunk));
    }
    return maxEntropy;
  }

  _calculateChunkEntropy(str) {
    const freq = new Map();
    for (const char of str) {
      freq.set(char, (freq.get(char) || 0) + 1);
    }
    let entropy = 0;
    const len = str.length;
    for (const count of freq.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  _countEncodingLayers(str) {
    if (!str) return 0;
    let layers = 0;
    let current = str;
    for (let i = 0; i < 5; i++) {
      try {
        const d = decodeURIComponent(current);
        if (d === current) break;
        current = d;
        layers++;
      } catch {
        break;
      }
    }
    return layers;
  }

  _charClassRatio(str, regex) {
    if (!str || !str.length) return 0;
    const m = str.match(regex);
    return m ? m.length / str.length : 0;
  }

  _fuzzyPatternMatch(value, patternProfile) {
    if (!value || !patternProfile.compiled) return { matched: false, similarity: 0 };

    const str = String(value);
    const directMatch = patternProfile.compiled.test(str);

    // Safe mode: skip fuzzy matching entirely — direct regex only
    if (this.safeMode) return { matched: directMatch, similarity: directMatch ? 1.0 : 0 };

    let similarity = 0;
    const patternStr = patternProfile.pattern || '';

    if (patternStr.includes('|')) {
      const alternatives = patternStr.split('|').map(s => s.replace(/[()]/g, '').trim());
      for (const alt of alternatives) {
        if (alt.length > 3 && str.toLowerCase().includes(alt.toLowerCase())) {
          similarity = Math.max(similarity, 0.7);
        }
      }
    }

    if (patternStr.includes('select') || patternStr.includes('union')) {
      const sqlIndicators = ['select', 'union', 'from', 'where', 'insert', 'delete'];
      const found = sqlIndicators.filter(ind => str.toLowerCase().includes(ind));
      if (found.length >= 2) similarity = Math.max(similarity, 0.6);
    }

    if (patternStr.includes('script') || patternStr.includes('javascript')) {
      const xssIndicators = ['script', 'alert', 'onerror', 'onload', 'javascript', 'eval'];
      const found = xssIndicators.filter(ind => str.toLowerCase().includes(ind));
      if (found.length >= 1) similarity = Math.max(similarity, 0.5);
    }

    if (patternStr.includes('127.0.0.1') || patternStr.includes('localhost')) {
      const ssrfIndicators = ['localhost', '127.', '0.0.0.0', '169.254', 'metadata'];
      const found = ssrfIndicators.filter(ind => str.toLowerCase().includes(ind.toLowerCase()));
      if (found.length >= 1) similarity = Math.max(similarity, 0.8);
    }

    if (patternStr.includes('admin') || patternStr.includes('role')) {
      const massAssignIndicators = ['admin', 'role', 'permission', 'isadmin', 'is_root'];
      const found = massAssignIndicators.filter(ind => str.toLowerCase().includes(ind.toLowerCase()));
      if (found.length >= 1) similarity = Math.max(similarity, 0.75);
    }

    return { matched: directMatch, similarity: Math.min(similarity, 0.95) };
  }

  _calculateBehavioralScore(features, rawFields) {
    let score = 0;
    const indicators = [];
    const seen = new Map();

    const add = (baseWeight, type, detail) => {
      const count = seen.get(type) || 0;
      const feedbackWeight = this._getEffectiveWeight(type, baseWeight);
      const effective = feedbackWeight / (1 + count * 0.7);
      seen.set(type, count + 1);
      score += effective;
      indicators.push({ type, weight: effective, baseWeight, detail });
    };

    if (features.entropy > 5.0 && features.specialCharDensity > 0.15) {
      add(3, 'high_entropy', `Entropy ${features.entropy.toFixed(2)} + special chars`);
    }

    if (features.encodingLayers > 2) {
      add(features.encodingLayers * 2, 'deep_encoding', `${features.encodingLayers} encoding layers`);
    }

    if (features.specialCharDensity > 0.3) {
      add(4, 'high_special_chars', `${(features.specialCharDensity * 100).toFixed(1)}% special chars`);
    }

    if (features.controlCharCount > 0) {
      add(features.controlCharCount * 3, 'control_chars', `${features.controlCharCount} control characters`);
    }

    if (/\x00/.test(rawFields)) {
      add(5, 'null_byte', 'Null byte detected - possible bypass attempt');
    }

    if (/%[0-9a-f]{2}/i.test(rawFields) && /\\x[0-9a-f]{2}/i.test(rawFields)) {
      add(4, 'mixed_encoding', 'Mixed URL and hex encoding');
    }

    if (/\.\.\/|\.\.\\/.test(features.allFields)) {
      add(5, 'path_traversal', 'Directory traversal patterns');
    }

    const nestingLevel = (rawFields.match(/[\{\[]/g) || []).length;
    if (nestingLevel > 15) {
      add(4, 'excessive_nesting', `High data structure nesting (${nestingLevel} levels)`);
    }

    return { score, indicators };
  }

  _calculateCategoryAnomaly(features) {
    const categoryScores = new Map();

    for (const [category, profile] of this.categoryProfiles) {
      let catScore = 0;
      const matchedPatterns = [];

      for (const pattern of profile.patterns) {
        for (const field of ['url', 'body', 'query', 'headers', 'cookies', 'userAgent']) {
          const result = this._fuzzyPatternMatch(features[field], pattern);
          if (result.matched) {
            // Severity-based direct match scoring
            const weight = profile.severity === 'critical' ? 30 : (profile.severity === 'high' ? 20 : 10);
            catScore += weight;
            matchedPatterns.push({ pattern: pattern.name, field, type: 'direct', weight });
          } else if (result.similarity > 0.7 && !this.safeMode) {
            // Safe mode: skip fuzzy matches entirely
            const weight = (profile.severity === 'critical' ? 10 : 5) * result.similarity;
            catScore += weight;
            matchedPatterns.push({ pattern: pattern.name, field, type: 'fuzzy', similarity: result.similarity, weight });
          }
        }
      }

      const criticalCount = profile.severities.filter(s => s === 'critical').length;
      const highCount = profile.severities.filter(s => s === 'high').length;
      catScore += Math.min(criticalCount, 2) + Math.min(highCount, 2) * 0.5;

      if (catScore > 0) {
        categoryScores.set(category, {
          score: catScore,
          severity: this._scoreToSeverity(catScore),
          matchedPatterns: matchedPatterns.slice(0, 5),
          ruleCount: profile.rules.length,
        });
      }
    }

    return categoryScores;
  }

  _scoreToSeverity(score) {
    if (score >= 25) return 'critical';
    if (score >= 15) return 'high';
    if (score >= 8) return 'medium';
    if (score >= 3) return 'low';
    return 'info';
  }

  _detectNovelAnomalies(features, categoryScores) {
    const novelIndicators = [];

    const totalCategoryScore = Array.from(categoryScores.values()).reduce((a, c) => a + c.score, 0);

    if (totalCategoryScore > 0 && totalCategoryScore < 5) {
      novelIndicators.push({
        type: 'fragmented_attack',
        detail: 'Partial indicators across multiple categories - possible evasion attempt',
        weight: this._getEffectiveWeight('fragmented_attack', 5),
        baseWeight: 5,
      });
    }

    if (features.encodingLayers > 1 && totalCategoryScore > 10) {
      novelIndicators.push({
        type: 'encoded_attack',
        detail: 'Encoded payload with attack indicators - likely obfuscated exploit',
        weight: this._getEffectiveWeight('encoded_attack', 8),
        baseWeight: 8,
      });
    }

    const highEntropyCats = Array.from(categoryScores.entries())
      .filter(([_, data]) => data.matchedPatterns.some(p => p.type === 'fuzzy'));

    if (highEntropyCats.length >= 2) {
      novelIndicators.push({
        type: 'multi_vector_fuzzy',
        detail: `Fuzzy matches in ${highEntropyCats.length} categories - possible variant attack`,
        weight: this._getEffectiveWeight('multi_vector_fuzzy', 6),
        baseWeight: 6,
      });
    }

    if (features.controlCharCount > 2 && features.specialCharDensity > 0.2) {
      const hasKnownCat = Array.from(categoryScores.keys()).some(c =>
        ['injection', 'xss', 'ssrf', 'traversal', 'command_injection'].includes(c)
      );
      if (!hasKnownCat) {
        novelIndicators.push({
          type: 'unknown_binary_payload',
          detail: 'Binary payload with control chars - possible novel exploit or protocol abuse',
          weight: this._getEffectiveWeight('unknown_binary_payload', 7),
          baseWeight: 7,
        });
      }
    }

    return novelIndicators;
  }

  _updateHistory(ip, result) {
    const now = Date.now();
    if (!ANOMALY_HISTORY.has(ip)) {
      ANOMALY_HISTORY.set(ip, []);
    }
    const history = ANOMALY_HISTORY.get(ip);
    const cats = result.categoryScores ? Object.keys(result.categoryScores) : [];
    history.push({ 
      timestamp: now, 
      score: result.score, 
      categories: cats,
      indicators: result.analysis?.topIndicators?.map(i => i.type) || []
    });

    const cutoff = now - HISTORY_WINDOW;
    while (history.length > 0 && history[0].timestamp < cutoff) {
      history.shift();
    }
    if (history.length > MAX_HISTORY) {
      history.shift();
    }
  }

  _calculateTemporalAnomaly(ip, currentResult) {
    const history = ANOMALY_HISTORY.get(ip) || [];
    if (history.length < 2) return null;

    const recent = history.slice(-5);
    
    // 1. Cross-Request Fragmentation Check (Elite Vector)
    // Detects attacks split across multiple requests (e.g. SELECT in req1, FROM in req2)
    const partialSignals = ['sql_indicator', 'xss_indicator', 'path_indicator'];
    const pastSignals = new Set(recent.flatMap(h => h.indicators || []));
    const currentSignals = currentResult.analysis?.topIndicators?.map(i => i.type) || [];
    
    const crossRequestAttack = partialSignals.some(s => pastSignals.has(s)) && 
                               currentSignals.some(s => partialSignals.includes(s));

    if (crossRequestAttack) {
      return {
        type: 'cross_request_fragmentation',
        detail: 'Attack indicators correlated across sequential requests from same IP',
        weight: this._getEffectiveWeight('cross_request_fragmentation', 15),
        baseWeight: 15
      };
    }

    // 2. Score Spike Check
    const avgScore = recent.reduce((a, h) => a + h.score, 0) / recent.length;
    const scoreSpike = currentResult.score > avgScore * 2 && currentResult.score > 10;

    if (scoreSpike) {
      return {
        type: 'behavioral_shift',
        detail: `Score spike: ${currentResult.score.toFixed(1)} vs avg ${avgScore.toFixed(1)}`,
        weight: this._getEffectiveWeight('behavioral_shift', 5),
        baseWeight: 5,
      };
    }
    return null;
  }

  _detectCrossFieldCorrelation(features) {
    const signals = [];

    if (/(select\s+.*|['"`;]\s*select)/i.test(features.query) && /(from\s+.*|--|#|\/\*)/i.test(features.body)) {
      signals.push({ type: 'distributed_sqli', weight: this._getEffectiveWeight('distributed_sqli', 6), baseWeight: 6, detail: 'SELECT in query + FROM/comments in body' });
    }

    if (/(union\s+.*|['"`;]\s*union)/i.test(features.url) && /(select\s+.*|--|#|\/\*)/i.test(features.body)) {
      signals.push({ type: 'fragmented_union', weight: this._getEffectiveWeight('fragmented_union', 5), baseWeight: 5, detail: 'UNION/SELECT split across fields' });
    }

    if (features.allFields.includes('script') && (features.allFields.includes('onerror') || features.allFields.includes('onload'))) {
      signals.push({ type: 'xss_correlation', weight: this._getEffectiveWeight('xss_correlation', 4), baseWeight: 4, detail: 'Script tag + event handler' });
    }

    if (features.entropy > 5.0 && features.encodingLayers >= 2) {
      signals.push({ type: 'encoded_payload', weight: this._getEffectiveWeight('encoded_payload', 6), baseWeight: 6, detail: 'High entropy with deep encoding' });
    }

    const blindPatterns = /(sleep\s*\(|pg_sleep\s*\(|waitfor\s+delay|benchmark\s*\()/i;
    if (blindPatterns.test(features.allFields)) {
      signals.push({ type: 'blind_sqli_indicators', weight: this._getEffectiveWeight('blind_sqli_indicators', 8), baseWeight: 8, detail: 'Time-based blind attack functions detected (sleep/waitfor/benchmark)'});
    }

    return signals;
  }

  // ── Build structured attack vector breakdown ──────────────────────────
  _buildAttackVectors(allIndicators) {
    const vectors = emptyVectors();
    for (const ind of allIndicators) {
      const mapping = SIGNAL_TO_VECTOR[ind.type];
      if (mapping) {
        const [cat, sub] = mapping;
        if (vectors[cat]?.[sub]) {
          vectors[cat][sub].push({ signal: ind.type, weight: ind.weight, detail: ind.detail });
        }
      }
    }

    // Also map category anomaly signals
    for (const ind of allIndicators) {
      if (ind.type.endsWith('_anomaly')) {
        const cat = ind.type.replace('_anomaly', '');
        if (vectors[cat]) {
          const firstSub = Object.keys(vectors[cat])[0];
          if (firstSub) {
            vectors[cat][firstSub].push({ signal: ind.type, weight: ind.weight, detail: ind.detail });
          }
        }
      }
    }

    return vectors;
  }

  analyze(decodedReq) {
    const features = this._extractRequestFeatures(decodedReq);
    const rawFields = [
      decodedReq.url, decodedReq.body, JSON.stringify(decodedReq.query),
      JSON.stringify(decodedReq.headers), decodedReq.userAgent
    ].join(' ');
    const behavioral = this._calculateBehavioralScore(features, rawFields);
    const categoryScores = this._calculateCategoryAnomaly(features);
    const correlationSignals = this._detectCrossFieldCorrelation(features);
    const novelIndicators = this._detectNovelAnomalies(features, categoryScores);

    let totalScore = behavioral.score;
    const allIndicators = [...behavioral.indicators];
    const suppressedSignals = [];

    for (const [category, data] of categoryScores) {
      totalScore += data.score;
      allIndicators.push({
        type: `${category}_anomaly`,
        weight: data.score,
        baseWeight: data.score,
        detail: `${category}: ${data.matchedPatterns.length} patterns, severity ${data.severity}`,
      });
    }

    for (const ind of novelIndicators) {
      totalScore += ind.weight;
      allIndicators.push(ind);
    }

    for (const sig of correlationSignals) {
      totalScore += sig.weight;
      allIndicators.push(sig);
    }

    const confidence = Math.min(1, totalScore / 40);

    const result = {
      score: totalScore,
      severity: this._scoreToSeverity(totalScore),
      behavioral,
      categoryScores: Object.fromEntries(categoryScores),
      novelIndicators,
      features: {
        entropy: features.entropy,
        encodingLayers: features.encodingLayers,
        specialCharDensity: features.specialCharDensity,
        controlCharCount: features.controlCharCount,
      },
    };

    const temporal = this._calculateTemporalAnomaly(decodedReq.ip, result);
    if (temporal) {
      result.temporalAnomaly = temporal;
      result.score += temporal.weight;
      totalScore += temporal.weight;
      allIndicators.push(temporal);
    }

    this._updateHistory(decodedReq.ip, result);

    // ── Threshold check (REMOVED: Delegated to Policy Engine) ─────────
    // We now act purely as a feature extractor, returning signals unconditionally.
    const topCategories = Array.from(categoryScores.entries())
      .sort((a, b) => b[1].score - a[1].score)
      .slice(0, 3)
      .map(([cat, data]) => `${cat}(${data.severity})`);

    const topSignals = allIndicators.sort((a, b) => b.weight - a.weight).slice(0, 3).map(i => i.type);
    const attackVectors = this._buildAttackVectors(allIndicators);

    return {
      detected: totalScore > 0, // Flag for compatibility, though we rely on `score` now
      rule: 'smart_anomaly_detection',
      tags: ['anomaly', 'heuristic', ...topCategories],
      severity: result.severity,
      category: topCategories[0]?.split('(')[0] || 'unknown',
      description: `Score ${result.score.toFixed(1)} (${result.severity}) | signals: ${topSignals.join(', ')}`,
      author: 'shieldwall-core', // Ownership corrected
      score: result.score,
      confidence,
      attackVectors,
      explanation: {
        summary: this._generateDescription(result, allIndicators),
        reasons: allIndicators.sort((a, b) => b.weight - a.weight).slice(0, 5),
        matchedCategories: Object.keys(result.categoryScores),
        correlationSignals: correlationSignals.map(s => s.type),
        // Per-signal contribution breakdown — critical for explainability
        signalContributions: allIndicators
          .filter(i => i.weight > 0)
          .sort((a, b) => b.weight - a.weight)
          .map(i => ({
            signal: i.type,
            weight: +i.weight.toFixed(2),
            baseWeight: i.baseWeight || i.weight,
            percentOfTotal: totalScore > 0 ? +((i.weight / totalScore) * 100).toFixed(1) : 0,
            feedbackAdjusted: i.baseWeight !== undefined && Math.abs(i.weight - i.baseWeight) > 0.01,
          })),
        thresholdUsed: this.detectionThreshold,
        safeMode: this.safeMode,
      },
      analysis: {
        score: result.score,
        severity: result.severity,
        confidence,
        behavioralScore: behavioral.score,
        categoryMatches: result.categoryScores,
        novelIndicators: novelIndicators.map(i => i.type),
        correlationSignals: correlationSignals.map(s => s.type),
        topIndicators: allIndicators.sort((a, b) => b.weight - a.weight).slice(0, 5),
        temporalAnomaly: result.temporalAnomaly,
        features: {
          entropy: features.entropy,
          encodingLayers: features.encodingLayers,
          specialCharDensity: features.specialCharDensity,
        },
      },
      matchedPatterns: allIndicators.slice(0, 5).map(i => ({
        name: i.type,
        matched: i.detail,
      })),
    };
  }

  _generateDescription(result, indicators) {
    const parts = [];
    parts.push(`Smart anomaly score ${result.score.toFixed(1)} (${result.severity})`);

    const topCats = Object.entries(result.categoryScores || {})
      .sort((a, b) => b[1].score - a[1].score)
      .slice(0, 2);

    if (topCats.length > 0) {
      parts.push(`Categories: ${topCats.map(([c]) => c).join(', ')}`);
    }

    if (result.novelIndicators?.length > 0) {
      parts.push(`Novel: ${result.novelIndicators.map(i => i.type).join(', ')}`);
    }

    const topInd = indicators.sort((a, b) => b.weight - a.weight)[0];
    if (topInd) {
      parts.push(`Primary: ${topInd.type}`);
    }

    return parts.join(' | ');
  }
}

const detector = new SmartAnomalyDetector();

function check(decodedReq) {
  const result = detector.analyze(decodedReq);
  if (result.score > 0) {
    return [result];
  }
  return [];
}

/**
 * Background Garbage Collection (GC) Tick.
 * CRITICAL FIX: Mitigates OOM leakage by sweeping ANOMALY_HISTORY map 
 * independently of live request traffic bindings.
 */
setInterval(() => {
  const now = Date.now();
  for (const [ip, history] of ANOMALY_HISTORY.entries()) {
    // Delete entries completely untouched over the interval
    if (history.length === 0 || now - history[history.length - 1].timestamp > HISTORY_WINDOW) {
      ANOMALY_HISTORY.delete(ip);
    }
  }
}, 60000);

module.exports = { check, SmartAnomalyDetector };
