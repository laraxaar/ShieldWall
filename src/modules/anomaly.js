'use strict';

/**
 * @file anomaly.js
 * @description Core Heuristic Anomaly Engine (Character & Distribution Analysis).
 * 
 * ROLE IN ARCHITECTURE:
 * Analyzes the "texture" of the request payload (entropy, nesting, special char density)
 * to catch unknown (Zero-Day) exploits before signatures are even written.
 * 
 * DATA FLOW:
 * [engine.js] passes `decodedReq` -> `analyze()` runs character class tests -> 
 * Updates EWMA baselines -> Yields signal scores mapped to threat categories.
 * 
 * CRITICAL FALSE POSITIVE (FP) MITIGATION:
 * - Safe Mode Baselines: Updates statistical profiles only on clean traffic.
 * - Suppress Pattern List: Whitelists known noisy structures (JWTs, GraphQL Introspection).
 * - Ops Budget: Limits regex execution depth to prevent ReDoS on massive inputs.
 */

const crypto = require('crypto');

const SCORE_THRESHOLD = 15;
const CRITICAL_THRESHOLD = SCORE_THRESHOLD * 2; // Dynamic based on SCORE_THRESHOLD

const WEIGHTS = {
  encodingLayers: 4,
  unusualCharDensity: 3,
  longParameter: 2,
  nestedParentheses: 3,
  controlCharacters: 5,
  mixedEncoding: 4,
  reservedKeywords: 2,
  stringTerminators: 3,
  commentSyntax: 3,
  abnormalMethod: 5,
  emptyUserAgent: 2,
  pathDepth: 2,
  repeatingPatterns: 3,
  highEntropy: 4,
  parameterPollution: 5,
  rawByteInjection: 6,
  payloadInflation: 3,
  nakedRequest: 3,
  headerIntegrity: 2,
  emptyBody: 2,
  paddingEvasion: 4,
  fragmentedWords: 5,
  executablePayload: 6,
  evasion: 5,
  criticalExploit: 8,
  templateInjection: 5,
  blindAnomaly: 4,
  code_execution_ratio: 5,
  linguistic_anomaly: 4,
  local_entropy_spike: 4,
  protocol_smuggling: 8,
  race_condition: 8,
  slow_bola_enumeration: 8,
  graphql_complexity_abuse: 5,
  novel_request_shape: 8,
};

const SIGNAL_GROUPS = {
  multi_layer_encoding: 'encoding',
  mixed_encoding:       'encoding',
  high_entropy:         'encoding',

  unusual_chars:        'structural',
  control_chars:        'structural',
  deep_nesting:         'structural',
  string_terminators:   'structural',
  comment_syntax:       'structural',
  padding_evasion:      'structural',
  fragmented_words:     'structural',
  executable_payload:   'structural',
  repeating_patterns:   'structural',
  raw_bytes:            'structural',
  oversized_param:      'structural',

  abnormal_method:      'behavioral',
  no_user_agent:        'behavioral',
  deep_path:            'behavioral',
  parameter_pollution:  'behavioral',
  payload_inflation:    'behavioral',
  naked_request:        'behavioral',
  header_integrity:     'behavioral',
  empty_json_body:      'behavioral',
  keywords:             'behavioral',

  invisible_chars:      'evasion',
  json_structure_anomaly: 'structural',
  ssti_indicator:       'structural',
  param_entropy_anomaly: 'encoding',
  obfuscated_payload:   'behavioral',
  structural_injection: 'structural',
  blind_time_anomaly:   'behavioral',
  code_execution_ratio: 'structural',
  linguistic_anomaly:   'structural',
  local_entropy_spike:  'structural',
  protocol_smuggling:   'structural',
  race_condition:       'behavioral',
  slow_bola_enumeration:'behavioral',
  graphql_complexity_abuse: 'structural',
  novel_request_shape:  'behavioral',
};

const SAFE_PATTERNS = [
  { test: (v) => /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v), suppress: ['high_entropy'] },
  { test: (v) => /\b__schema\b|\bintrospection\b|\b__type\b/i.test(v), suppress: ['keywords'] },
  { test: (v) => /^[A-Za-z0-9+/]{40,}={0,2}$/.test(v), suppress: ['high_entropy'], condition: (v) => v.length < 500 },
  { test: (v) => /^[a-f0-9]{32,64}$/i.test(v), suppress: ['high_entropy'] },
  { test: (v) => /^\/api\/v\d+\//i.test(v), suppress: ['deep_path'] },
];

function detectSafePatterns(candidates) {
  const suppressed = new Set();
  for (const val of candidates) {
    if (!val) continue;
    for (const sp of SAFE_PATTERNS) {
      if (sp.test(val) && (!sp.condition || sp.condition(val))) {
        for (const s of sp.suppress) suppressed.add(s);
      }
    }
  }
  return suppressed;
}

const MAX_REGEX_INPUT = 5000;
const MAX_ANALYSIS_SIZE = 10000;

function charClassRatio(str, regex) {
  if (!str || !str.length) return 0;
  const capped = str.length > MAX_REGEX_INPUT ? str.slice(0, MAX_REGEX_INPUT) : str;
  const m = capped.match(regex);
  return m ? m.length / capped.length : 0;
}

function detectMixedEncoding(str) {
  if (!str) return 0;
  let n = 0;
  const capped = str.slice(0, MAX_REGEX_INPUT);
  if (/%[0-9A-Fa-f]{2}/.test(capped)) n++;
  if (/&#(x[0-9A-Fa-f]+|\d+);?/.test(capped)) n++;
  if (/\\u[0-9A-Fa-f]{4}/.test(capped)) n++;
  if (/\\x[0-9A-Fa-f]{2}/.test(capped)) n++;
  return n;
}

function countEncodingLayers(str) {
  if (!str) return 0;
  let layers = 0, current = str;
  for (let i = 0; i < 5; i++) {
    try {
      const d = decodeURIComponent(current);
      if (d === current) break;
      current = d.slice(0, MAX_REGEX_INPUT); 
      layers++;
    } catch { break; }
  }
  return layers;
}

function nestingDepth(str) {
  if (!str) return 0;
  let max = 0, depth = 0;
  for (const ch of str) {
    if ('([{'.includes(ch)) { depth++; if (depth > max) max = depth; }
    else if (')]}'.includes(ch)) depth = Math.max(0, depth - 1);
  }
  return max;
}

function repeatingRatio(str) {
  if (!str || str.length < 8) return 0;
  const capped = str.length > MAX_REGEX_INPUT ? str.slice(0, MAX_REGEX_INPUT) : str;
  const runs = capped.match(/(.)\1{4,}|(\.\.\/){3,}|(\.\.\\){3,}/g);
  if (!runs) return 0;
  return runs.reduce((a, r) => a + r.length, 0) / capped.length;
}

const SOFT_KEYWORDS_PATTERN = '\\b(select|union|insert|update|delete|drop|alter|exec|eval|system|passthru|shell_exec|require|include)\\b';

function calculateEntropy(str) {
  if (!str || str.length < 10) return 0;
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

function detectParameterPollution(decodedReq) {
  const indicators = [];
  const query = decodedReq.query || {};
  const body = decodedReq.body || {};

  for (const [key, val] of Object.entries(query)) {
    if (Array.isArray(val)) indicators.push(`query:${key}(${val.length}x)`);
  }

  if (typeof body === 'object' && body !== null) {
    for (const [key, val] of Object.entries(body)) {
      if (Array.isArray(val)) indicators.push(`body:${key}(${val.length}x)`);
    }
  }

  const rawUrl = (decodedReq.rawUrl || '').slice(0, MAX_REGEX_INPUT);
  if (rawUrl && rawUrl.includes('?')) {
    const qs = rawUrl.split('?')[1];
    if (qs && qs.includes('&')) {
      const parts = qs.split('&');
      const keys = new Map();
      for (const part of parts) {
        if (!part) continue;
        const eqIdx = part.indexOf('=');
        const key = eqIdx > -1 ? part.substring(0, eqIdx) : part;
        const count = (keys.get(key) || 0) + 1;
        keys.set(key, count);
        if (count === 2) indicators.push(`raw:${key}`);
      }
    }
  }

  return indicators;
}

function detectRawBytes(str) {
  if (!str) return [];
  const found = [];
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if ((code >= 0 && code <= 8) || (code >= 14 && code <= 31) || code === 127) {
      found.push(`0x${code.toString(16).padStart(2, '0')}@pos${i}`);
    }
  }
  return found;
}

function detectPayloadInflation(decodedReq) {
  const body = decodedReq.body;
  if (!body || typeof body !== 'object') return null;
  const keys = Object.keys(body);
  if (keys.length === 0) return null;
  const bodyStr = JSON.stringify(body);
  const avgSize = bodyStr.length / keys.length;
  if (avgSize > 100000 && keys.length <= 3) {
    return { ratio: avgSize, keys: keys.length, total: bodyStr.length };
  }
  return null;
}

function detectNakedRequest(headers, userAgent) {
  const indicators = [];
  if (!headers['accept'] && !headers['Accept']) indicators.push('missing_accept');
  if (!headers['accept-language'] && !headers['Accept-Language']) indicators.push('missing_accept_language');
  if (!headers['accept-encoding'] && !headers['Accept-Encoding']) indicators.push('missing_accept_encoding');
  const ua = userAgent || '';
  if (/^python-requests|^axios|^node-fetch|^http\.client|^Go-http/i.test(ua)) indicators.push('automation_ua');
  return indicators;
}

function detectRichHeaderAnomaly(method, headers, rawHeaders, userAgent) {
  const indicators = [];
  const isBrowser = /Chrome|Firefox|Safari|Edge/i.test(userAgent || '');

  const isHttp2 = headers['x-alpn'] === 'h2' || headers['x-h2-fingerprint'] != null;

  if (rawHeaders && rawHeaders.length > 0 && !isHttp2) {
    const keys = [];
    for (let i = 0; i < rawHeaders.length; i += 2) keys.push(rawHeaders[i]);

    const coreHeadersToCheck = ['host', 'user-agent', 'connection', 'accept', 'referer', 'origin'];
    let lowercaseAnomalies = 0;
    for (const key of keys) {
      if (coreHeadersToCheck.includes(key.toLowerCase()) && /^[a-z\-]+$/.test(key)) {
        lowercaseAnomalies++;
      }
    }
    
    if (lowercaseAnomalies >= 2 && isBrowser) {
      indicators.push('impersonation_casing_anomaly');
    }

    if (keys.length > 0 && keys[0].toLowerCase() !== 'host') indicators.push('abnormal_header_order_host');
    if (keys.includes('Connection') && keys.indexOf('Connection') > keys.length - 2) indicators.push('abnormal_header_order_connection');
  }

  const rareHeaders = ['x-scanner', 'x-http-method-override', 'acunetix-product', 'x-forwarded-host', 'x-req-id'];
  for (const h of rareHeaders) {
    if (headers[h]) indicators.push(`suspicious_header_${h}`);
  }

  if (isBrowser) {
    if (!headers['accept'] && !headers['Accept']) indicators.push('browser_no_accept');
    if (!headers['accept-language'] && !headers['Accept-Language']) indicators.push('browser_no_lang');
  }

  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const hasOrigin = headers['origin'] || headers['Origin'];
    const hasReferer = headers['referer'] || headers['Referer'];
    if (!hasOrigin && !hasReferer) indicators.push('post_no_origin');
  }

  return indicators;
}

function detectInvisibleChars(str) {
  if (!str) return 0;
  const matches = str.match(/[\u200b-\u200f\u2028-\u202f\ufeff]/g);
  return matches ? matches.length : 0;
}

function detectMalformedJsonKeys(decodedReq) {
  const body = decodedReq.body;
  if (!body || typeof body !== 'object') return [];
  const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
  const found = [];
  function traverse(obj, path = '', depth = 0) {
    if (depth > 10) return; // Prevent Stack Overflow
    for (const key in obj) {
      if (dangerousKeys.includes(key)) {
        found.push(`prototype_pollution:${path}${key}`);
      }
      if (typeof obj[key] === 'object' && obj[key] !== null) {
        traverse(obj[key], `${path}${key}.`, depth + 1);
      }
    }
  }
  traverse(body);
  return found;
}

function detectSSTI(str) {
  if (!str) return false;
  const capped = str.slice(0, MAX_REGEX_INPUT);
  return /(\{\{[^}]*\}\}|\$\{[^}]*\}|<%[^%]*%>|#\{[^}]*\})/.test(capped) || 
         /__(class|init|globals|mro|subclasses)__/.test(capped);
}

function detectEmptyBody(headers, body) {
  const contentType = headers['content-type'] || headers['Content-Type'] || '';
  if (contentType.includes('application/json')) {
    if (!body || (typeof body === 'string' && body.trim().length === 0) ||
        (typeof body === 'object' && Object.keys(body).length === 0)) {
      return true;
    }
  }
  return false;
}

function detectPaddingEvasion(str) {
  if (!str) return false;
  const capped = str.length > MAX_REGEX_INPUT ? str.slice(0, MAX_REGEX_INPUT) : str;
  return /\b(select|union|from|where|insert|delete|update|drop)\s{5,}/i.test(capped);
}

function detectFragmentedWords(str) {
  if (!str) return false;
  const capped = str.length > MAX_REGEX_INPUT ? str.slice(0, MAX_REGEX_INPUT) : str;
  const concatSyntax = /(['"]\w['"]\s*(\+|\|\|)\s*){3,}/i;
  const sqlConcat = /concat\(\s*['"]\w['"]\s*(,\s*['"]\w['"]\s*){3,}\)/i;
  const inlineChr = /(chr|char)\(\d{2,3}\)\s*(\|\||\+)\s*(chr|char)\(/i;
  return concatSyntax.test(capped) || sqlConcat.test(capped) || inlineChr.test(capped);
}

function detectExecutablePayload(str) {
  if (!str) return false;
  const capped = str.slice(0, MAX_REGEX_INPUT);
  return /(MZ[^\n]*\n|TVqQ[A-Za-z0-9+/=]{10,}|f0VMR[A-Za-z0-9+/=]{10,})/.test(capped);
}

class EwmaTracker {
  constructor(alpha = 0.05) {
    this.alpha = alpha;
    this.mean = 0;
    this.variance = 0;
    this.count = 0;
  }
  update(x) {
    this.count++;
    if (this.count === 1) {
      this.mean = x;
      this.variance = 0;
    } else {
      const diff = x - this.mean;
      this.mean += this.alpha * diff;
      this.variance = (1 - this.alpha) * (this.variance + this.alpha * diff * diff);
    }
  }
  get stdDev() { return Math.sqrt(this.variance); }
  getZScore(x) {
    if (this.count < 50 || this.stdDev === 0) return 0;
    return (x - this.mean) / this.stdDev;
  }
}

const CONCURRENCY_MAP = new Map();
const RESOURCE_HISTOGRAM = new Map();
const COMMON_BIGRAMS = new Set(['th','he','in','er','an','re','on','at','en','nd','ti','es','or','te','of','ed','is','it','al','ar','st','to','nt','ng','se','ha','as','ou','io','le','ve','co','me','de','hi','ri','ro','ic','ne','ea','ra','ce']);

function calculateCodeRatio(str) {
  if (!str || str.length < 15) return 0;
  const capped = str.slice(0, MAX_REGEX_INPUT);
  const operators = (capped.match(/[=<>!&|^\*%~]/g) || []).length;
  const operands = (capped.match(/[a-zA-Z0-9_]+/g) || []).length;
  if (operands === 0) return operators > 5 ? 1 : 0;
  return operators / operands; 
}

function detectHomoglyphs(str) {
  if (!str) return 0;
  // Ищем смешение латиницы и кириллицы в одном слове
  const matches = str.match(/[a-zа-яё]+/gi);
  if (!matches) return 0;
  let mixedCount = 0;
  for (const word of matches) {
    const hasLatin = /[a-z]/i.test(word);
    const hasCyrillic = /[а-яё]/i.test(word);
    if (hasLatin && hasCyrillic) mixedCount++;
  }
  return mixedCount;
}

function calculateNgramDeviation(str) {
  if (!str || str.length < 20) return 0;
  const lower = str.normalize('NFKC').toLowerCase().replace(/[^a-z]/g, ''); 
  if (lower.length < 20) return 0;
  let total = 0, valid = 0;
  for (let i = 0; i < lower.length - 1; i++) {
    total++;
    if (COMMON_BIGRAMS.has(lower.substring(i, i + 2))) valid++;
  }
  return 1 - (valid / total);
}

function detectLocalEntropySpike(str, windowSize = 32, step = 16) {
  if (!str || str.length < windowSize * 2) return false;
  let maxLocalSpecial = 0;
  for (let i = 0; i <= str.length - windowSize; i += step) {
    const chunk = str.slice(i, i + windowSize);
    const ratio = charClassRatio(chunk, /[^a-zA-Z0-9\s.,\-_@]/g);
    if (ratio > maxLocalSpecial) maxLocalSpecial = ratio;
  }
  return maxLocalSpecial > 0.40; 
}

function getParamType(val) {
  if (/^\d+$/.test(val)) return 'int';
  if (/^[0-9a-f]{8}-[0-9a-f]{4}/i.test(val)) return 'uuid';
  if (/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(val)) return 'email';
  return 'string';
}

function detectRequestSmuggling(decodedReq) {
  const headers = decodedReq.headers || {};
  const hasCL = headers['content-length'] !== undefined;
  const hasTE = headers['transfer-encoding'] !== undefined;
  const indicators = [];

  if (hasCL && hasTE) indicators.push('cl_te_conflict');

  if (hasTE) {
    const teVal = String(headers['transfer-encoding']).toLowerCase();
    if (teVal.includes('chunked') && (teVal.includes(',') || teVal.includes(';'))) {
      indicators.push('te_obfuscation');
    }
  }

  if (hasCL && String(headers['content-length']).includes(',')) {
    const lengths = String(headers['content-length']).split(',').map(s => s.trim());
    if (new Set(lengths).size > 1) indicators.push('double_cl_mismatch');
  }

  return indicators;
}

function checkRaceCondition(decodedReq) {
  const method = (decodedReq.method || '').toUpperCase();
  if (!['POST', 'PUT', 'PATCH'].includes(method)) return 0;
  const ip = decodedReq.ip || 'unknown';
  const path = decodedReq.path || '/';
  const key = `${ip}:${path}`;
  const now = Date.now();
  
  if (!CONCURRENCY_MAP.has(key)) CONCURRENCY_MAP.set(key, []);
  const attempts = CONCURRENCY_MAP.get(key);
  
  const recent = attempts.filter(t => now - t < 100);
  recent.push(now);
  CONCURRENCY_MAP.set(key, recent);

  if (CONCURRENCY_MAP.size > 10000) CONCURRENCY_MAP.delete(CONCURRENCY_MAP.keys().next().value);

  if (recent.length > 3) return recent.length;
  return 0;
}

function detectSlowBOLA(ip, paramName, paramValue) {
  if (!/^\d+$/.test(paramValue) && !/^[0-9a-f]{8}/i.test(paramValue)) return 0;
  const key = `${ip}:${paramName}`;
  const now = Date.now();
  const WINDOW = 3600000;
  
  if (!RESOURCE_HISTOGRAM.has(key)) RESOURCE_HISTOGRAM.set(key, []);
  const history = RESOURCE_HISTOGRAM.get(key);
  
  history.push({ id: paramValue, ts: now });
  const recent = history.filter(h => now - h.ts < WINDOW);
  RESOURCE_HISTOGRAM.set(key, recent);

  if (RESOURCE_HISTOGRAM.size > 10000) RESOURCE_HISTOGRAM.delete(RESOURCE_HISTOGRAM.keys().next().value);

  const uniqueIds = new Set(recent.map(h => h.id)).size;
  if (uniqueIds > 30 && uniqueIds > (recent.length * 0.8)) {
    return uniqueIds;
  }
  return 0;
}

function detectGraphQLAbuse(decodedReq) {
  const path = decodedReq.path || '';
  const isGQL = path.endsWith('/graphql') || path.endsWith('/gql');
  if (!isGQL || !decodedReq.body || typeof decodedReq.body !== 'object') return 0;

  const query = decodedReq.body.query || '';
  if (!query) return 0;

  let score = 0, maxDepth = 0, currentDepth = 0;
  for (const char of query) {
    if (char === '{') { currentDepth++; maxDepth = Math.max(maxDepth, currentDepth); }
    if (char === '}') currentDepth--;
  }
  if (maxDepth > 7) score += maxDepth * 2;

  const aliasCount = (query.match(/\w+\s*:\s*\w+\s*\(/g) || []).length;
  if (aliasCount > 5) score += aliasCount * 2;

  return score;
}

function detectHeaderCRLFInjection(decodedReq) {
  const headers = decodedReq.headers || {};
  for (const [key, val] of Object.entries(headers)) {
    if (typeof val === 'string' && /[\r\n]/.test(val)) {
      return true;
    }
  }
  return false;
}

function getRequestShape(decodedReq) {
  const method = decodedReq.method || 'GET';
  const path = decodedReq.path || '/';
  let shape = `${method}:${path}|`;
  
  const extractKeys = (obj, prefix = '') => {
    if (!obj || typeof obj !== 'object') return;
    for (const key of Object.keys(obj).sort()) {
      const val = obj[key];
      const type = Array.isArray(val) ? 'arr' : typeof val;
      shape += `${prefix}${key}:${type},`;
      if (type === 'object') extractKeys(val, `${prefix}${key}.`);
    }
  };
  
  extractKeys(decodedReq.query, 'q:');
  
  let bodyObj = decodedReq.body;
  if (typeof bodyObj === 'string') {
    try { bodyObj = JSON.parse(bodyObj); } catch(e) {}
  }
  if (typeof bodyObj === 'object' && bodyObj !== null) {
     extractKeys(bodyObj, 'b:');
  }
  
  return crypto.createHash('sha256').update(shape).digest('hex').substring(0, 12);
}

const STATS_MAP = new Map();
const MAX_BASELINES = 5000;

function getParamStats(pathStats, key) {
  if (!pathStats.paramProfiles.has(key)) {
    // Prevent OOM fuzzing
    if (pathStats.paramProfiles.size > 100) return { entropy: new EwmaTracker(), specialRatio: new EwmaTracker(), types: new Map() };
    pathStats.paramProfiles.set(key, {
      entropy: new EwmaTracker(),
      specialRatio: new EwmaTracker(),
      types: new Map()
    });
  }
  return pathStats.paramProfiles.get(key);
}

function getStats(path) {
  if (STATS_MAP.has(path)) {
    const s = STATS_MAP.get(path);
    s.lastSeen = Date.now();
    STATS_MAP.delete(path);
    STATS_MAP.set(path, s);
    return s;
  }
  if (STATS_MAP.size >= MAX_BASELINES) {
    const oldest = STATS_MAP.keys().next().value;
    STATS_MAP.delete(oldest);
  }
  const s = {
    entropy: new EwmaTracker(),
    specialRatio: new EwmaTracker(),
    lastSeen: Date.now(),
    paramProfiles: new Map(),
    shapeFrequency: new Map()
  };
  STATS_MAP.set(path, s);
  return s;
}

const _cleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [path, stats] of STATS_MAP.entries()) {
    if (now - stats.lastSeen > 1800000) {
      STATS_MAP.delete(path);
    }
  }
}, 60000);
if (_cleanupInterval.unref) _cleanupInterval.unref();

const _tempMapsCleanup = setInterval(() => {
  const now = Date.now();
  for (const [key, timestamps] of CONCURRENCY_MAP.entries()) {
    if (timestamps.length === 0 || now - timestamps[timestamps.length - 1] > 5000) {
      CONCURRENCY_MAP.delete(key);
    }
  }
  for (const [key, history] of RESOURCE_HISTOGRAM.entries()) {
    const recent = history.filter(h => now - h.ts < 3600000);
    if (recent.length === 0) {
      RESOURCE_HISTOGRAM.delete(key);
    } else {
      RESOURCE_HISTOGRAM.set(key, recent);
    }
  }
  for (const [key, data] of MUTATION_CACHE.entries()) {
    if (now - data.ts > 300000) {
      MUTATION_CACHE.delete(key);
    }
  }
}, 60000);
if (_tempMapsCleanup.unref) _tempMapsCleanup.unref();

function detectObfuscatedJNDI(str) {
  if (!str) return false;
  const capped = str.slice(0, MAX_REGEX_INPUT);
  const jndiPattern = /\$\{.*?(jndi|lower|upper|env|sys|java|date).*?:.*?\}/is;
  return jndiPattern.test(capped);
}

function analyze(decodedReq) {
  const path = decodedReq.path || '/';
  const method = (decodedReq.method || '').toUpperCase();

  // FAST PATH: Пропускаем статику и безопасные методы без тяжелых вычислений
  if (method === 'GET' && !decodedReq.query && /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2|ttf|mp4)$/i.test(path)) {
    return { score: 0, level: 'none', threshold: SCORE_THRESHOLD, factors: [], groupScores: { encoding: 0, structural: 0, behavioral: 0 }, description: 'Clean (Static Asset)', _path: path, _maxEntropy: 0, _maxSpecialRatio: 0, _paramEntropyUpdates: new Map(), _paramSpecialUpdates: new Map(), _paramTypeUpdates: new Map(), _shapeHash: null };
  }

  const factors = [];
  let score = 0;
  const groupScores = { encoding: 0, structural: 0, behavioral: 0 };
  const paramTypeUpdates = new Map();

  let opsBudget = 1000;
  const budgetMatch = (str, regex) => {
    if (opsBudget <= 0) return null;
    const m = str.match(regex);
    if (m) opsBudget -= m.length;
    return m;
  };

  const add = (weight, name, detail) => {
    score += weight;
    const group = SIGNAL_GROUPS[name] || 'structural';
    groupScores[group] = (groupScores[group] || 0) + weight;
    factors.push({ weight, name, detail, group });
  };

  const path = decodedReq.path || '/';
  const urlCapped = (decodedReq.url || '').slice(0, MAX_ANALYSIS_SIZE);
  
  // Safe body extraction to prevent JSON.stringify OOM DoS on massive bodies
  let bodyCapped = '';
  if (typeof decodedReq.body === 'string') {
    bodyCapped = decodedReq.body.slice(0, MAX_ANALYSIS_SIZE);
  } else if (typeof decodedReq.body === 'object' && decodedReq.body !== null) {
    let size = 0;
    const parts = [];
    for (const val of Object.values(decodedReq.body)) {
      const strVal = String(val);
      if (size + strVal.length > MAX_ANALYSIS_SIZE) {
        parts.push(strVal.slice(0, MAX_ANALYSIS_SIZE - size));
        break;
      }
      parts.push(strVal);
      size += strVal.length;
    }
    bodyCapped = parts.join(' ');
  }
  
  const queryVals = Object.values(decodedReq.query || {}).map(v => String(v).slice(0, 500));
  const cookieVals = Object.values(decodedReq.cookies || {}).map(v => String(v).slice(0, 500));
  
  const candidates = [urlCapped, bodyCapped, ...queryVals, ...cookieVals].filter(Boolean);
  const suppressed = detectSafePatterns(candidates);

  const allFields = candidates.join(' ');
  const contentType = (decodedReq.headers && decodedReq.headers['content-type']) ? decodedReq.headers['content-type'].toLowerCase() : '';
  if (contentType.includes('application/json') && bodyCapped.trim().startsWith('<')) {
    add(WEIGHTS.criticalExploit, 'content_type_mismatch', 'JSON Content-Type but XML/HTML payload structure detected');
  } else if (contentType.includes('application/xml') && bodyCapped.trim().startsWith('{')) {
    add(WEIGHTS.structural_injection, 'content_type_mismatch', 'XML Content-Type but JSON payload structure detected');
  }

  if (detectObfuscatedJNDI(allFields)) {
    add(WEIGHTS.criticalExploit, 'obfuscated_jndi', 'Obfuscated JNDI/Log4Shell pattern detected');
  }

  const encLayers = countEncodingLayers(decodedReq.rawUrl || '');
  if (encLayers >= 2) add(WEIGHTS.encodingLayers * encLayers, 'multi_layer_encoding', `${encLayers} encoding layers detected`);

  let maxMixedEnc = 0;
  for (const c of candidates) {
    maxMixedEnc = Math.max(maxMixedEnc, detectMixedEncoding(c));
  }
  if (maxMixedEnc >= 2) add(WEIGHTS.mixedEncoding * (maxMixedEnc - 1), 'mixed_encoding', `${maxMixedEnc} different encoding schemes in one request`);

  let maxSpecialRatio = 0;
  for (const c of candidates) {
    maxSpecialRatio = Math.max(maxSpecialRatio, charClassRatio(c, /[^a-zA-Z0-9\s.,\-_@]/g));
  }

  const stats = getStats(path);
  let specialZ = 0;
  
  // We calculate z-score, but we DO NOT update the tracker here. We update it in `check` if it's safe.
  if (candidates.some(c => c.length > 20)) {
    specialZ = stats.specialRatio.getZScore(maxSpecialRatio);
  }

  if (specialZ > 3) {
    add(WEIGHTS.unusualCharDensity * (specialZ > 5 ? 2 : 1), 'unusual_chars', `Mathematical Z-Score Anomaly: SpecChar z=${specialZ.toFixed(2)} (baseline mean=${stats.specialRatio.mean.toFixed(3)})`);
  } else if (maxSpecialRatio > 0.30) {
    add(WEIGHTS.unusualCharDensity * Math.ceil(maxSpecialRatio * 10), 'unusual_chars', `${(maxSpecialRatio * 100).toFixed(0)}% special characters`);
  }

  let totalCtrlChars = 0;
  for (const c of candidates) {
    totalCtrlChars += (budgetMatch(c, /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g) || []).length;
  }
  if (totalCtrlChars > 0) add(WEIGHTS.controlCharacters, 'control_chars', `${totalCtrlChars} control characters found`);

  let maxDepth = 0;
  for (const c of candidates) {
    maxDepth = Math.max(maxDepth, nestingDepth(c));
  }
  if (maxDepth >= 3) add(WEIGHTS.nestedParentheses, 'deep_nesting', `Nesting depth ${maxDepth}`);

  for (const val of queryVals) {
    if (val && val.length > 500) { add(WEIGHTS.longParameter, 'oversized_param', `${val.length} char parameter`); break; }
  }

  for (const c of candidates) {
    if (detectPaddingEvasion(c)) { add(WEIGHTS.paddingEvasion, 'padding_evasion', 'Suspicious whitespace padding evasion'); break; }
    if (detectFragmentedWords(c)) { add(WEIGHTS.fragmentedWords, 'fragmented_words', 'String concatenation / character evasion'); break; }
    if (detectExecutablePayload(c)) { add(WEIGHTS.executablePayload, 'executable_payload', 'Executable header detected'); break; }
  }

  let maxRepRatio = 0;
  for (const c of candidates) {
    maxRepRatio = Math.max(maxRepRatio, repeatingRatio(c));
  }
  if (maxRepRatio > 0.15) add(WEIGHTS.repeatingPatterns, 'repeating_patterns', `${(maxRepRatio * 100).toFixed(0)}% repetitive content`);

  let totalTerminators = 0;
  for (const c of candidates) {
    totalTerminators += (budgetMatch(c, /['`]/g) || []).length;
  }
  if (totalTerminators >= 4) add(WEIGHTS.stringTerminators, 'string_terminators', `${totalTerminators} quote characters`);

  let totalComments = 0;
  for (const c of candidates) {
    totalComments += (budgetMatch(c, /(--|\/\*|#|\/\/)/g) || []).length;
  }
  if (totalComments >= 2) add(WEIGHTS.commentSyntax, 'comment_syntax', `${totalComments} comment tokens`);

  if (!suppressed.has('keywords')) {
    let totalKeywords = 0;
    const kwRegex = new RegExp(SOFT_KEYWORDS_PATTERN, 'gi');
    for (const c of candidates) {
      totalKeywords += (budgetMatch(c, kwRegex) || []).length;
    }
    if (totalKeywords >= 3) add(WEIGHTS.reservedKeywords, 'keywords', `${totalKeywords} programming keywords`);
  }

  const method = (decodedReq.method || '').toUpperCase();
  const normalMethods = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);
  if (method && !normalMethods.has(method)) add(WEIGHTS.abnormalMethod, 'abnormal_method', `Non-standard method "${method}"`);

  if (!decodedReq.userAgent || decodedReq.userAgent.length < 5) add(WEIGHTS.emptyUserAgent, 'no_user_agent', 'Missing User-Agent');

  if (!suppressed.has('deep_path')) {
    const pathSegs = (decodedReq.path || '').split('/').filter(Boolean).length;
    if (pathSegs > 10) add(WEIGHTS.pathDepth, 'deep_path', `${pathSegs} path segments`);
  }

  let maxEntropy = 0;
  if (!suppressed.has('high_entropy')) {
    for (const c of candidates) {
      if (c.length > 50) {
        maxEntropy = Math.max(maxEntropy, calculateEntropy(c));
      }
    }
    if (maxEntropy > 0) {
      const entropyZ = stats.entropy.getZScore(maxEntropy);
      if (entropyZ > 3) {
        add(WEIGHTS.highEntropy * (entropyZ > 5 ? 2 : 1), 'high_entropy', `Mathematical Z-Score Anomaly: Entropy z=${entropyZ.toFixed(2)} (baseline mean=${stats.entropy.mean.toFixed(2)})`);
      } else if (maxEntropy > 5.5) {
        add(WEIGHTS.highEntropy, 'high_entropy', `Entropy ${maxEntropy.toFixed(2)} (likely encoded payload)`);
      }
    }
  }

  const paramAnomalies = [];
  const paramEntropyUpdates = new Map();
  const paramSpecialUpdates = new Map();

  for (const [key, val] of Object.entries(decodedReq.query || {})) {
    const strVal = String(val).slice(0, 500);
    if (!strVal || strVal.length < 2) continue;
    const paramStats = getParamStats(stats, key);
    
    const bolaScore = detectSlowBOLA(decodedReq.ip, key, strVal);
    if (bolaScore > 0) {
      add(WEIGHTS.slow_bola_enumeration, 'slow_bola_enumeration', `Slow IDOR pattern: ${bolaScore} unique IDs for param "${key}" in 1h`);
    }

    const currentType = getParamType(strVal);
    if (currentType !== 'string') {
      paramTypeUpdates.set(`${key}:${currentType}`, (paramStats.types.get(currentType) || 0) + 1);
    }
    const isUsuallyNumeric = (paramStats.types.get('int') || 0) > 20 || (paramStats.types.get('uuid') || 0) > 20;
    if (isUsuallyNumeric && currentType === 'string') {
      const logicKeywords = /\b(OR|AND|UNION|SELECT|FROM|WHERE|LIKE|BETWEEN|WAITFOR|SLEEP)\b/i;
      if (logicKeywords.test(strVal) || charClassRatio(strVal, /[^a-zA-Z0-9\s]/g) > 0.05) {
        paramAnomalies.push(`Query param "${key}" type mutation with logic keywords (${strVal.substring(0, 20)})`);
      }
    }

    if (strVal.length < 10) continue;

    const vEnt = calculateEntropy(strVal);
    const vSpec = charClassRatio(strVal, /[^a-zA-Z0-9\s.,\-_@]/g);
    if (vEnt > 0) paramEntropyUpdates.set(key, vEnt);
    if (vSpec > 0) paramSpecialUpdates.set(key, vSpec);
    const zEnt = paramStats.entropy.getZScore(vEnt);
    const zSpec = paramStats.specialRatio.getZScore(vSpec);
    if (zEnt > 3) paramAnomalies.push(`Query param "${key}" entropy z=${zEnt.toFixed(2)}`);
    if (zSpec > 3) paramAnomalies.push(`Query param "${key}" spec_chars z=${zSpec.toFixed(2)}`);
  }

  if (typeof decodedReq.body === 'object' && decodedReq.body !== null) {
    for (const [key, val] of Object.entries(decodedReq.body)) {
      const strVal = String(val).slice(0, 500);
      if (!strVal || strVal.length < 2) continue;
      const paramStats = getParamStats(stats, `body:${key}`);

      const bolaScore = detectSlowBOLA(decodedReq.ip, key, strVal);
      if (bolaScore > 0) {
        add(WEIGHTS.slow_bola_enumeration, 'slow_bola_enumeration', `Slow IDOR pattern: ${bolaScore} unique IDs for param "body:${key}" in 1h`);
      }

      const currentType = getParamType(strVal);
      if (currentType !== 'string') {
        paramTypeUpdates.set(`body:${key}:${currentType}`, (paramStats.types.get(currentType) || 0) + 1);
      }
      const isUsuallyNumeric = (paramStats.types.get('int') || 0) > 20 || (paramStats.types.get('uuid') || 0) > 20;
      if (isUsuallyNumeric && currentType === 'string') {
        const logicKeywords = /\b(OR|AND|UNION|SELECT|FROM|WHERE|LIKE|BETWEEN|WAITFOR|SLEEP)\b/i;
        if (logicKeywords.test(strVal) || charClassRatio(strVal, /[^a-zA-Z0-9\s]/g) > 0.05) {
          paramAnomalies.push(`Body param "${key}" type mutation with logic keywords (${strVal.substring(0, 20)})`);
        }
      }

      if (strVal.length < 10) continue;

      const vEnt = calculateEntropy(strVal);
      const vSpec = charClassRatio(strVal, /[^a-zA-Z0-9\s.,\-_@]/g);
      if (vEnt > 0) paramEntropyUpdates.set(`body:${key}`, vEnt);
      if (vSpec > 0) paramSpecialUpdates.set(`body:${key}`, vSpec);
      const zEnt = paramStats.entropy.getZScore(vEnt);
      const zSpec = paramStats.specialRatio.getZScore(vSpec);
      if (zEnt > 3) paramAnomalies.push(`Body param "${key}" entropy z=${zEnt.toFixed(2)}`);
      if (zSpec > 3) paramAnomalies.push(`Body param "${key}" spec_chars z=${zSpec.toFixed(2)}`);
    }
  }

  if (paramAnomalies.length > 0) {
    add(WEIGHTS.highEntropy * paramAnomalies.length, 'param_entropy_anomaly', paramAnomalies.slice(0, 3).join(', '));
  }

  if (maxEntropy > 5.0 && maxSpecialRatio > 0.25) {
    add(WEIGHTS.highEntropy + WEIGHTS.unusualCharDensity, 'obfuscated_payload', 'High entropy + High special chars correlation');
  } else if (maxEntropy < 3.5 && maxSpecialRatio > 0.25) {
    add(WEIGHTS.unusualCharDensity * 2, 'structural_injection', 'Low entropy + High special chars correlation (Injection/SSTI)');
  }

  let invisibleChars = 0;
  for (const c of candidates) {
    invisibleChars += detectInvisibleChars(c);
  }
  if (invisibleChars > 0) {
    add(WEIGHTS.evasion * 2, 'invisible_chars', `${invisibleChars} zero-width/invisible unicode chars detected`);
  }

  const jsonAnomalies = detectMalformedJsonKeys(decodedReq);
  if (jsonAnomalies.length > 0) {
    add(WEIGHTS.criticalExploit, 'json_structure_anomaly', `Dangerous JSON keys: ${jsonAnomalies.join(', ')}`);
  }

  let hasSSTI = false;
  for (const c of candidates) {
    if (detectSSTI(c)) { hasSSTI = true; break; }
  }
  if (hasSSTI) add(WEIGHTS.templateInjection, 'ssti_indicator', 'Server-Side Template Injection syntax detected');

  const pollution = detectParameterPollution(decodedReq);
  if (pollution.length > 0) add(WEIGHTS.parameterPollution, 'parameter_pollution', `${pollution.length} duplicate keys: ${pollution.slice(0, 3).join(', ')}`);

  let rawBytesList = [];
  for (const c of candidates) {
    rawBytesList.push(...detectRawBytes(c));
  }
  if (rawBytesList.length > 0) add(WEIGHTS.rawByteInjection, 'raw_bytes', `${rawBytesList.length} control bytes: ${rawBytesList.slice(0, 3).join(', ')}`);

  const inflation = detectPayloadInflation(decodedReq);
  if (inflation) add(WEIGHTS.payloadInflation, 'payload_inflation', `${(inflation.ratio/1024).toFixed(1)}KB avg per ${inflation.keys} keys`);

  const naked = detectNakedRequest(decodedReq.headers, decodedReq.userAgent);
  if (naked.length > 0) add(WEIGHTS.nakedRequest, 'naked_request', naked.slice(0, 3).join(', '));

  const headerIssues = detectRichHeaderAnomaly(decodedReq.method, decodedReq.headers, decodedReq.rawHeaders, decodedReq.userAgent);
  if (headerIssues.length > 0) add(WEIGHTS.headerIntegrity, 'header_integrity', headerIssues.join(', '));

  if (detectEmptyBody(decodedReq.headers, decodedReq.body)) {
    add(WEIGHTS.emptyBody, 'empty_json_body', 'Content-Type: application/json but body is empty');
  }

  const codeRatio = Math.max(...candidates.map(c => calculateCodeRatio(c)));
  if (codeRatio > 0.2) {
    add(WEIGHTS.code_execution_ratio * (codeRatio > 0.4 ? 2 : 1), 'code_execution_ratio', 
      `High operator-to-operand ratio (${codeRatio.toFixed(2)}) indicates code execution attempt`);
  }

  for (const c of candidates) {
    if (detectLocalEntropySpike(c)) {
      add(WEIGHTS.local_entropy_spike, 'local_entropy_spike', 'Local structural anomaly detected (embedded payload)');
      break; 
    }
  }

  const homoglyphs = Math.max(...candidates.map(c => detectHomoglyphs(c)));
  if (homoglyphs > 0) {
    add(WEIGHTS.evasion, 'homoglyph_evasion', `${homoglyphs} words with mixed latin/cyrillic detected (bypass attempt)`);
  }

  if (maxEntropy > 4.5) {
    const ngramDev = Math.max(...candidates.map(c => calculateNgramDeviation(c)));
    if (ngramDev > 0.9) {
      add(WEIGHTS.linguistic_anomaly, 'linguistic_anomaly', 
        `High N-gram deviation (${ngramDev.toFixed(2)}) indicates obfuscated payload`);
    }
  }

  if (detectHeaderCRLFInjection(decodedReq)) {
    add(WEIGHTS.protocol_smuggling, 'header_crlf_injection', 'CR/LF characters detected in HTTP headers (H2 Smuggling attempt)');
  }

  const smuggling = detectRequestSmuggling(decodedReq);
  if (smuggling.length > 0) {
    add(WEIGHTS.protocol_smuggling, 'protocol_smuggling', `HTTP Desync indicator: ${smuggling.join(', ')}`);
  }

  const raceScore = checkRaceCondition(decodedReq);
  if (raceScore > 0) {
    add(WEIGHTS.race_condition, 'race_condition', `Concurrency spike detected (${raceScore} requests in 100ms window)`);
  }

  const gqlScore = detectGraphQLAbuse(decodedReq);
  if (gqlScore > 0) {
    add(WEIGHTS.graphql_complexity_abuse + gqlScore, 'graphql_complexity_abuse', `GraphQL DoS pattern: depth/aliases score ${gqlScore}`);
  }

  let shapeHash = null;
  if (stats.entropy.count > 100) {
    shapeHash = getRequestShape(decodedReq);
    const shapeRarity = stats.shapeFrequency.get(shapeHash) || 0;
    
    let ipTaint = 0;
    try {
      const { getReputationTaint } = require('../core/recon-tracker');
      ipTaint = getReputationTaint(decodedReq.ip);
    } catch(e) {}
    
    if (shapeRarity < 2 && ipTaint > 10) {
      add(WEIGHTS.novel_request_shape, 'novel_request_shape', 
        'Zero-Day indicator: Novel request structure from suspicious IP on calibrated endpoint');
    }
  }

  let level = 'none';
  if (score >= CRITICAL_THRESHOLD) level = 'critical';
  else if (score >= SCORE_THRESHOLD) level = 'high';
  else if (score >= SCORE_THRESHOLD * 0.6) level = 'medium';
  else if (score >= SCORE_THRESHOLD * 0.3) level = 'low';

  return {
    score, level, threshold: SCORE_THRESHOLD, factors, groupScores,
    suppressedSignals: suppressed.size > 0 ? [...suppressed] : undefined,
    dominantGroup: Object.entries(groupScores).sort((a, b) => b[1] - a[1])[0]?.[0] || 'none',
    description: factors.length ? `Anomaly score ${score}/${CRITICAL_THRESHOLD}: ${factors.map(f => f.name).join(', ')}` : 'Clean',
    
    // Internal values for stats updating
    _maxEntropy: maxEntropy,
    _maxSpecialRatio: maxSpecialRatio,
    _path: path,
    _paramEntropyUpdates: paramEntropyUpdates,
    _paramSpecialUpdates: paramSpecialUpdates,
    _paramTypeUpdates: paramTypeUpdates,
    _shapeHash: shapeHash
  };
}

const MUTATION_CACHE = new Map();

function check(decodedReq, responseTimeMs = 0) {
  const result = analyze(decodedReq);

  // Payload Mutation & Evasion Tracking (Polymorphism / Fuzzing)
  if (result.score >= 5 && result.score < SCORE_THRESHOLD) {
    const mutationKey = `mutation:${decodedReq.ip}:${result._path}`;
    const mutationData = MUTATION_CACHE.get(mutationKey) || { count: 0, ts: Date.now() };
    mutationData.count += 1;
    mutationData.ts = Date.now();
    MUTATION_CACHE.set(mutationKey, mutationData);
    
    if (mutationData.count >= 3) {
      result.score += 8; 
      result.factors.push({ name: 'payload_mutation_fuzzing', detail: `${mutationData.count} suspicious variants from same IP` });
      
      if (result.score >= CRITICAL_THRESHOLD) result.level = 'critical';
      else if (result.score >= SCORE_THRESHOLD) result.level = 'high';
      else if (result.score >= SCORE_THRESHOLD * 0.6) result.level = 'medium';
      else result.level = 'low';
    }
    
    if (MUTATION_CACHE.size > 10000) {
      MUTATION_CACHE.delete(MUTATION_CACHE.keys().next().value);
    }
  }

  // Add penalty for blind injection
  if (result.score > 5 && responseTimeMs > 2000) {
     result.score += WEIGHTS.blindAnomaly;
     result.factors.push({ name: 'blind_time_anomaly', detail: `Response time ${responseTimeMs}ms with low-score payload`, group: 'behavioral', weight: WEIGHTS.blindAnomaly });
     
     // Recalculate level after score change
     if (result.score >= CRITICAL_THRESHOLD) result.level = 'critical';
     else if (result.score >= SCORE_THRESHOLD) result.level = 'high';
     else if (result.score >= SCORE_THRESHOLD * 0.6) result.level = 'medium';
     else result.level = 'low';
  }

  // Safely update baselines only on benign traffic to prevent poisoning
  if (result.score < SCORE_THRESHOLD * 0.3) {
    const stats = getStats(result._path);
    if (result._maxEntropy > 0) stats.entropy.update(result._maxEntropy);
    if (result._maxSpecialRatio > 0) stats.specialRatio.update(result._maxSpecialRatio);
    if (result._paramEntropyUpdates) {
      for (const [k, v] of result._paramEntropyUpdates) {
        getParamStats(stats, k).entropy.update(v);
      }
    }
    if (result._paramSpecialUpdates) {
      for (const [k, v] of result._paramSpecialUpdates) {
        getParamStats(stats, k).specialRatio.update(v);
      }
    }
    if (result._paramTypeUpdates) {
      for (const [typeKey, count] of result._paramTypeUpdates) {
        const parts = typeKey.split(':');
        const type = parts.pop();
        const paramKey = parts.join(':');
        const pStats = getParamStats(stats, paramKey);
        pStats.types.set(type, count);
      }
    }
    if (result._shapeHash) {
      stats.shapeFrequency.set(result._shapeHash, (stats.shapeFrequency.get(result._shapeHash) || 0) + 1);
    }
    return []; // Clean request
  }

  if (result.score < SCORE_THRESHOLD) {
    return [{
      rule: 'anomaly_detection',
      tags: ['anomaly', 'low_confidence', 'preliminary'],
      severity: 'low',
      category: 'anomaly',
      description: `Preliminary anomaly signals detected (score ${result.score}/${SCORE_THRESHOLD}). Recommend smart-anomaly analysis.`,
      author: 'laraxaar',
      sourceFile: 'builtin:anomaly',
      matchedPatterns: result.factors.map(f => ({ name: f.name, matched: f.detail })),
      analysis: { ...result, recommendation: 'escalate_to_smart_anomaly' },
      escalateTo: 'smart_anomaly',
    }];
  }

  return [{
    rule: 'anomaly_detection',
    tags: ['anomaly', result.level === 'critical' ? 'confirmed' : 'suspicious'],
    severity: result.level,
    category: 'anomaly',
    description: result.description,
    author: 'laraxaar',
    sourceFile: 'builtin:anomaly',
    matchedPatterns: result.factors.map(f => ({ name: f.name, matched: f.detail })),
    analysis: result,
  }];
}

module.exports = { analyze, check, SCORE_THRESHOLD, CRITICAL_THRESHOLD };
