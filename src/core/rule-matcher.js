'use strict';

/**
 * @file rule-matcher.js
 * @description YARA-inspired Signature Evaluation Engine.
 * 
 * ROLE IN ARCHITECTURE:
 * It receives normalized (decoded) HTTP payloads and evaluates them against compiled
 * `.shield` DSL rules. It executes the boolean logic tree (and, or, match_in, etc).
 * 
 * DATA FLOW:
 * [engine.js] passes `decodedReq` -> `prepareMatchData()` creates flat strings -> 
 *  `evaluate()` recursively checks AST nodes -> `matchAllRules()` outputs Threat Matches.
 * 
 * CRITICAL FALSE POSITIVE (FP) MITIGATION:
 * The legacy stringifier concatenated everything into `md.full`. This caused massive 
 * False Positives on XSS signatures when evaluating benign data (e.g., a blog post about XSS).
 * The new stringifier flattens JSON arrays properly and rules strongly prefer `resolveTarget`
 * over generic `md.full` matches.
 */

const TARGET_MAP = {
  'request.url': 'url', 'request.path': 'path', 'request.body': 'body',
  'request.query': 'queryString', 'request.headers': 'headerString',
  'request.cookies': 'cookieString', 'request.method': 'method',
  'request.useragent': 'userAgent', 'request.user_agent': 'userAgent',
  'request.ip': 'ip', 'request.raw_url': 'rawUrl', 'request.raw_body': 'rawBody',
  'request.session': 'sessionId', 'request.sessionid': 'sessionId',
  'request.timestamp': 'timestamp', 'request.time': 'timestamp',
  'request.geoip': 'geoipString', 'request.geo': 'geoipString',
  'request.fingerprint': 'fingerprintString', 'request.fp': 'fingerprintString',
  'request.rate': 'rateString',
  'request.content_type': 'contentType', 'request.hostname': 'hostname',
  'request.protocol': 'protocol',
};

/**
 * Transforms nested objects into a flat string representation safely.
 * FP MITIGATION: Resolves crashes where arrays/objects in GraphQL/JSON are fed to Object.entries.
 * @param {any} val - The value to stringify.
 * @returns {string} Safe flattened string.
 */
function _safeStringify(val) {
  if (typeof val === 'string') return val;
  if (Array.isArray(val)) return val.map(_safeStringify).join(',');
  if (val !== null && typeof val === 'object') {
    return Object.entries(val).map(([k, v]) => `${k}=${_safeStringify(v)}`).join('&');
  }
  return String(val || '');
}

/**
 * Normalizes the decoded request payload into mapping strings for RegExp execution.
 * @param {Object} d - Decoded request object from `decoder.js`.
 * @returns {Object} Search-optimized data structure.
 */
function prepareMatchData(d) {
  const data = {
    url: d.url || '', path: d.path || '', body: d.body || '',
    method: d.method || '', userAgent: d.userAgent || '', ip: d.ip || '',
    rawUrl: d.rawUrl || '', rawBody: d.rawBody || '',
    queryString: '', headerString: '', cookieString: '', full: '',
    sessionId: d.sessionId || '',
    timestamp: d.timestamp || Date.now(),
    geoipString: '',
    fingerprintString: '',
    rateString: '',
    contentType: (d.headers && (d.headers['content-type'] || d.headers['Content-Type'])) || '',
    hostname: (d.headers && (d.headers['host'] || d.headers['Host'])) || '',
    protocol: d.protocol || 'http',
  };

  if (d.query) data.queryString = _safeStringify(d.query);
  if (d.headers) data.headerString = _safeStringify(d.headers);
  if (d.cookies) data.cookieString = _safeStringify(d.cookies);
  if (d.geoip) data.geoipString = _safeStringify(d.geoip);
  if (d.fingerprint) data.fingerprintString = _safeStringify(d.fingerprint);
  if (d.rate) data.rateString = _safeStringify(d.rate);

  // DEEP DIVE: 'data.full' is a brute-force search space. 
  // Should only be used by `any_of_them` global fallback rules. Do not map explicit targets to this.
  data.full = [data.url, data.queryString, data.body, data.headerString, data.cookieString, data.geoipString, data.fingerprintString].join('\n');
  return data;
}

/**
 * Executes a RegExp pattern against the target string safely.
 * @param {Object} def - Compiled string definition from rule.
 * @param {string} text - The target text surface.
 * @returns {boolean} True if matched.
 */
function testPattern(def, text) { 
  return def?.compiled && text ? def.compiled.test(text) : false; 
}

/**
 * Resolves the specific DSL target string (e.g. `request.body`) mapping to the internal data structure.
 * @param {string} name - The DSL target variable name.
 * @param {Object} rule - The current executing rule.
 * @param {Object} md - The Match Data surface.
 * @returns {string} The resolved string content.
 */
function resolveTarget(name, rule, md) {
  if (rule.targets?.[name]) { 
    const mapped = TARGET_MAP[rule.targets[name]] || rule.targets[name]; 
    return md[mapped] || ''; 
  }
  return md.full;
}

/**
 * Evaluates the AST condition block recursively.
 * @param {Object} node - Current AST node (`and`, `or`, `match`, etc).
 * @param {Object} rule - The executing rule context.
 * @param {Object} md - The normalized search data surface.
 * @returns {boolean} True if the node evaluates positively.
 */
function evaluate(node, rule, md) {
  if (!node) return true;
  switch (node.type) {
    case 'and': return evaluate(node.left, rule, md) && evaluate(node.right, rule, md);
    case 'or': return evaluate(node.left, rule, md) || evaluate(node.right, rule, md);
    case 'not': return !evaluate(node.expr, rule, md);
    case 'match': return testPattern(rule.strings[node.pattern], md.full);
    case 'match_in': return testPattern(rule.strings[node.pattern], resolveTarget(node.target, rule, md));
    case 'any_of_them': return Object.values(rule.strings).some(d => testPattern(d, md.full));
    case 'all_of_them': return Object.values(rule.strings).every(d => testPattern(d, md.full));
    case 'any_of': return node.vars.some(v => testPattern(rule.strings[v], md.full));
    case 'all_of': return node.vars.every(v => testPattern(rule.strings[v], md.full));
    case 'boolean': return node.value;
    default: return false;
  }
}

/**
 * Compiles parsed rules into an optimized matching context.
 * Uses Target Grouping and Aho-Corasick for O(n) fast-path filtering.
 * @param {Array} rules - Raw parsed rules.
 * @returns {Object} Compiled matcher context.
 */
function compileRules(rules) {
  const AhoCorasick = require('./aho-corasick');
  const context = {
    allRules: rules,
    targetGroups: {
      url: [], body: [], headers: [], any: []
    },
    aho: new AhoCorasick(),
    literalRules: new Set(), // Rules that MUST have a literal match to trigger
  };

  for (const rule of rules) {
    let hasLiteral = false;
    let targetCategory = 'any';

    // 1. Grouping by Target to prevent evaluating body rules on empty bodies
    const targets = Object.values(rule.targets || {});
    if (targets.every(t => t.includes('body'))) targetCategory = 'body';
    else if (targets.every(t => t.includes('url') || t.includes('path') || t.includes('query'))) targetCategory = 'url';
    else if (targets.every(t => t.includes('header') || t.includes('cookie') || t.includes('useragent'))) targetCategory = 'headers';

    context.targetGroups[targetCategory].push(rule);

    // 2. Extract Literal Strings for Aho-Corasick
    // If all patterns in the rule's condition require specific strings,
    // and those strings are literals (not regex), we can mandate a fast-path match.
    for (const [name, def] of Object.entries(rule.strings)) {
      if (def.type === 'string' && def.value.length >= 3) {
        // Add literal to Aho-Corasick. Output is the rule reference.
        context.aho.add(def.nocase ? def.value.toLowerCase() : def.value, rule);
        hasLiteral = true;
      }
    }

    if (hasLiteral) {
      context.literalRules.add(rule);
    }
  }

  context.aho.build();
  return context;
}

/**
 * Iterates across all loaded signatures using Aho-Corasick Fast-Path.
 * Outputs matches acting as 'Signals' for engine.js's Unified Risk Aggregator.
 * @param {Object} ctx - Compiled Matcher Context.
 * @param {Object} decodedReq - Request data.
 * @returns {Array} List of triggered match objects containing severity and context.
 */
function matchCompiledRules(ctx, decodedReq) {
  const md = prepareMatchData(decodedReq);
  const matches = [];

  // Determine active rule groups based on request context
  const activeRules = new Set(ctx.targetGroups.any);
  ctx.targetGroups.url.forEach(r => activeRules.add(r)); // URL is always present
  if (md.body) ctx.targetGroups.body.forEach(r => activeRules.add(r));
  if (md.headerString) ctx.targetGroups.headers.forEach(r => activeRules.add(r));

  // 1. Aho-Corasick Fast Path (O(n) scan over entire payload)
  const fullPayloadLower = md.full.toLowerCase();
  const fastPathHits = new Set(ctx.aho.search(fullPayloadLower));

  for (const rule of activeRules) {
    // Fast-path exclusion: If the rule relies on literals and Aho didn't find ANY, skip AST eval.
    if (ctx.literalRules.has(rule) && !fastPathHits.has(rule)) {
      continue;
    }

    // AST Evaluation (Slow Path)
    if (!evaluate(rule.condition, rule, md)) continue;

    const mp = [];
    for (const [name, def] of Object.entries(rule.strings)) {
      if (testPattern(def, md.full)) { 
        const m = md.full.match(def.compiled); 
        mp.push({ name, matched: m ? m[0] : '(matched)' }); 
      }
    }

    matches.push({
      rule: rule.name, 
      tags: rule.tags, 
      severity: rule.meta.severity || 'medium',
      category: rule.tags[0] || rule.meta.category || 'unknown',
      description: rule.meta.description || '', 
      author: rule.meta.author || 'ShieldWall',
      sourceFile: rule.sourceFile || 'inline', 
      matchedPatterns: mp,
    });
  }
  return matches;
}

module.exports = { prepareMatchData, testPattern, evaluate, compileRules, matchCompiledRules, TARGET_MAP };
