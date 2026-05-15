'use strict';

/**
 * @file decoder.js
 * @description Advanced Context-Aware Request Decoder & Normalizer.
 * 
 * ROLE:
 * Neutralizes evasion attempts (URL encoding, HTML entities, Base64, Path traversal)
 * by canonicalizing the request into a "clean" structural map.
 */

const MAX_DECODE_DEPTH = 5;
const MAX_INPUT_LENGTH = 64 * 1024;
const MAX_OUTPUT_LENGTH = 256 * 1024;
const MAX_EXPANSION_RATIO = 8;



/**
 * Normalizes path and resolves traversal safely.
 * FIX: BUG_3 — iterative resolution for nested ../ and trailing ..
 */
function normalizePath(str) {
  let path = str.replace(/\\/g, '/').replace(/\/+/g, '/');
  const parts = path.split('/');
  const stack = [];
  for (const part of parts) {
    if (part === '..') {
      if (stack.length > 0 && stack[stack.length - 1] !== '') stack.pop();
    } else if (part !== '.' && part !== '') {
      stack.push(part);
    }
  }
  let resolved = '/' + stack.join('/');
  if (path.endsWith('/') && !resolved.endsWith('/')) resolved += '/';
  return resolved;
}

/**
 * Strict Base64 decoder with round-trip validation.
 * FIX: BUG_4 — added strict validation, padding check, expansion ratio
 */
function tryDecodeBase64(token) {
  if (token.length < 8) return null;
  const normalized = token.replace(/-/g, '+').replace(/_/g, '/');
  
  // Validate charset strictly
  if (!/^[A-Za-z0-9+/]+=*$/.test(normalized)) return null;
  
  // Validate padding logic
  const withoutPadding = normalized.replace(/=+$/, '');
  const remainder = withoutPadding.length % 4;
  if (remainder === 1) return null; // Invalid length for B64
  
  try {
    const buf = Buffer.from(normalized, 'base64');
    
    // Round-trip check
    const reEncoded = buf.toString('base64').replace(/=+$/, '');
    if (reEncoded !== withoutPadding) return null;
    
    const decoded = buf.toString('utf8');
    
    // Quality checks
    if (decoded.length < 4) return null;
    if (!/^[\x09\x0A\x0D\x20-\x7E\u0400-\u04FF]+$/.test(decoded)) return null;
    if (decoded.length > token.length * MAX_EXPANSION_RATIO) return null;
    
    return decoded;
  } catch {
    return null;
  }
}

/**
 * Detects duplicate keys in JSON body to prevent smuggling.
 * FIX: BUG_5 — compares parsed key count with raw matches to handle nesting/escapes
 */
function hasDuplicateKeys(jsonStr) {
  if (typeof jsonStr !== 'string' || !jsonStr.includes('{')) return false;
  try {
    const parsed = JSON.parse(jsonStr);
    const parsedKeyCount = Object.keys(parsed).length;
    let depth = 0;
    let inString = false;
    let escape = false;
    let keysAtDepth1 = 0;
    for (let i = 0; i < jsonStr.length; i++) {
      const char = jsonStr[i];
      if (inString) {
        if (escape) escape = false;
        else if (char === '\\') escape = true;
        else if (char === '"') inString = false;
      } else {
        if (char === '"') inString = true;
        else if (char === '{') depth++;
        else if (char === '}') depth--;
        else if (char === ':' && depth === 1) keysAtDepth1++;
      }
    }
    return keysAtDepth1 > parsedKeyCount;
  } catch {
    return false;
  }
}

/**
 * Main entry point for request normalization.
 */
function decodeRequest(req) {
  const decoded = {
    method: (req.method || 'GET').toUpperCase(),
    rawUrl: req.url || '/',
    path: '',
    query: {},
    headers: {},
    cookies: {},
    body: null,
    rawBody: req.body || '',
    ip: req.clientIp || 'unknown'
  };

  try {
    const url = new URL(req.url || '/', 'http://local');
    decoded.path = fullDecode(url.pathname, 'path');
    for (const [k, v] of url.searchParams.entries()) {
      decoded.query[fullDecode(k, 'queryKey')] = deepDecode(v, 'queryValue');
    }
  } catch (e) {
    const parts = (req.url || '/').split('?');
    decoded.path = fullDecode(parts[0], 'path');
  }

  if (req.headers) {
    for (const [key, value] of Object.entries(req.headers)) {
      decoded.headers[key.toLowerCase()] = fullDecode(String(value), 'header');
    }
  }

  if (req.body) {
    if (hasDuplicateKeys(req.body)) decoded.jsonSmuggling = true;
    decoded.body = deepDecode(req.body, 'body');
  }

  return decoded;
}

/**
 * Recursively decodes structured data.
 * FIX: BUG_6 — uses MAX_DECODE_DEPTH constant
 */
function deepDecode(value, context, depth = 0) {
  if (depth >= MAX_DECODE_DEPTH) return value;
  if (typeof value === 'string') return fullDecode(value, context, depth);
  if (Array.isArray(value)) return value.map(v => deepDecode(v, context, depth + 1));
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [
        fullDecode(k, context + 'Key'),
        deepDecode(v, context, depth + 1)
      ])
    );
  }
  return value;
}

/**
 * Multi-pass context-aware decoder.
 * FIX: BUG_7 — added length protection between passes
 */
function fullDecode(str, context = 'generic', depth = 0) {
  if (!str || typeof str !== 'string' || depth >= MAX_DECODE_DEPTH) return str || '';
  
  let current = str;
  const checkLen = (s) => s.length > MAX_OUTPUT_LENGTH ? s.slice(0, MAX_OUTPUT_LENGTH) : s;

  // Layer 0: Unicode & Nulls
  current = checkLen(current.normalize('NFKC').replace(/\0/g, ''));

  // Layer 1: URL Decode
  const plusAsSpace = ['queryValue', 'queryKey', 'cookie', 'body'].includes(context);
  const urlDecoded = urlDecode(current, plusAsSpace);
  current = checkLen(urlDecoded);

  // Layer 2: HTML Entities
  const htmlDecoded = htmlEntityDecode(current);
  current = checkLen(htmlDecoded);

  // Layer 3: Unicode Escapes
  const uniDecoded = unicodeDecode(current);
  current = checkLen(uniDecoded);

  // Layer 4: Base64 (selective)
  if (['queryValue', 'body', 'cookie', 'header'].includes(context)) {
    const b64 = tryDecodeBase64(current);
    if (b64) return fullDecode(checkLen(b64), context, depth + 1);
  }

  // Layer 5: Path Normalization
  if (context === 'path') current = normalizePath(current);

  // Recursion until stable
  if (current !== str) {
    if (depth > 2) console.debug(`[decoder] Deep recursion reached for context ${context}`);
    return fullDecode(current, context, depth + 1);
  }

  return current;
}

function urlDecode(str, plusAsSpace) {
  const input = plusAsSpace ? str.replace(/\+/g, ' ') : str;
  try { return decodeURIComponent(input); } catch {
    return input.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  }
}

function htmlEntityDecode(str) {
  return str
    .replace(/&lt;?/gi, '<').replace(/&gt;?/gi, '>').replace(/&quot;?/gi, '"')
    .replace(/&#39;?/g, "'").replace(/&amp;?/gi, '&')
    .replace(/&#x([0-9A-Fa-f]+);?/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&#([0-9]+);?/g, (_, d) => String.fromCharCode(parseInt(d, 10)));
}

function unicodeDecode(str) {
  return str
    .replace(/%u([0-9A-Fa-f]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\u\{([0-9A-Fa-f]{1,6})\}/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/\\u([0-9A-Fa-f]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\x([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\0([0-7]{1,3})/g, (_, o) => String.fromCharCode(parseInt(o, 8)));
}

/**
 * Protocol extraction helpers.
 */
function getAlpn(req) {
  return req.socket?.alpnProtocol || req.headers['x-alpn'] || req.headers['cf-alpn'] || (req.httpVersion === '2.0' ? 'h2' : 'http/1.1');
}

function extractH2Fingerprint(req) {
  const h = req.headers['x-h2-fingerprint'] || req.headers['ck-h2-settings'];
  if (h) return h;
  if (req.httpVersion === '2.0' && req.stream?.session?.originSettings) {
    const s = req.stream.session.originSettings;
    return `1:${s.headerTableSize};3:${s.maxConcurrentStreams};4:${s.initialWindowSize}`;
  }
  return 'h1';
}

module.exports = { decodeRequest, fullDecode, deepDecode, getAlpn, extractH2Fingerprint };

// === EXPORTS ===
/**
 * @typedef {Object} DecoderModule
 * @property {Function} decodeRequest - Main normalization entry
 * @property {Function} fullDecode - Multi-pass string decoder
 * @property {Function} deepDecode - Recursive object decoder
 * @property {Function} getAlpn - ALPN protocol extractor
 * @property {Function} extractH2Fingerprint - H2 settings extractor
 */
