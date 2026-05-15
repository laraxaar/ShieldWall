'use strict';

/**
 * @file fingerprinter.js
 * @description TLS Identity Synthesis & Identity Drift Engine.
 * 
 * ROLE IN ARCHITECTURE:
 * Generates high-entropy identity markers (JA4L, JA3) and validates them against 
 * HTTP/2 settings and Browser Family claims. Essential for identifying impersonation.
 * 
 * DATA FLOW:
 * [Go Gateway] -> x-tls-* headers -> [fingerprinter.js] -> `analyzeRequest()` -> 
 * Cross-references with `reputation.js` -> Yields `classification` and `suspectScore`.
 * 
 * CRITICAL FALSE POSITIVE (FP) MITIGATION:
 * - Soft-Blocking: Uses suspicion tiers (elevated, suspicious) rather than immediate blocks.
 * - ASN Multipliers: Weights risk higher only for Hosting/Cloud ASNs (AWS, GCP).
 * - Drift Context: Only penalizes identity rotation if it happens within a tight time-window.
 */

const crypto = require('crypto');
const { fingerprintTracker } = require('./reputation');
const { getAlpn, extractH2Fingerprint } = require('../core/decoder');

const CONFIG = { enableJa4L: true, enableDriftDetection: true, scoringMode: 'soft-block', blockThreshold: 65, caps: { structure: 60, consistency: 50, behavioral: 50, context: 30 } };
const H2_EXPECTED = { chrome: { headerTableSize: 65536, initialWindowSize: 6291456 }, firefox: { headerTableSize: 65536, initialWindowSize: 131072 }, safari: { headerTableSize: 4096, initialWindowSize: 2097152 } };
const HOSTING_ASN = new Set([14061, 16509, 24940, 13335, 15169]);

const isGrease = (v) => Number.isInteger(v) && ((v >> 8) === (v & 0xFF)) && ((v & 0x0F) === 0x0A);

function parseJa3(ja3) {
    if (!ja3 || typeof ja3 !== 'string') return null;
    const p = ja3.split(',');
    if (p.length < 2) return null;
    const parseList = (s) => s ? s.split('-').map(Number).filter(Number.isFinite) : [];
    return { ver: p[0], ciphers: parseList(p[1]), extensions: parseList(p[2]), groups: parseList(p[3]), formats: parseList(p[4]) };
}

/**
 * Robust H2 Settings parser.
 * FIX: BUG_1 — removed Cyrillic "Й". FIX: BUG_5 — added finite validation and robust parsing
 */
function parseH2Fp(h2str) {
    if (!h2str || h2str === 'h1') return null;
    const result = {};
    for (const pair of h2str.split(';')) {
        const [k, v] = pair.split(':');
        const key = parseInt(k, 10);
        const val = parseInt(v, 10);
        if (Number.isFinite(key) && Number.isFinite(val)) {
            result[key] = val;
        }
    }
    if (Object.keys(result).length === 0) return null;
    return { headerTableSize: result[1] ?? null, initialWindowSize: result[4] ?? null };
}

function detectBrowserFamily(ua) {
    if (/edg\//i.test(ua)) return 'chrome'; 
    if (/chrome|chromium/i.test(ua)) return 'chrome';
    if (/firefox/i.test(ua)) return 'firefox';
    if (/safari/i.test(ua) && !/chrome/i.test(ua)) return 'safari';
    return null;
}

function generateJa4L(parts, alpn = 'h2') {
    const filter = (arr) => arr.filter(v => !isGrease(v));
    const hash = (str) => crypto.createHash('sha256').update(str).digest('hex').substring(0, 12);
    const proto = parts.ver === '771' ? 't12' : 't13';
    const c = filter(parts.ciphers);
    const e = filter(parts.extensions);
    const cc = String(c.length).padStart(2, '0'), ec = String(e.length).padStart(2, '0');
    const alpnTag = alpn.includes('h2') ? 'h2' : 'h1';
    const hC = hash(c.length > 0 ? c.join('-') : 'EMPTY'), hE = hash(e.length > 0 ? e.join('-') : 'EMPTY');
    return `${proto}d${cc}${ec}${alpnTag}_${hC}_${hE}`;
}

function classify(score, threshold) {
    if (score >= threshold) return 'likely-bot';
    if (score >= threshold * 0.6) return 'suspicious';
    if (score >= threshold * 0.3) return 'elevated';
    return 'clean';
}

function _analyzeRequest(req, config, tracker) {
    try {
        const gatewaySecret = req.headers['x-gateway-auth'];
        const isTrustedGateway = gatewaySecret === process.env.GATEWAY_SECRET;

        if (!isTrustedGateway && process.env.GATEWAY_SECRET) {
            delete req.headers['x-ja3-fingerprint'];
            delete req.headers['x-tls-random-entropy'];
        }

        const ja3 = req.headers['ja3-fingerprint'] || req.headers['x-ja3-fingerprint'];
        const parts = parseJa3(ja3);
        if (!parts) return { suspectScore: 0, signals: ['E_INVALID_JA3'], classification: 'unknown' };

        const clientIp = req.ip || req.socket?.remoteAddress || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';
        const ua = (req.headers['user-agent'] || '').toLowerCase();
        const h2 = extractH2Fingerprint(req);
        const alpn = getAlpn(req);
        
        const scores = { structure: 0, consistency: 0, behavioral: 0, context: 0 };
        const signals = [];

        if (parts.extensions.length > 4 && parts.extensions.every((v, i) => i === 0 || v >= parts.extensions[i - 1])) {
            scores.structure += 40; signals.push("E_MONOTONIC_EXTENSIONS");
        }
        if ((ua.includes('chrome') || ua.includes('edg/')) && !parts.extensions.some(isGrease)) {
            scores.structure += 30; signals.push("E_GREASE_MISSING");
        }
        scores.structure = Math.min(scores.structure, config.caps.structure);

        if (parts.extensions.includes(43) && !parts.extensions.includes(51)) {
            scores.consistency += 40; signals.push("C_TLS13_INCOMPLETE");
        }
        const family = detectBrowserFamily(ua), h2Parsed = parseH2Fp(h2);
        if (family && h2Parsed) {
            if (h2Parsed.initialWindowSize !== null && (h2Parsed.initialWindowSize < 1048576 || h2Parsed.initialWindowSize > 16777216)) {
                scores.consistency += 35; signals.push("C_H2_ANOMALOUS_WINDOW");
            }
        }
        scores.consistency = Math.min(scores.consistency, config.caps.consistency);

        const ja4l = generateJa4L(parts, alpn);
        const rarityScore = tracker.getRarityScore(ja4l); 
        tracker.recordFingerprint(ja4l);
        if (config.enableDriftDetection && clientIp !== 'unknown') { scores.behavioral += tracker.trackDrift(clientIp, ja4l); }
        scores.behavioral += rarityScore;
        scores.behavioral = Math.min(scores.behavioral, config.caps.behavioral);

        // FIX: BUG_9 — Using Multiplier only (Option A) to avoid double counting ASN risk.
        const asnMultiplier = (req.asn && HOSTING_ASN.has(req.asn)) ? 1.4 : 1.0;
        if (asnMultiplier > 1.0) signals.push("X_HOSTING_ASN");

        // ── Gateway-sourced heuristics (injected by Go TLS proxy) ───────
        // These only fire when the Go gateway is in the data path.
        // Gracefully degrades: no gateway = no extra signals.

        // Entropy check: real browsers use CSPRNG (entropy ≈ 7.5+).
        // Bots using LCG or predictable generators score much lower.
        const entropyHeader = req.headers['x-tls-random-entropy'];
        if (entropyHeader) {
            const entropy = parseFloat(entropyHeader);
            if (Number.isFinite(entropy)) {
                if (entropy < 5.0) {
                    scores.behavioral += 30; signals.push("E_LOW_RANDOM_ENTROPY");
                } else if (entropy < 6.5) {
                    scores.behavioral += 15; signals.push("E_WEAK_RANDOM_ENTROPY");
                }
            }
        }

        // GREASE cross-validation: Chrome/Edge always emit GREASE values.
        // If UA says Chrome but the gateway reports no GREASE, it's spoofed.
        const greaseHeader = req.headers['x-tls-has-grease'];
        if (greaseHeader && (ua.includes('chrome') || ua.includes('edg/'))) {
            if (greaseHeader === 'false') {
                scores.structure += 25; signals.push("E_GATEWAY_GREASE_MISSING");
            }
        }

        // Use gateway-provided JA4 if available (more accurate than JA4L)
        const gatewayJa4 = req.headers['x-ja4-fingerprint'];

        scores.behavioral = Math.min(scores.behavioral, config.caps.behavioral);

        const totalScore = Math.round((scores.structure + scores.consistency + scores.behavioral) * asnMultiplier + scores.context);

        return { ja4l, gatewayJa4: gatewayJa4 || null, clientIp, suspectScore: totalScore, classification: classify(totalScore, config.blockThreshold), signals, details: { scores, asnMultiplier } };
    } catch (err) {
        console.error('[fingerprinter] analyzeRequest error:', err);
        return { suspectScore: 0, classification: 'unknown', signals: ['E_INTERNAL_ERROR'], error: err.message };
    }
}

function analyzeRequest(req, userConfig = {}) { return _analyzeRequest(req, { ...CONFIG, ...userConfig }, fingerprintTracker); }

/**
 * Factory with validation.
 * FIX: BUG_10 — added deep validation for caps values
 */
function createAnalyzer(userConfig = {}, deps = {}) {
    const config = { ...CONFIG, ...userConfig };
    if (typeof config.blockThreshold !== 'number' || config.blockThreshold <= 0) throw new Error('[fingerprinter] blockThreshold must be > 0');
    if (!config.caps || typeof config.caps !== 'object') throw new Error('[fingerprinter] caps must be an object');
    
    const requiredCaps = ['structure', 'consistency', 'behavioral', 'context'];
    for (const cap of requiredCaps) {
        if (typeof config.caps[cap] !== 'number' || config.caps[cap] < 0) {
            throw new Error(`[fingerprinter] caps.${cap} must be a non-negative number`);
        }
    }
    
    return { analyzeRequest: (req) => _analyzeRequest(req, config, deps.tracker || fingerprintTracker) };
}

module.exports = { analyzeRequest, createAnalyzer, CONFIG: Object.freeze({ ...CONFIG, caps: Object.freeze({ ...CONFIG.caps }) }) };

// === EXPORTS ===
/**
 * @typedef {Object} FingerprintAnalysis
 * @property {string} ja4l - Generated JA4-Light fingerprint
 * @property {string} clientIp - Resolved client IP
 * @property {number} suspectScore - Total weighted risk score
 * @property {('clean'|'elevated'|'suspicious'|'likely-bot'|'unknown')} classification - Threat level
 * @property {string[]} signals - Triggered heuristic IDs
 * @property {Object} details - Breakdown of scores and multipliers
 */
