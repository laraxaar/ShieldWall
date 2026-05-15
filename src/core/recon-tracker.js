'use strict';

/**
 * @file recon-tracker.js
 * @description Reconnaissance-to-Exploit Correlation Engine.
 * 
 * ROLE IN ARCHITECTURE:
 * Acts as the memory of the WAF. Tracks IP addresses that behave like scanners
 * (e.g. looking for /.env, /wp-admin) and applies a "Taint" score.
 * If a tainted IP later attempts a subtle exploit on a critical endpoint,
 * the WAF uses the historical taint to lower the blocking threshold and 
 * stop the attack (Kill Chain interruption).
 */

const RECON_HISTORY = new Map();
const MAX_RECON_ENTRIES = 20000;
const RECON_TTL = 3600000; // 1 hour memory of malicious intent

// Patterns that a normal user would NEVER organically trigger
const SCANNER_PATTERNS = [
  /\.(env|git|htaccess|aws|ds_store)/i,
  /(wp-admin|wp-login|phpmyadmin|adminer|xmlrpc)/i,
  /\/(actuator|swagger|graphql|api-docs|\.well-known)/i,
  /\b(v1|v2)\/(internal|debug|console|metrics)\b/i,
];

// Sensitive endpoints (Zero-Day targets)
const SENSITIVE_ENDPOINTS = [
  /\/(auth|login|oauth|sso|api\/token)/i,
  /\/(admin|dashboard|config|settings)/i,
  /\/api\/v\d+\/(payment|checkout|users|exec)/i,
];

/**
 * Records an indicator of reconnaissance from an IP.
 * @param {string} ip - The client IP.
 * @param {string} path - The requested URI path.
 * @param {number} statusCode - The HTTP status code returned to the client.
 */
function recordReconAttempt(ip, path, statusCode) {
  if (!RECON_HISTORY.has(ip)) {
    if (RECON_HISTORY.size >= MAX_RECON_ENTRIES) {
      RECON_HISTORY.delete(RECON_HISTORY.keys().next().value);
    }
    RECON_HISTORY.set(ip, { score: 0, lastSeen: Date.now(), paths: [] });
  }

  const record = RECON_HISTORY.get(ip);
  record.lastSeen = Date.now();

  // 1. Scanner-like paths (404 on /.env, etc.)
  if (SCANNER_PATTERNS.some(p => p.test(path))) {
    record.score += 10; // Severe penalty
    record.paths.push(path);
  }

  // 2. Anomalous 404/403 percentage (directory brute forcing)
  if (statusCode === 404 || statusCode === 403) {
    record.score += 2;
  }

  // Cap memory usage per IP
  if (record.paths.length > 10) record.paths.shift();
}

/**
 * Retrieves the current "Taint" score for an IP.
 * @param {string} ip - The client IP.
 * @returns {number} The current taint score (0 if clean or expired).
 */
function getReputationTaint(ip) {
  const record = RECON_HISTORY.get(ip);
  if (!record) return 0;

  // Decay score over time
  const timeDiff = Date.now() - record.lastSeen;
  if (timeDiff > RECON_TTL) {
    RECON_HISTORY.delete(ip);
    return 0;
  }

  return record.score;
}

/**
 * Checks if the requested path is considered a sensitive target for Zero-Days.
 * @param {string} path - The requested URI path.
 * @returns {boolean} True if sensitive.
 */
function isSensitiveTarget(path) {
  return SENSITIVE_ENDPOINTS.some(p => p.test(path));
}

// Background cleanup of expired recon records
const _cleanupInterval = setInterval(() => {
  const cutoff = Date.now() - RECON_TTL;
  for (const [ip, record] of RECON_HISTORY.entries()) {
    if (record.lastSeen < cutoff) RECON_HISTORY.delete(ip);
  }
}, 300000);
if (_cleanupInterval.unref) _cleanupInterval.unref();

module.exports = { recordReconAttempt, getReputationTaint, isSensitiveTarget };
