'use strict';

/**
 * @file session-anomaly.js
 * @description Session Anomaly & Geo Velocity Module
 * 
 * ROLE IN ARCHITECTURE:
 * Operates at the session level across multiple requests to detect Account Takeover (ATO)
 * and distributed abuse. Emits feature signals that engine.js translates into structural risk risks.
 * 
 * DATA FLOW:
 * [engine.js] inputs `decodedReq` -> `check()` evaluates IP drift, Geo Velocity, and Fingerprint ->
 * Returns array of Anomaly Signals back to Risk Aggregator.
 * 
 * CRITICAL FALSE POSITIVE (FP) MITIGATION:
 * - Desktop VPNs simulate "Impossible Travel" (> 900km/h), which previously trapped valid users.
 *   We now inspect 'x-forwarded-for' or 'via' patterns to classify 'VPN suspect' behaviors and downgrade risk.
 * - Memory Leak Resolution: `SESSION_DATA` Map bounds are strictly LRU pruned using `_cleanup()`
 *   based on MAX_SESSION_AGE boundaries.
 */

const SESSION_DATA = new Map();
const SESSION_GRAPHS = new Map();
const RESOURCE_ACCESS = new Map();
const MAX_SESSIONS = 50000;
const MAX_SESSION_AGE = 24 * 60 * 60 * 1000;
const HOSTING_ASN = new Set([14061, 16509, 24940, 13335, 15169]); // AWS, GCP, DigitalOcean, Cloudflare, Google

const CITY_COORDS = {
  'US': { lat: 37.0902, lon: -95.7129 },
  'RU': { lat: 61.5240, lon: 105.3188 },
  'CN': { lat: 35.8617, lon: 104.1954 },
  'GB': { lat: 55.3781, lon: -3.4360 },
  'DE': { lat: 51.1657, lon: 10.4515 },
  'FR': { lat: 46.2276, lon: 2.2137 },
  'JP': { lat: 36.2048, lon: 138.2529 },
};

const MOBILE_UA_PATTERN = /Android|iPhone|iPad|iPod|Mobile|Windows Phone/i;

/**
 * Heuristically determines if the client is running on a mobile OS.
 * @param {string} userAgent - Raw HTTP User-Agent header.
 * @returns {boolean} True if matching a known mobile browser pattern.
 */
function isMobileUA(userAgent) {
  return MOBILE_UA_PATTERN.test(userAgent || '');
}

/**
 * Mathematical formula measuring straight-line geographical distance between coordinates.
 * @param {number} lat1 - Starting Latitude.
 * @param {number} lon1 - Starting Longitude.
 * @param {number} lat2 - Target Latitude.
 * @param {number} lon2 - Target Longitude.
 * @returns {number} Distance in kilometers.
 */
function haversineDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // Earth radius in KM
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
            Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
            Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
}

/**
 * Calculates travel speed over the passed time difference.
 * @param {Object} prevLocation - Object holding `{lat, lon}`.
 * @param {Object} currLocation - Object holding `{lat, lon}`.
 * @param {number} timeDiff - Delta in milliseconds.
 * @returns {number} Velocity in km/h.
 */
function calculateGeoVelocity(prevLocation, currLocation, timeDiff) {
  if (!prevLocation || !currLocation || timeDiff <= 0) return 0;
  const distance = haversineDistance(
    prevLocation.lat, prevLocation.lon,
    currLocation.lat, currLocation.lon
  );
  const hours = timeDiff / (1000 * 60 * 60);
  return distance / hours;
}

/**
 * Evaluates the session to determine if a VPN is heavily suspected.
 * Useful for dampening Impossible Travel false positives.
 * @param {Object} decodedReq - Decoded Request map.
 * @returns {boolean} True if suspected.
 */
function isSuspectedVPN(decodedReq) {
  if (!decodedReq.headers) return false;
  const isHosting = decodedReq.asn && HOSTING_ASN.has(decodedReq.asn);
  return !!(
    decodedReq.headers['via'] || 
    decodedReq.headers['x-forwarded-for']?.includes(',') ||
    decodedReq.headers['x-vpn'] ||
    decodedReq.headers['surrogate-capability'] ||
    isHosting
  );
}

/**
 * Evaluates the current session map against geographical velocity logic constraints.
 * Extrapolates Impossible Travel and Rapid Country Switching.
 * @param {string} sessionId - The localized grouping ID.
 * @param {Object} geoData - Present lookup location.
 * @param {Object} decodedReq - Used for VPN contextual FP evaluation.
 * @returns {Array} Array of Threat Indicators.
 */
function checkGeoVelocity(sessionId, geoData, decodedReq) {
  const now = Date.now();
  const data = SESSION_DATA.get(sessionId);

  if (!data || !data.lastLocation || !geoData.country) return [];

  const timeDiff = now - data.lastLocation.timestamp;
  const country = geoData.country?.toUpperCase();
  const prevCountry = data.lastLocation.country?.toUpperCase();

  const currCoords = geoData.city?.latitude 
    ? { lat: geoData.city.latitude, lon: geoData.city.longitude }
    : null;

  const prevCoords = data.lastLocation.lat 
    ? { lat: data.lastLocation.lat, lon: data.lastLocation.lon }
    : null;

  const indicators = [];
  const vpnContext = isSuspectedVPN(decodedReq);

  // Считаем скорость ТОЛЬКО если у нас есть точные координаты городов
  if (currCoords && prevCoords && timeDiff > 0) {
    const velocity = calculateGeoVelocity(
      { ...prevCoords, timestamp: data.lastLocation.timestamp },
      { ...currCoords, timestamp: now },
      timeDiff
    );

    if (velocity > 900) {
      if (vpnContext) {
        indicators.push({ type: 'vpn_node_switch', detail: `VPN routing altered` }); // Low weight mapping expected
      } else {
        indicators.push({
          type: 'impossible_travel',
          detail: `Velocity ${velocity.toFixed(0)} km/h from ${prevCountry} to ${country}`,
        });
      }
    }
  } else if (!currCoords || !prevCoords) {
    // Если городов нет, используем консервативный таймаут для смены страны (1 час)
    if (country !== prevCountry && timeDiff < 3600000 && !vpnContext) {
      indicators.push({ type: 'rapid_country_switch_no_city', detail: `Country changed from ${prevCountry} to ${country} without city data in <1h` });
    }
  }

  const isMobile = isMobileUA(data.userAgent);
  const rapidThreshold = isMobile || vpnContext ? 300000 : 3600000;
  
  if (currCoords && prevCoords && country !== prevCountry && timeDiff < rapidThreshold) {
    indicators.push({
      type: 'rapid_country_switch',
      detail: `Geo bounce: ${prevCountry} to ${country} in ${(timeDiff/60000).toFixed(1)} min`,
      isMobile, 
    });
  }
  
  return indicators;
}

/**
 * Compares mid-session Browser Fingerprint integrity (UA, Canvas, WebGL, Screen).
 * Sudden shifts are massive indications of Token Hijacking or Bot rotations.
 * @param {string} sessionId - User token.
 * @param {Object} fingerprint - Request client context map.
 * @returns {Array} Extracted discrepancies as feature indicators.
 */
function checkFingerprintChange(sessionId, fingerprint) {
  const data = SESSION_DATA.get(sessionId);
  if (!data || !data.fingerprint || !fingerprint) return [];

  const indicators = [];
  const prev = data.fingerprint;
  const curr = fingerprint;

  if (prev.userAgent && curr.userAgent && prev.userAgent !== curr.userAgent) {
    indicators.push({ type: 'ua_changed', detail: 'User-Agent modified mid-session' });
  }
  
  if (prev.canvas && curr.canvas && prev.canvas !== curr.canvas) {
    indicators.push({ type: 'canvas_changed', detail: 'Canvas context shifted' });
  }
  
  if (prev.screen && curr.screen) {
    const widthDiff = Math.abs(prev.screen.width - curr.screen.width);
    const heightDiff = Math.abs(prev.screen.height - curr.screen.height);
    const widthChangePct = widthDiff / Math.max(prev.screen.width, 1);
    
    // FP Control: Minor browser resizing shouldn't trigger an anomaly
    if ((widthChangePct > 0.2 && widthDiff > 200) || heightDiff > 200) {
      indicators.push({
        type: 'screen_changed',
        detail: `Resolution drastic shift (${prev.screen.width}x${prev.screen.height} → ${curr.screen.width}x${curr.screen.height})`,
      });
    }
  }

  return indicators;
}

/**
 * Analyzes the request against the historical Session Map. Emits weighted vectors.
 * @param {Object} decodedReq - Standardized extraction object from Decoder.
 * @returns {Array} Risk match instances for engine evaluation.
 */
const IP_SESSION_MAP = new Map();

function check(decodedReq) {
  const sessionId = decodedReq.sessionId || `${decodedReq.ip}:${decodedReq.userAgent}`;
  if (!sessionId) return [];

  const now = Date.now();
  const data = SESSION_DATA.get(sessionId) || {
    firstSeen: now,
    ips: new Set(),
    userAgent: decodedReq.userAgent,
    lastLocation: null,
    fingerprint: null,
    errorCount: 0,
    lastErrorReset: now,
  };

  const indicators = [];

  const clientIp = decodedReq.ip;
  if (!IP_SESSION_MAP.has(clientIp)) IP_SESSION_MAP.set(clientIp, new Set());
  const ipSessions = IP_SESSION_MAP.get(clientIp);
  ipSessions.add(sessionId);

  // Ограничиваем размер Set, чтобы не забить память
  if (ipSessions.size > 100) {
    const oldestSession = ipSessions.values().next().value;
    ipSessions.delete(oldestSession);
  }

  // Если с одного IP идет больше 10 уникальных сессий за короткое время
  if (ipSessions.size > 10) {
    indicators.push({
      type: 'credential_stuffing_farm',
      detail: `IP ${clientIp} associated with ${ipSessions.size} unique sessions (possible botnet/stuffing)`
    });
  }

  const statusCode = decodedReq.statusCode || decodedReq._internalStatusCode; // Fallback from engine
  if (statusCode && (statusCode >= 400 || statusCode === 500)) {
    data.errorCount = (data.errorCount || 0) + 1;
    if (data.errorCount > 20) {
      indicators.push({
        type: 'fuzzing_error_spike',
        detail: `${data.errorCount} error responses in session (possible blind fuzzing)`
      });
    }
  }
  if (!data.lastErrorReset) data.lastErrorReset = now;
  // Сброс счетчика раз в 10 минут
  if (now - data.lastErrorReset > 600000) {
    data.errorCount = 0;
    data.lastErrorReset = now;
  }

  const referer = decodedReq.headers && (decodedReq.headers['referer'] || decodedReq.headers['origin']);
  const sensitivePaths = ['/api/payment', '/api/admin', '/api/password', '/login'];
  if (sensitivePaths.some(p => (decodedReq.path || '').includes(p))) {
    if (!referer) {
      indicators.push({ type: 'sensitive_no_referer', detail: 'Direct request to sensitive endpoint without Referer/Origin' });
    } else if (decodedReq.headers && decodedReq.headers['host'] && !referer.includes(decodedReq.headers['host'])) {
      indicators.push({ type: 'cross_origin_sensitive', detail: `Cross-origin request to sensitive endpoint from ${referer.substring(0, 30)}` });
    }
  }

  // --- 1. Request Lineage (Process Tree Analogue) ---
  if (!SESSION_GRAPHS.has(sessionId)) SESSION_GRAPHS.set(sessionId, []);
  const history = SESSION_GRAPHS.get(sessionId);
  const currentPath = decodedReq.path || '/';

  if (currentPath.startsWith('/api/') && !currentPath.includes('/public/')) {
    const hasUiReferer = history.some(p => !p.startsWith('/api/'));
    if (!hasUiReferer && history.length < 3) {
      indicators.push({ type: 'orphan_api_call', detail: 'API call without prior frontend navigation' });
    }
  }

  if (history.length > 2) {
    const lastTime = history[history.length - 1].ts;
    const timeDiff = now - lastTime;
    if (timeDiff < 200 && history[history.length - 1].path !== currentPath) {
      indicators.push({ type: 'rate_velocity', detail: 'Rapid cross-page navigation' });
    }
  }

  history.push({ path: currentPath, ts: now });
  if (history.length > 20) history.shift();

  // --- 2. Lateral Movement (BOLA / IDOR Detection) ---
  const accessMap = RESOURCE_ACCESS.get(sessionId) || {};
  const bodyObj = typeof decodedReq.body === 'object' && decodedReq.body !== null ? decodedReq.body : {};
  const allParams = { ...(decodedReq.query || {}), ...bodyObj };

  for (const [key, val] of Object.entries(allParams)) {
    const strVal = String(val);
    if (/^\d+$/.test(strVal) || /^[0-9a-f]{8}-[0-9a-f]{4}/i.test(strVal)) {
      if (!accessMap[key]) accessMap[key] = new Set();
      if (accessMap[key].size < 10) {
        accessMap[key].add(strVal);
      }
      
      if (accessMap[key].size > 5) {
        indicators.push({ type: 'lateral_movement', detail: `Accessed ${accessMap[key].size}+ unique IDs for param "${key}"` });
      }
    }
  }
  RESOURCE_ACCESS.set(sessionId, accessMap);

  if (decodedReq.geoip && typeof decodedReq.geoip === 'object') {
    const geoAlerts = checkGeoVelocity(sessionId, decodedReq.geoip, decodedReq);
    indicators.push(...geoAlerts);
    data.lastLocation = {
      country: decodedReq.geoip.country,
      lat: decodedReq.geoip.city?.latitude,
      lon: decodedReq.geoip.city?.longitude,
      timestamp: now,
    };
  }

  if (decodedReq.fingerprint && typeof decodedReq.fingerprint === 'object') {
    const fpAlerts = checkFingerprintChange(sessionId, decodedReq.fingerprint);
    indicators.push(...fpAlerts);
    data.fingerprint = decodedReq.fingerprint;
  }

  if (data.ips.size < 20) {
    data.ips.add(decodedReq.ip);
  }
  if (data.ips.size > 10) {
    indicators.push({
      type: 'session_ip_flood',
      detail: `Session shared across ${data.ips.size}+ unique IPs`,
    });
  }

  SESSION_DATA.set(sessionId, data);
  if (SESSION_DATA.size > MAX_SESSIONS) _cleanup();

  if (indicators.length > 0) {
    const matches = indicators.map(ind => ({
      rule: 'session_anomaly',
      tags: ['fraud', 'session_takeover'],
      severity: ind.type === 'impossible_travel' || ind.type === 'session_ip_flood' ? 'high' : 'medium',
      category: 'session-anomaly',
      description: ind.detail,
    }));
    return matches;
  }

  return [];
}

/**
 * Triggers LRU boundaries to prevent the Map() from consuming excessive OS RAM limits.
 */
function _cleanup() {
  const cutoff = Date.now() - MAX_SESSION_AGE;
  for (const [key, value] of SESSION_DATA.entries()) {
    if (value.firstSeen < cutoff) {
      SESSION_DATA.delete(key);
      SESSION_GRAPHS.delete(key);
      RESOURCE_ACCESS.delete(key);
    }
  }
}

setInterval(_cleanup, 300000).unref(); // Run every 5 minutes

module.exports = { check, checkGeoVelocity, checkFingerprintChange, CITY_COORDS };
