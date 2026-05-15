'use strict';

// Security headers (CSP, HSTS, Permissions-Policy, etc.) — built-in helmet.js alternative

const DEFAULTS = {
  contentSecurityPolicy: {
    enabled: true,
    directives: {
      'default-src': ["'self'"], 'script-src': ["'self'"],
      'style-src': ["'self'", "'unsafe-inline'"],
      'img-src': ["'self'", 'data:', 'https:'], 'font-src': ["'self'"],
      'connect-src': ["'self'"], 'frame-ancestors': ["'none'"],
      'base-uri': ["'self'"], 'form-action': ["'self'"], 'object-src': ["'none'"],
    },
  },
  hsts: { enabled: true, maxAge: 31536000, includeSubDomains: true, preload: false },
  nosniff: true,
  frameOptions: 'DENY',
  xssProtection: '0',
  referrerPolicy: 'strict-origin-when-cross-origin',
  dnsPrefetchControl: 'off',
  permittedCrossDomainPolicies: 'none',
  downloadOptions: 'noopen',
  permissionsPolicy: {
    enabled: true,
    features: { camera: [], microphone: [], geolocation: [], payment: [], usb: [], 'interest-cohort': [] },
  },
  crossOriginEmbedderPolicy: 'require-corp',
  crossOriginOpenerPolicy: 'same-origin',
  crossOriginResourcePolicy: 'same-origin',
  removeHeaders: ['X-Powered-By', 'Server'],
};

function buildCSP(d) { return Object.entries(d).map(([k, v]) => `${k} ${Array.isArray(v) ? v.join(' ') : v}`).join('; '); }
function buildPermissions(f) { return Object.entries(f).map(([k, a]) => a.length ? `${k}=(${a.join(' ')})` : `${k}=()`).join(', '); }

// Schema-based config builder to prevent prototype pollution / config injection
function applyConfig(defaults, user) {
  if (!user || typeof user !== 'object') return { ...defaults };
  const conf = { ...defaults };
  
  if (user.contentSecurityPolicy) {
    conf.contentSecurityPolicy = { ...defaults.contentSecurityPolicy, ...user.contentSecurityPolicy };
    if (user.contentSecurityPolicy.directives) {
      conf.contentSecurityPolicy.directives = { 
        ...defaults.contentSecurityPolicy.directives, 
        ...user.contentSecurityPolicy.directives 
      };
      // Sanitize directives keys against known list if strictly needed, or trust defaults + explicit user map.
    }
  }

  if (user.hsts) conf.hsts = { ...defaults.hsts, ...user.hsts };
  if (user.permissionsPolicy) {
    conf.permissionsPolicy = { ...defaults.permissionsPolicy, ...user.permissionsPolicy };
    if (user.permissionsPolicy.features) {
      conf.permissionsPolicy.features = {
        ...defaults.permissionsPolicy.features,
        ...user.permissionsPolicy.features
      };
    }
  }

  // Copy primitives
  const primitives = [
    'nosniff', 'frameOptions', 'xssProtection', 'referrerPolicy', 
    'dnsPrefetchControl', 'permittedCrossDomainPolicies', 'downloadOptions',
    'crossOriginEmbedderPolicy', 'crossOriginOpenerPolicy', 'crossOriginResourcePolicy'
  ];
  for (const p of primitives) {
    if (user[p] !== undefined) conf[p] = user[p];
  }

  if (Array.isArray(user.removeHeaders)) conf.removeHeaders = user.removeHeaders;

  return conf;
}

const crypto = require('crypto');

function createMiddleware(userConfig = {}) {
  const c = applyConfig(DEFAULTS, userConfig);
  return function securityHeaders(req, res, next) {
    if (c.contentSecurityPolicy?.enabled) {
      const nonce = crypto.randomBytes(16).toString('base64');
      res.locals = res.locals || {};
      res.locals.cspNonce = nonce;
      
      const directives = JSON.parse(JSON.stringify(c.contentSecurityPolicy.directives));
      if (directives['script-src']) {
        directives['script-src'] = directives['script-src'].filter(v => v !== "'unsafe-inline'");
        directives['script-src'].push(`'nonce-${nonce}'`);
      }
      res.setHeader('Content-Security-Policy', buildCSP(directives));
    }

    if (c.contentSecurityPolicy?.reportUri) {
      res.setHeader('Report-To', JSON.stringify({
        group: 'csp-violations',
        max_age: 10886400,
        endpoints: [{ url: c.contentSecurityPolicy.reportUri }]
      }));
    }

    if (c.hsts?.enabled) {
      let v = `max-age=${c.hsts.maxAge}`; if (c.hsts.includeSubDomains) v += '; includeSubDomains'; if (c.hsts.preload) v += '; preload';
      res.setHeader('Strict-Transport-Security', v);
    }
    if (c.nosniff) res.setHeader('X-Content-Type-Options', 'nosniff');
    if (c.frameOptions) res.setHeader('X-Frame-Options', c.frameOptions);
    if (c.xssProtection !== false) res.setHeader('X-XSS-Protection', c.xssProtection || '0');
    if (c.referrerPolicy) res.setHeader('Referrer-Policy', c.referrerPolicy);
    if (c.dnsPrefetchControl) res.setHeader('X-DNS-Prefetch-Control', c.dnsPrefetchControl);
    if (c.permittedCrossDomainPolicies) res.setHeader('X-Permitted-Cross-Domain-Policies', c.permittedCrossDomainPolicies);
    if (c.downloadOptions) res.setHeader('X-Download-Options', c.downloadOptions);
    if (c.permissionsPolicy?.enabled) res.setHeader('Permissions-Policy', buildPermissions(c.permissionsPolicy.features));
    if (c.crossOriginEmbedderPolicy) res.setHeader('Cross-Origin-Embedder-Policy', c.crossOriginEmbedderPolicy);
    if (c.crossOriginOpenerPolicy) res.setHeader('Cross-Origin-Opener-Policy', c.crossOriginOpenerPolicy);
    if (c.crossOriginResourcePolicy) res.setHeader('Cross-Origin-Resource-Policy', c.crossOriginResourcePolicy);
    if (c.removeHeaders) c.removeHeaders.forEach(h => res.removeHeader(h));
    
    if (typeof next === 'function') next();
  };
}

module.exports = { createMiddleware, DEFAULTS, buildCSP, buildPermissions };
