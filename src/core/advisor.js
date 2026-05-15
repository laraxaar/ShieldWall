'use strict';

/**
 * @file advisor.js
 * @description Analyzes security events and generates actionable advice for developers.
 */

class Advisor {
  static suggest(event) {
    const suggestions = [];

    // Rule-based suggestions
    if (event.category === 'sqli') {
      suggestions.push('🚨 Use parameterized queries (Prepared Statements) to prevent SQL Injection.');
      suggestions.push('🔍 Check for unvalidated inputs in database queries on this endpoint.');
    }

    if (event.category === 'xss') {
      suggestions.push('🛡️ Implement a strict Content Security Policy (CSP) header.');
      suggestions.push('✨ Sanitize all user-generated content before rendering it in the DOM.');
    }

    if (event.category === 'traversal') {
      suggestions.push('📁 Avoid passing user input directly to filesystem APIs.');
      suggestions.push('✅ Use a whitelist of allowed files or a chroot-like jail.');
    }

    if (event.category === 'bot') {
      suggestions.push('🤖 Consider adding a CAPTCHA or rate-limiting to this sensitive route.');
      suggestions.push('🕵️ Monitor for unusual traffic volume from this IP range.');
    }

    // Structural suggestions
    if (event.analysis?.features?.encodingLayers > 2) {
      suggestions.push('🎭 Detected multiple encoding layers. This is often used to bypass WAFs.');
    }

    if (event.analysis?.features?.specialCharDensity > 0.4) {
      suggestions.push('☣️ High density of special characters detected. Check for command injection or obfuscation.');
    }

    return suggestions;
  }
}

module.exports = Advisor;
