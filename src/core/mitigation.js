'use strict';

/**
 * @file mitigation.js
 * @description Handles active mitigation: JS Challenges, Throttling, and feature downgrading.
 */

const CHALLENGE_SESSIONS = new Map();

class MitigationEngine {
  constructor(options = {}) {
    this.challengeTimeout = options.challengeTimeout || 300000; // 5 mins
  }

  /**
   * Checks if a request needs mitigation or has solved a challenge.
   * @returns {Object|null} Mitigation action or null if allowed.
   */
  process(req, res, event) {
    const ip = req.ip || req.connection.remoteAddress;
    const score = event.riskScore || 0;

    // 1. Check if session is already in "Challenge Solved" state
    if (CHALLENGE_SESSIONS.has(ip)) {
      const session = CHALLENGE_SESSIONS.get(ip);
      if (Date.now() < session.expires) return null; // Allowed
      CHALLENGE_SESSIONS.delete(ip);
    }

    // 2. High Risk: Hard Block (Handled by engine.js usually, but here for completeness)
    if (score >= 40) return { type: 'block', code: 403 };

    // 3. Medium-High Risk: JS Challenge
    if (score >= 15) {
      // Check if this is a challenge submission
      const url = new URL(req.url, 'http://localhost');
      if (url.searchParams.has('__shield_solve')) {
        const solution = url.searchParams.get('__shield_solve');
        if (this._verifySolution(ip, solution)) {
          CHALLENGE_SESSIONS.set(ip, { expires: Date.now() + 3600000 }); // 1 hour pass
          return { type: 'redirect', url: url.pathname };
        }
      }
      return { type: 'challenge', html: this._generateChallengePage(ip) };
    }

    // 4. Low-Medium Risk: Throttling (Slow down response)
    if (score >= 8) {
      return { type: 'throttle', delay: Math.min(score * 100, 3000) };
    }

    return null;
  }

  _generateChallengePage(ip) {
    const target = Date.now().toString(16); // Simple dynamic target
    return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>ShieldWall Security Check</title>
      <style>
        body { background: #0a0a0f; color: #e8e8ef; font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .card { background: #16161f; padding: 40px; border-radius: 16px; border: 1px solid rgba(255,255,255,0.1); text-align: center; max-width: 400px; }
        .spinner { border: 4px solid rgba(255,255,255,0.1); border-top: 4px solid #6366f1; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        h1 { font-size: 1.5rem; margin-bottom: 10px; color: #818cf8; }
        p { color: #8888a0; font-size: 0.9rem; line-height: 1.5; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>🛡️ ShieldWall Check</h1>
        <p>We've detected unusual activity. Please wait while we verify your browser...</p>
        <div class="spinner"></div>
        <script>
          // Simple PoW: Find a suffix that makes SHA-256 starts with '000'
          // For demo, we just wait 2 seconds and redirect
          setTimeout(() => {
            const url = new URL(window.location.href);
            url.searchParams.set('__shield_solve', '${target}');
            window.location.href = url.toString();
          }, 2000);
        </script>
      </div>
    </body>
    </html>`;
  }

  _verifySolution(ip, solution) {
    // In a real implementation, this would verify the PoW
    return !!solution;
  }
}

module.exports = MitigationEngine;
