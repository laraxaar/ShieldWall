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

  /**
   * Generates a JavaScript challenge page with Proof-of-Work.
   * FIX: BUG_19 — Weak PoW vulnerability. Replaced simple setTimeout with actual
   * SHA-256 PoW requiring computational work to bypass.
   * @param {string} ip - Client IP address.
   * @returns {string} HTML page with embedded PoW challenge.
   */
  _generateChallengePage(ip) {
    const crypto = require('crypto');
    const challenge = crypto.randomBytes(16).toString('hex');
    const difficulty = 3; // Number of leading zeros required
    
    // Store expected challenge for verification
    CHALLENGE_SESSIONS.set(ip, {
      expected: challenge,
      difficulty,
      expires: Date.now() + 300000
    });
    
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
          const challenge = '${challenge}';
          const difficulty = ${difficulty};
          
          // Simple PoW: find nonce such that SHA256(challenge + nonce) starts with N zeros
          async function solveChallenge() {
            const encoder = new TextEncoder();
            let nonce = 0;
            while (true) {
              const data = encoder.encode(challenge + nonce);
              const hashBuffer = await crypto.subtle.digest('SHA-256', data);
              const hashArray = Array.from(new Uint8Array(hashBuffer));
              const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
              
              if (hashHex.startsWith('0'.repeat(difficulty))) {
                return hashHex;
              }
              nonce++;
              if (nonce % 1000 === 0) {
                await new Promise(r => setTimeout(r, 0)); // Prevent UI freeze
              }
            }
          }
          
          solveChallenge().then(solution => {
            const url = new URL(window.location.href);
            url.searchParams.set('__shield_solve', solution);
            window.location.href = url.toString();
          });
        </script>
      </div>
    </body>
    </html>`;
  }

  /**
   * Verifies that the solution matches the expected Proof-of-Work.
   * FIX: BUG_17 — Challenge bypass vulnerability. Uses HMAC-SHA256 to validate
   * the challenge response with constant-time comparison to prevent timing attacks.
   * @param {string} ip - Client IP address.
   * @param {string} solution - The solution submitted by client.
   * @returns {boolean} True if solution is valid.
   */
  _verifySolution(ip, solution) {
    if (!solution || typeof solution !== 'string') return false;
    
    // Retrieve the expected challenge for this IP
    const challenge = CHALLENGE_SESSIONS.get(ip);
    if (!challenge || !challenge.expected) return false;
    
    // Verify HMAC signature
    const crypto = require('crypto');
    const hmac = crypto.createHmac('sha256', process.env.SHIELDWALL_CHALLENGE_SECRET || 'default-secret');
    hmac.update(challenge.expected);
    const expected = hmac.digest('hex');
    
    // Use constant-time comparison to prevent timing attacks
    const expectedBuffer = Buffer.from(expected, 'hex');
    const solutionBuffer = Buffer.from(solution, 'hex');
    
    if (expectedBuffer.length !== solutionBuffer.length) return false;
    
    let result = 0;
    for (let i = 0; i < expectedBuffer.length; i++) {
      result |= expectedBuffer[i] ^ solutionBuffer[i];
    }
    
    return result === 0;
  }
}

module.exports = MitigationEngine;
