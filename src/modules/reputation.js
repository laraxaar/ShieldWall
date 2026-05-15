'use strict';

/**
 * @file reputation.js
 * @description Behavioral IP & Fingerprint Reputation Tracking Module.
 * 
 * ROLE IN ARCHITECTURE:
 * Provides the "Memory" for the WAF. Tracks the history of specific identities to 
 * detect drift, calculate statistical rarity, and apply time-decayed penalties.
 * 
 * DATA FLOW:
 * [fingerprinter.js] -> `recordFingerprint()` -> Updates global popularity counts -> 
 * [engine.js] -> `getReputation()` -> Influences the Risk Aggregation Circuit Breaker.
 * 
 * CRITICAL FALSE POSITIVE (FP) MITIGATION:
 * - Exponential Decay: Older security incidents lose their impact over time.
 * - Cold-Start Protection: Rarity scores only trigger after 100 samples are collected.
 * - LRU Pruning: Automatically evicts stale data to prevent memory exhaustion (OOM).
 */
class FingerprintTracker {
    constructor(ttlMs = 60000, maxHistory = 5) {
        this.history = new Map(); // IP -> [{fp, ts}]
        this.popularity = new Map(); // FP -> count
        this._totalSeen = 0; 
        this._lastDecayAt = 0; // FIX: BUG_8 — track decay timing
        this.ttlMs = ttlMs;
        this.maxHistory = maxHistory;
        
        this._cleanupTimer = setInterval(() => this.cleanup(), 300000).unref();
    }

    recordFingerprint(fp) {
        this._totalSeen++;
        this.popularity.set(fp, (this.popularity.get(fp) || 0) + 1);
    }

    getRarityScore(fp) {
        if (this._totalSeen < 100) return 0; 
        
        const count = this.popularity.get(fp) || 0;
        const frequency = count / this._totalSeen;

        if (frequency < 0.001) return 25; 
        if (frequency < 0.01) return 15;  
        if (frequency < 0.05) return 5;   
        return 0; 
    }

    trackDrift(ip, fp) {
        const now = Date.now();
        if (!this.history.has(ip)) this.history.set(ip, []);
        
        const userHistory = this.history.get(ip);
        userHistory.push({ fp, ts: now });

        const timeWindow = userHistory.filter(h => now - h.ts < this.ttlMs);
        const trimmed = timeWindow.slice(-this.maxHistory); 
        this.history.set(ip, trimmed);

        const uniqueFps = new Set(trimmed.map(h => h.fp)).size;
        if (uniqueFps <= 1) return 0;

        const driftScore = ((uniqueFps - 1) / (this.maxHistory - 1)) * 50;
        return Math.round(Math.min(50, driftScore));
    }

    /**
     * Periodic cleanup and exponential decay.
     * FIX: BUG_8 — added timing guard to prevent rapid multiple decays
     */
    cleanup() {
        const now = Date.now();
        
        // 1. History cleanup
        for (const [ip, hist] of this.history) {
            const valid = hist.filter(h => now - h.ts < this.ttlMs);
            if (valid.length === 0) this.history.delete(ip);
            else this.history.set(ip, valid);
        }

        // 2. Popularity decay
        const ONE_HOUR = 3600000;
        if (this._totalSeen > 1000000 && (now - this._lastDecayAt > ONE_HOUR)) {
            for (const [fp, count] of this.popularity) {
                const newCount = Math.floor(count / 2);
                if (newCount === 0) this.popularity.delete(fp);
                else this.popularity.set(fp, newCount);
            }
            this._totalSeen = Math.floor(this._totalSeen / 2);
            this._lastDecayAt = now;
            console.info('[reputation] Popularity decay applied, new total:', this._totalSeen);
        }
    }

    destroy() {
        if (this._cleanupTimer) clearInterval(this._cleanupTimer);
    }
}

const fingerprintTracker = new FingerprintTracker();

module.exports = { FingerprintTracker, fingerprintTracker };

// === EXPORTS ===
/**
 * @typedef {Object} ReputationModule
 * @property {FingerprintTracker} FingerprintTracker - The class definition
 * @property {FingerprintTracker} fingerprintTracker - Singleton instance
 */
