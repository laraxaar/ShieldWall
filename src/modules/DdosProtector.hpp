#ifndef DDOS_PROTECTOR_HPP
#define DDOS_PROTECTOR_HPP

/**
 * @file DdosProtector.hpp
 * @brief Application-Layer DDoS & Slowloris Mitigation Module (C++17 port).
 *
 * MIGRATED FROM: ddos-protection.js -> DdosProtector
 *
 * KEY DESIGN DECISIONS vs JS:
 * - JS used two separate module-level Maps (CONNECTION_TRACKER,
 *   SLOWLORIS_TRACKER) and a promise-chain lock per IP (TRACKER_LOCKS).
 *   Here, both trackers live inside the class protected by a single
 *   std::shared_mutex — giving lock-free concurrent reads.
 * - OOM guard (BUG_37): maxTrackerSize cap with oldest-entry eviction.
 * - Header validation (BUG_40): only std::string scalar header values
 *   are accepted — prototype pollution via nested objects is impossible
 *   in C++, so the check simplifies to size/key validation.
 * - IP validation (BUG_38): same regex-based isValidIP() used everywhere.
 * - Whitelist stored in std::unordered_set<std::string> for O(1) lookup.
 */

#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <shared_mutex>
#include <atomic>
#include <chrono>

// ─── Public result type ────────────────────────────────────────────────────

struct DdosMatch {
    std::string rule;
    std::string severity;   ///< "critical" | "high"
    std::string category;
    std::string description;
    struct Pattern {
        std::string name;
        std::string matched;
    };
    std::vector<Pattern> matchedPatterns;
};

// ─── Decoded request surface (mirrors JS decodedReq) ───────────────────────

struct DecodedRequest {
    std::string ip;
    std::unordered_map<std::string,std::string> headers;
    std::unordered_map<std::string,std::string> query;
    int64_t contentLength = 0;   ///< parsed from Content-Length header
};

// ─── DdosProtector ────────────────────────────────────────────────────────

/**
 * @class DdosProtector
 * @brief Evaluates requests for L7 volumetric / Slowloris / header-bomb attacks.
 *
 * MIGRATED FROM: ddos-protection.js -> module-level check()
 */
class DdosProtector {
public:
    struct Options {
        size_t  maxConnectionsPerIp = 300;         ///< Shifted from 100 to 300 (NAT/SPA FP fix)
        size_t  maxHeaderBytes      = 8192;
        size_t  maxQueryParams      = 50;
        int64_t maxBodyBytes        = 100LL * 1024 * 1024;  ///< 100 MB
        int64_t connectionWindowMs  = 60'000;
        int64_t slowlorisTimeoutMs  = 10'000;
        size_t  maxTrackerSize      = 10'000;       ///< BUG_37 OOM guard
    };

    explicit DdosProtector(const Options& opts = Options{});
    ~DdosProtector();

    /**
     * @brief Evaluate a decoded request and return any DDoS matches.
     * @param req Decoded request surface.
     * @return Non-empty vector when a threat is detected.
     *
     * MIGRATED FROM: ddos-protection.js -> check()
     */
    std::vector<DdosMatch> check(const DecodedRequest& req);

    // ── Whitelist management ─────────────────────────────────────────────────
    void addToWhitelist   (const std::string& ip);
    void removeFromWhitelist(const std::string& ip);
    bool isWhitelisted    (const std::string& ip) const;

    // ── Metrics ──────────────────────────────────────────────────────────────
    struct Metrics {
        std::atomic<size_t> blockedCount{0};
        size_t connectionTrackerSize() const;
        size_t slowlorisTrackerSize()  const;
    };
    const Metrics& metrics() const { return metrics_; }

    /** Periodic GC — sweep expired windows. Call from a timer thread. */
    void gc();

private:
    // ── Internal tracker entries ─────────────────────────────────────────────
    struct ConnEntry  { std::deque<int64_t> requests; };
    struct SlowEntry  { int64_t lastActivity; };

    Options opts_;
    mutable std::shared_mutex mu_;

    std::unordered_map<std::string, ConnEntry>  connTracker_;
    std::unordered_map<std::string, SlowEntry>  slowTracker_;
    std::unordered_set<std::string>             whitelist_;

    Metrics metrics_;

    // ── Internal helpers ─────────────────────────────────────────────────────
    static bool isValidIP(const std::string& ip);
    std::vector<DdosMatch> checkSlowloris   (const DecodedRequest& req, int64_t now);
    std::vector<DdosMatch> checkConnFlood   (const DecodedRequest& req, int64_t now);

    void evictOldestConn_locked();
    void evictOldestSlow_locked();
};

#endif // DDOS_PROTECTOR_HPP
