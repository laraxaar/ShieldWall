#ifndef RECON_TRACKER_HPP
#define RECON_TRACKER_HPP

/**
 * @file ReconTracker.hpp
 * @brief Reconnaissance-to-Exploit Correlation Engine (C++17 port).
 *
 * MIGRATED FROM: recon-tracker.js -> ReconTracker
 *
 * ROLE IN ARCHITECTURE:
 * Acts as the WAF's long-term memory. Tracks IPs that exhibit scanner-like
 * behaviour (probing /.env, /wp-admin, etc.) and accumulates a "Taint" score.
 * When a tainted IP later attempts a subtle exploit on a critical endpoint,
 * WafEngine uses the historical taint to lower the blocking threshold,
 * implementing Kill-Chain interruption.
 *
 * KEY DESIGN DECISIONS vs JS:
 * - RECON_HISTORY (JS Map) -> std::unordered_map protected by std::shared_mutex.
 * - Scanner / sensitive-endpoint patterns compiled once as std::regex objects
 *   stored in static vectors (avoids repeated compilation on every call).
 * - Taint score uses std::atomic<int> so concurrent readers can query without
 *   a full exclusive lock; mutation (record update) takes an exclusive lock.
 * - Per-IP path ring-buffer capped at MAX_PATHS_PER_IP via std::deque::pop_front.
 * - OOM guard: MAX_RECON_ENTRIES eviction of oldest entry before insertion.
 */

#include <string>
#include <deque>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <atomic>
#include <chrono>
#include <regex>

class ReconTracker {
public:
    struct Options {
        size_t  maxEntries     = 20'000;
        int64_t ttlMs          = 3'600'000;   ///< 1 hour — recon intent memory
        size_t  maxPathsPerIp  = 10;
        int     scannerPenalty = 10;          ///< Score added for scanner-path hit
        int     errorPenalty   = 2;           ///< Score added for 404 / 403
    };

    explicit ReconTracker(const Options& opts = Options{});
    ~ReconTracker();

    /**
     * @brief Record an indicator of reconnaissance from an IP.
     * @param ip         Client IP (already validated).
     * @param path       Requested URI path.
     * @param statusCode HTTP status returned to client.
     *
     * MIGRATED FROM: recon-tracker.js -> recordReconAttempt()
     */
    void recordReconAttempt(const std::string& ip,
                            const std::string& path,
                            int statusCode);

    /**
     * @brief Retrieve the decayed taint score for an IP.
     * @return 0 if clean or TTL expired, otherwise accumulated score.
     *
     * MIGRATED FROM: recon-tracker.js -> getReputationTaint()
     */
    int getReputationTaint(const std::string& ip) const;

    /**
     * @brief Check whether a path is a sensitive Zero-Day target.
     *
     * MIGRATED FROM: recon-tracker.js -> isSensitiveTarget()
     */
    static bool isSensitiveTarget(const std::string& path);

    /** Periodic GC — sweep expired records. Call from a timer thread. */
    void gc();

private:
    struct IpRecord {
        int      score    = 0;
        int64_t  lastSeen = 0;  ///< Unix-ms
        std::deque<std::string> paths;
    };

    Options opts_;
    mutable std::shared_mutex mu_;
    std::unordered_map<std::string, IpRecord> history_;

    static const std::vector<std::regex>& scannerPatterns();
    static const std::vector<std::regex>& sensitiveEndpoints();
    void evictOldest_locked();
};

#endif // RECON_TRACKER_HPP
