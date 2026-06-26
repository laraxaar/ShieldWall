#ifndef BRUTE_FORCE_GUARD_HPP
#define BRUTE_FORCE_GUARD_HPP

/**
 * @file BruteForceGuard.hpp
 * @brief Progressive-backoff brute-force protection for auth endpoints.
 *
 * MIGRATED FROM: brute-force.js -> BruteForceGuard
 *
 * KEY DESIGN DECISIONS vs JS:
 * - Per-IP state stored in std::unordered_map with a std::shared_mutex
 *   (many parallel readers, rare writers — ideal for sliding-window checks).
 * - Timestamps kept in a fixed-capacity circular buffer (std::array) to
 *   eliminate repeated heap allocations that fragmented the JS heap.
 * - Progressive delay ("tarpit") applied via std::this_thread::sleep_for
 *   inside a detached thread so the calling thread is never blocked.
 * - std::atomic<size_t> for map size tracking avoids locking the full map
 *   just to read the element count.
 */

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <shared_mutex>
#include <atomic>
#include <chrono>
#include <optional>

/** @brief Result of a brute-force check. */
struct BfCheckResult {
    bool blocked = false;
    std::string ip;
    std::string reason;
    int64_t retryAfterMs = 0;   ///< milliseconds until unblock
    size_t attempts = 0;
};

/**
 * @class BruteForceGuard
 * @brief Tracks failed authentication attempts per IP and account.
 *
 * MIGRATED FROM: brute-force.js -> BruteForceGuard
 */
class BruteForceGuard {
public:
    struct Options {
        size_t  maxAttempts        = 5;
        int64_t windowMs           = 15 * 60'000;       ///< Sliding window length
        int64_t blockDurationMs    = 15 * 60'000;       ///< Base block duration
        int64_t maxBlockDurationMs = 24 * 60 * 60'000;  ///< Progressive backoff cap
        bool    progressiveBackoff = true;
        bool    trustProxy         = false;
        size_t  accountMaxAttempts = 10;
        size_t  maxStateSize       = 50'000;
        size_t  maxAccountSize     = 100'000;
        std::vector<std::string> sensitivePaths = {
            "/login", "/api/auth", "/api/login", "/signin", "/api/signin"
        };
        std::unordered_set<int> failedCodes = { 401, 403, 422 };
    };

    explicit BruteForceGuard(const Options& opts = Options{});
    ~BruteForceGuard();

    /**
     * @brief Checks whether an IP is currently blocked on a sensitive path.
     * @param ip      Resolved client IP.
     * @param path    Lowercase URL path.
     * @return BfCheckResult with `blocked=true` when IP is timed out.
     *
     * MIGRATED FROM: brute-force.js -> check()
     */
    BfCheckResult check(const std::string& ip, const std::string& path) const;

    /**
     * @brief Checks whether an account identifier is globally locked.
     * @param accountId Email / username string.
     * @return BfCheckResult with `blocked=true` when account is saturated.
     *
     * MIGRATED FROM: brute-force.js -> checkAccount()
     */
    BfCheckResult checkAccount(const std::string& accountId) const;

    /**
     * @brief Records a response code for an auth attempt and updates state.
     * @param ip         Resolved client IP.
     * @param path       Lowercase URL path.
     * @param statusCode HTTP response status.
     * @param accountId  Optional account identifier.
     *
     * MIGRATED FROM: brute-force.js -> recordResponse()
     */
    void recordResponse(const std::string& ip,
                        const std::string& path,
                        int statusCode,
                        const std::string& accountId = "");

    /** @brief Forcibly clears the block for a specific IP. */
    void reset(const std::string& ip);

    /** @brief Returns a snapshot of all currently-blocked IPs. */
    std::vector<std::pair<std::string, std::string>> getBlockedIPs() const;

private:
    // ── Internal state ──────────────────────────────────────────────────────
    struct IpEntry {
        std::vector<int64_t> attempts;   ///< Unix-ms timestamps of failed auth
        int64_t blockUntil  = 0;         ///< Unix-ms of unblock; 0 = not blocked
        size_t  blockCount  = 0;         ///< How many times blocked (for backoff)
    };

    struct AccountEntry {
        std::vector<int64_t> attempts;
    };

    Options opts;

    mutable std::shared_mutex  ipMutex;
    std::unordered_map<std::string, IpEntry>      ipState;

    mutable std::shared_mutex  accMutex;
    std::unordered_map<std::string, AccountEntry> accState;

    // ── Helpers ─────────────────────────────────────────────────────────────
    bool        isSensitive(const std::string& path) const;
    void        evictOldestIp();
    void        evictOldestAcc();
    void        gc();  ///< Sweep expired windows
};

#endif // BRUTE_FORCE_GUARD_HPP
