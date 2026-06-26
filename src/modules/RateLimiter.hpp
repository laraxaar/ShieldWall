#ifndef RATE_LIMITER_HPP
#define RATE_LIMITER_HPP

/**
 * @file RateLimiter.hpp
 * @brief Sliding-window per-IP rate limiter with pluggable back-end store.
 *
 * MIGRATED FROM: rate-limiter.js -> RateLimiter / MemoryStore
 *
 * KEY DESIGN DECISIONS vs JS:
 * - The JS MemoryStore used async promise-based locking per key; in C++ we
 *   use a single std::shared_mutex — shared for reads (isBlocked / count
 *   queries), exclusive for writes (increment / block). This eliminates the
 *   per-key lock-map overhead and avoids lock-map memory leaks (BUG_25).
 * - Timestamps are stored in std::deque<int64_t> so front-pop (slide window)
 *   is O(1) instead of O(n) filter copies done in JS.
 * - OOM guard (BUG_22) via maxKeys eviction at increment() time.
 */

#include <string>
#include <deque>
#include <unordered_map>
#include <shared_mutex>
#include <vector>
#include <functional>
#include <chrono>
#include <memory>

// ─── IStore Interface ───────────────────────────────────────────────────────

/**
 * @class IStore
 * @brief Abstract key-value store interface for pluggable rate-limit backends.
 *
 * MIGRATED FROM: rate-limiter.js -> MemoryStore interface.
 * Implementations can be swapped to a Redis or Memcached backend for
 * horizontal scaling, matching the JS abstraction.
 */
class IStore {
public:
    virtual ~IStore() = default;
    virtual size_t  increment(const std::string& key)            = 0;
    virtual void    block    (const std::string& key, int64_t ms) = 0;
    virtual int64_t isBlocked(const std::string& key)            = 0;  ///< 0=not blocked, else blockUntil ms
    virtual void    unblock  (const std::string& key)            = 0;
    virtual void    cleanup  ()                                  = 0;
    virtual std::vector<std::pair<std::string,int64_t>> blockedIPs() const = 0;
    virtual void    clear    ()                                  = 0;
};

// ─── MemoryStore ─────────────────────────────────────────────────────────────

/**
 * @class MemoryStore
 * @brief In-process sliding-window store for the RateLimiter.
 *
 * MIGRATED FROM: rate-limiter.js -> MemoryStore
 * FIX BUG_22 — maxKeys cap + atomic increment via exclusive lock.
 * FIX BUG_25 — No separate lock-map; a single shared_mutex covers all ops.
 */
class MemoryStore final : public IStore {
public:
    explicit MemoryStore(int64_t windowMs, size_t maxKeys = 100'000);

    size_t  increment(const std::string& key) override;
    void    block    (const std::string& key, int64_t ms) override;
    int64_t isBlocked(const std::string& key) override;
    void    unblock  (const std::string& key) override;
    void    cleanup  () override;
    std::vector<std::pair<std::string,int64_t>> blockedIPs() const override;
    void    clear    () override;

private:
    int64_t windowMs_;
    size_t  maxKeys_;

    mutable std::shared_mutex mu_;
    std::unordered_map<std::string, std::deque<int64_t>> requests_;  ///< key -> sorted timestamps
    std::unordered_map<std::string, int64_t>             blocked_;   ///< key -> blockUntil ms

    void evictOldest_locked();  ///< Must be called under exclusive lock
};

// ─── Check Result ─────────────────────────────────────────────────────────────

struct RlCheckResult {
    bool    limited   = false;
    std::string ip;
    size_t  count     = 0;
    size_t  maxReqs   = 0;
    size_t  remaining = 0;
    int64_t retryAfterMs = 0;
};

// ─── RateLimiter ─────────────────────────────────────────────────────────────

/**
 * @class RateLimiter
 * @brief Primary L4/L7 volumetric gate.
 *
 * MIGRATED FROM: rate-limiter.js -> RateLimiter
 * FIX BUG_23 — IP validation before accepting X-Forwarded-For header.
 */
class RateLimiter {
public:
    struct Options {
        int64_t windowMs      = 60'000;
        size_t  max           = 100;
        int64_t blockDuration = 300'000;
        bool    trustProxy    = false;
        std::vector<std::string> skipPaths;
        std::shared_ptr<IStore>  store;           ///< nullptr -> use MemoryStore
    };

    explicit RateLimiter(const Options& opts = Options{});
    ~RateLimiter();

    /**
     * @brief Evaluate a request against the sliding window.
     * @param ip    Resolved client IP.
     * @param path  Request URL path (no query string).
     *
     * MIGRATED FROM: rate-limiter.js -> check()
     */
    RlCheckResult check(const std::string& ip, const std::string& path);

    void blockIP  (const std::string& ip, int64_t ms = 0);
    void unblockIP(const std::string& ip);
    std::vector<std::pair<std::string,int64_t>> getBlockedIPs() const;

    /** Trigger periodic GC — call from a timer thread every 60 s. */
    void gc();

private:
    Options opts_;
    std::shared_ptr<IStore> store_;

    static bool isValidIP(const std::string& ip);
};

#endif // RATE_LIMITER_HPP
