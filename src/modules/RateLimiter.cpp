/**
 * @file RateLimiter.cpp
 * @brief Sliding-window per-IP rate limiter — C++17 implementation.
 *
 * MIGRATED FROM: rate-limiter.js -> RateLimiter / MemoryStore
 */

#include "RateLimiter.hpp"

#include <algorithm>
#include <regex>

// ─── Helpers ────────────────────────────────────────────────────────────────

static int64_t nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

// ─── MemoryStore ─────────────────────────────────────────────────────────────

MemoryStore::MemoryStore(int64_t windowMs, size_t maxKeys)
    : windowMs_(windowMs), maxKeys_(maxKeys)
{}

/**
 * MIGRATED FROM: rate-limiter.js -> MemoryStore.increment()
 * FIX BUG_22 — OOM guard: evict oldest when at capacity.
 * FIX BUG_16 — Atomic update under exclusive lock (no promise-chain needed).
 */
size_t MemoryStore::increment(const std::string& key) {
    const int64_t now    = nowMs();
    const int64_t cutoff = now - windowMs_;

    std::unique_lock lk(mu_);

    // OOM guard
    if (requests_.size() >= maxKeys_) evictOldest_locked();

    auto& dq = requests_[key];
    // Slide the window: pop expired front entries (O(1) per pop)
    while (!dq.empty() && dq.front() <= cutoff) dq.pop_front();
    dq.push_back(now);

    return dq.size();
}

/**
 * MIGRATED FROM: rate-limiter.js -> MemoryStore.block()
 */
void MemoryStore::block(const std::string& key, int64_t ms) {
    std::unique_lock lk(mu_);
    blocked_[key] = nowMs() + ms;
}

/**
 * MIGRATED FROM: rate-limiter.js -> MemoryStore.isBlocked()
 * @returns 0 if not blocked, else blockUntil-ms timestamp.
 */
int64_t MemoryStore::isBlocked(const std::string& key) {
    const int64_t now = nowMs();
    std::shared_lock lk(mu_);
    auto it = blocked_.find(key);
    if (it == blocked_.end()) return 0;
    if (now < it->second) return it->second;
    // Expired — upgrade to exclusive and erase
    lk.unlock();
    std::unique_lock ulk(mu_);
    blocked_.erase(key);
    return 0;
}

void MemoryStore::unblock(const std::string& key) {
    std::unique_lock lk(mu_);
    blocked_.erase(key);
    requests_.erase(key);
}

/**
 * MIGRATED FROM: rate-limiter.js -> MemoryStore.cleanup()
 * FIX BUG_25 — No separate lock-map to clean; shared_mutex handles it all.
 */
void MemoryStore::cleanup() {
    const int64_t cutoff = nowMs() - windowMs_;
    const int64_t now    = nowMs();

    std::unique_lock lk(mu_);

    for (auto it = requests_.begin(); it != requests_.end(); ) {
        auto& dq = it->second;
        while (!dq.empty() && dq.front() <= cutoff) dq.pop_front();
        if (dq.empty()) it = requests_.erase(it);
        else            ++it;
    }
    for (auto it = blocked_.begin(); it != blocked_.end(); ) {
        if (now >= it->second) it = blocked_.erase(it);
        else                   ++it;
    }
}

std::vector<std::pair<std::string,int64_t>> MemoryStore::blockedIPs() const {
    const int64_t now = nowMs();
    std::shared_lock lk(mu_);
    std::vector<std::pair<std::string,int64_t>> out;
    for (const auto& [k, u] : blocked_)
        if (now < u) out.emplace_back(k, u);
    return out;
}

void MemoryStore::clear() {
    std::unique_lock lk(mu_);
    requests_.clear();
    blocked_.clear();
}

void MemoryStore::evictOldest_locked() {
    if (!requests_.empty()) requests_.erase(requests_.begin());
    if (!blocked_.empty())  blocked_.erase(blocked_.begin());
}

// ─── RateLimiter ─────────────────────────────────────────────────────────────

RateLimiter::RateLimiter(const Options& opts)
    : opts_(opts)
{
    store_ = opts_.store
        ? opts_.store
        : std::make_shared<MemoryStore>(opts_.windowMs);
}

RateLimiter::~RateLimiter() = default;

/**
 * MIGRATED FROM: rate-limiter.js -> RateLimiter.check()
 * FIX BUG_23 — IP is already validated by the caller (WafEngine) before
 * arriving here; no XFF parsing at this layer for clean separation of concerns.
 */
RlCheckResult RateLimiter::check(const std::string& ip, const std::string& path) {
    RlCheckResult res;
    res.ip     = ip;
    res.maxReqs = opts_.max;

    // Skip paths bypass rate limiting
    for (const auto& skip : opts_.skipPaths)
        if (path.rfind(skip, 0) == 0)
            return res;  // limited=false, remaining=0 (caller ignores remaining when not limited)

    const int64_t now = nowMs();

    // Check if already blocked
    const int64_t blockUntil = store_->isBlocked(ip);
    if (blockUntil > 0) {
        res.limited      = true;
        res.count        = opts_.max;
        res.retryAfterMs = blockUntil - now;
        return res;
    }

    const size_t count = store_->increment(ip);
    res.count = count;

    if (count > opts_.max) {
        store_->block(ip, opts_.blockDuration);
        res.limited      = true;
        res.retryAfterMs = opts_.blockDuration;
    } else {
        res.remaining = opts_.max - count;
    }
    return res;
}

void RateLimiter::blockIP(const std::string& ip, int64_t ms) {
    store_->block(ip, ms > 0 ? ms : opts_.blockDuration);
}

void RateLimiter::unblockIP(const std::string& ip) {
    store_->unblock(ip);
}

std::vector<std::pair<std::string,int64_t>> RateLimiter::getBlockedIPs() const {
    return store_->blockedIPs();
}

/** MIGRATED FROM: rate-limiter.js -> setInterval cleanup callback */
void RateLimiter::gc() {
    store_->cleanup();
}

/**
 * MIGRATED FROM: rate-limiter.js -> _isValidIP()
 * FIX BUG_23 — IP format validation.
 */
bool RateLimiter::isValidIP(const std::string& ip) {
    if (ip.empty()) return false;
    static const std::regex ipv4(
        R"(^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$)");
    static const std::regex ipv6(
        R"(^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$)");
    return std::regex_match(ip, ipv4) || std::regex_match(ip, ipv6);
}
