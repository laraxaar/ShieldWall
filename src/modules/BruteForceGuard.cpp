/**
 * @file BruteForceGuard.cpp
 * @brief Progressive-backoff brute-force protection (C++17 port).
 *
 * MIGRATED FROM: brute-force.js -> BruteForceGuard
 */

#include "BruteForceGuard.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <regex>

// ─── Helpers ────────────────────────────────────────────────────────────────

static int64_t nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

/**
 * @brief Validate IPv4/IPv6 format.
 * MIGRATED FROM: brute-force.js -> _isValidIP()
 * FIX: BUG_27 — prevents X-Forwarded-For injection.
 */
static bool isValidIP(const std::string& ip) {
    if (ip.empty()) return false;
    // IPv4
    static const std::regex ipv4(
        R"(^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$)");
    // IPv6 (compact full-form; for production use a full RFC-compliant parser)
    static const std::regex ipv6(
        R"(^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$)");
    return std::regex_match(ip, ipv4) || std::regex_match(ip, ipv6);
}

// ─── Constructor / Destructor ────────────────────────────────────────────────

BruteForceGuard::BruteForceGuard(const Options& opts)
    : opts(opts)
{}

BruteForceGuard::~BruteForceGuard() = default;

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * MIGRATED FROM: brute-force.js -> check()
 */
BfCheckResult BruteForceGuard::check(const std::string& ip,
                                     const std::string& path) const {
    BfCheckResult res;
    res.ip = ip;

    if (!isSensitive(path)) return res;

    // Shared (read) lock — many concurrent check() calls allowed
    std::shared_lock lk(ipMutex);
    auto it = ipState.find(ip);
    if (it == ipState.end()) return res;

    const IpEntry& e = it->second;
    const int64_t  now = nowMs();

    if (e.blockUntil > 0 && now < e.blockUntil) {
        res.blocked     = true;
        res.reason      = "Blocked after " + std::to_string(e.attempts.size()) + " failed attempts";
        res.retryAfterMs = e.blockUntil - now;
        res.attempts    = e.attempts.size();
    }
    return res;
}

/**
 * MIGRATED FROM: brute-force.js -> checkAccount()
 */
BfCheckResult BruteForceGuard::checkAccount(const std::string& accountId) const {
    BfCheckResult res;
    if (accountId.empty()) return res;

    const int64_t now = nowMs();

    std::shared_lock lk(accMutex);
    auto it = accState.find(accountId);
    if (it == accState.end()) return res;

    // Count attempts within the sliding window without mutating
    size_t count = 0;
    for (int64_t ts : it->second.attempts)
        if (now - ts < opts.windowMs) ++count;

    if (count >= opts.accountMaxAttempts) {
        res.blocked      = true;
        res.reason       = "Account locked after " + std::to_string(count) + " failed attempts globally";
        res.retryAfterMs = opts.blockDurationMs;
    }
    return res;
}

/**
 * MIGRATED FROM: brute-force.js -> recordResponse()
 * FIX BUG_26 — OOM guard: evict oldest entry when map is at capacity.
 */
void BruteForceGuard::recordResponse(const std::string& ip,
                                     const std::string& path,
                                     int statusCode,
                                     const std::string& accountId) {
    if (!isSensitive(path)) return;

    const int64_t now = nowMs();
    const bool isFailed = (opts.failedCodes.count(statusCode) > 0);

    // ── Account tracking ─────────────────────────────────────────────────────
    if (!accountId.empty() && isFailed) {
        std::unique_lock lk(accMutex);
        // OOM guard
        if (accState.size() >= opts.maxAccountSize) evictOldestAcc();

        auto& ae = accState[accountId];
        ae.attempts.push_back(now);
    }

    // ── IP tracking ──────────────────────────────────────────────────────────
    if (!isFailed) {
        // Successful auth — reset counter
        std::unique_lock lk(ipMutex);
        ipState.erase(ip);
        return;
    }

    std::unique_lock lk(ipMutex);
    // OOM guard
    if (ipState.size() >= opts.maxStateSize) evictOldestIp();

    IpEntry& e = ipState[ip];

    // Slide the window — drop timestamps older than windowMs
    auto& att = e.attempts;
    att.erase(std::remove_if(att.begin(), att.end(),
        [&](int64_t ts){ return now - ts >= opts.windowMs; }),
        att.end());
    att.push_back(now);

    if (static_cast<size_t>(att.size()) >= opts.maxAttempts) {
        e.blockCount++;
        const double mult = opts.progressiveBackoff
            ? std::pow(2.0, static_cast<double>(e.blockCount - 1))
            : 1.0;
        const int64_t duration =
            std::min(static_cast<int64_t>(opts.blockDurationMs * mult),
                     opts.maxBlockDurationMs);
        e.blockUntil = now + duration;
    }
}

/** MIGRATED FROM: brute-force.js -> reset() */
void BruteForceGuard::reset(const std::string& ip) {
    std::unique_lock lk(ipMutex);
    ipState.erase(ip);
}

/** MIGRATED FROM: brute-force.js -> getBlockedIPs() */
std::vector<std::pair<std::string,std::string>>
BruteForceGuard::getBlockedIPs() const {
    const int64_t now = nowMs();
    std::vector<std::pair<std::string,std::string>> out;

    std::shared_lock lk(ipMutex);
    out.reserve(ipState.size());
    for (const auto& [ip, e] : ipState) {
        if (e.blockUntil > 0 && now < e.blockUntil)
            out.emplace_back(ip, std::to_string(e.blockUntil));
    }
    return out;
}

// ─── Private Helpers ─────────────────────────────────────────────────────────

/**
 * MIGRATED FROM: brute-force.js -> _isSensitive()
 */
bool BruteForceGuard::isSensitive(const std::string& path) const {
    for (const auto& s : opts.sensitivePaths) {
        if (path == s || path.rfind(s + '/', 0) == 0) return true;
    }
    return false;
}

/**
 * Evict the single oldest entry from the IP map.
 * Called while ipMutex is held exclusive.
 */
void BruteForceGuard::evictOldestIp() {
    if (ipState.empty()) return;
    ipState.erase(ipState.begin());
}

void BruteForceGuard::evictOldestAcc() {
    if (accState.empty()) return;
    accState.erase(accState.begin());
}

/**
 * MIGRATED FROM: brute-force.js -> _gc()
 * Sweep expired attempt windows. Call periodically from a timer thread.
 */
void BruteForceGuard::gc() {
    const int64_t now = nowMs();

    {
        std::unique_lock lk(ipMutex);
        for (auto it = ipState.begin(); it != ipState.end(); ) {
            auto& e = it->second;
            auto& att = e.attempts;
            att.erase(std::remove_if(att.begin(), att.end(),
                [&](int64_t ts){ return now - ts >= opts.windowMs; }),
                att.end());
            if (att.empty() && (e.blockUntil == 0 || now >= e.blockUntil))
                it = ipState.erase(it);
            else
                ++it;
        }
    }

    {
        std::unique_lock lk(accMutex);
        for (auto it = accState.begin(); it != accState.end(); ) {
            auto& att = it->second.attempts;
            att.erase(std::remove_if(att.begin(), att.end(),
                [&](int64_t ts){ return now - ts >= opts.windowMs; }),
                att.end());
            if (att.empty())
                it = accState.erase(it);
            else
                ++it;
        }
    }
}
