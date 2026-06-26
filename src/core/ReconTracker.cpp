/**
 * @file ReconTracker.cpp
 * @brief Reconnaissance-to-Exploit Correlation Engine — C++17 implementation.
 *
 * MIGRATED FROM: recon-tracker.js -> ReconTracker
 */

#include "ReconTracker.hpp"

// ─── Time helper ────────────────────────────────────────────────────────────

static int64_t nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

// ─── Static pattern sets ─────────────────────────────────────────────────────

/**
 * MIGRATED FROM: recon-tracker.js -> SCANNER_PATTERNS
 * Compiled exactly once (Meyers-singleton) to avoid repeated regex compilation.
 */
const std::vector<std::regex>& ReconTracker::scannerPatterns() {
    static const std::vector<std::regex> patterns = {
        std::regex(R"(\.(env|git|htaccess|aws|ds_store))",
                   std::regex::icase | std::regex::ECMAScript),
        std::regex(R"((wp-admin|wp-login|phpmyadmin|adminer|xmlrpc))",
                   std::regex::icase | std::regex::ECMAScript),
        std::regex(R"(/(actuator|swagger|graphql|api-docs|\.well-known))",
                   std::regex::icase | std::regex::ECMAScript),
        std::regex(R"(\b(v1|v2)/(internal|debug|console|metrics)\b)",
                   std::regex::icase | std::regex::ECMAScript),
    };
    return patterns;
}

/**
 * MIGRATED FROM: recon-tracker.js -> SENSITIVE_ENDPOINTS
 */
const std::vector<std::regex>& ReconTracker::sensitiveEndpoints() {
    static const std::vector<std::regex> patterns = {
        std::regex(R"(/(auth|login|oauth|sso|api/token))",
                   std::regex::icase | std::regex::ECMAScript),
        std::regex(R"(/(admin|dashboard|config|settings))",
                   std::regex::icase | std::regex::ECMAScript),
        std::regex(R"(/api/v\d+/(payment|checkout|users|exec))",
                   std::regex::icase | std::regex::ECMAScript),
    };
    return patterns;
}

// ─── Constructor / Destructor ────────────────────────────────────────────────

ReconTracker::ReconTracker(const Options& opts) : opts_(opts) {}
ReconTracker::~ReconTracker() = default;

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * MIGRATED FROM: recon-tracker.js -> recordReconAttempt()
 */
void ReconTracker::recordReconAttempt(const std::string& ip,
                                      const std::string& path,
                                      int statusCode) {
    const int64_t now = nowMs();
    std::unique_lock lk(mu_);

    auto it = history_.find(ip);
    if (it == history_.end()) {
        // OOM guard: evict oldest before inserting
        if (history_.size() >= opts_.maxEntries) evictOldest_locked();

        history_[ip] = IpRecord{};
        it = history_.find(ip);
    }

    IpRecord& rec = it->second;
    rec.lastSeen  = now;

    // 1. Scanner-path hit → heavy penalty
    for (const auto& pat : scannerPatterns()) {
        if (std::regex_search(path, pat)) {
            rec.score += opts_.scannerPenalty;
            rec.paths.push_back(path);
            if (rec.paths.size() > opts_.maxPathsPerIp) rec.paths.pop_front();
            break;  // one pattern match is enough for a single request
        }
    }

    // 2. 404 / 403 directory-bruteforce signal
    if (statusCode == 404 || statusCode == 403) {
        rec.score += opts_.errorPenalty;
    }
}

/**
 * MIGRATED FROM: recon-tracker.js -> getReputationTaint()
 * Returns 0 if IP is unknown or TTL has expired (lazy eviction).
 */
int ReconTracker::getReputationTaint(const std::string& ip) const {
    const int64_t now = nowMs();

    // Fast path: shared lock for read
    {
        std::shared_lock lk(mu_);
        auto it = history_.find(ip);
        if (it == history_.end()) return 0;

        const int64_t age = now - it->second.lastSeen;
        if (age <= opts_.ttlMs) return it->second.score;
    }

    // TTL expired — upgrade to exclusive lock and erase
    std::unique_lock lk(mu_);
    auto it = history_.find(ip);
    if (it != history_.end() && (now - it->second.lastSeen) > opts_.ttlMs)
        history_.erase(it);
    return 0;
}

/**
 * MIGRATED FROM: recon-tracker.js -> isSensitiveTarget()
 */
bool ReconTracker::isSensitiveTarget(const std::string& path) {
    for (const auto& pat : sensitiveEndpoints())
        if (std::regex_search(path, pat)) return true;
    return false;
}

// ─── GC ──────────────────────────────────────────────────────────────────────

/**
 * MIGRATED FROM: recon-tracker.js -> setInterval cleanup callback.
 */
void ReconTracker::gc() {
    const int64_t cutoff = nowMs() - opts_.ttlMs;
    std::unique_lock lk(mu_);
    for (auto it = history_.begin(); it != history_.end(); ) {
        if (it->second.lastSeen < cutoff)
            it = history_.erase(it);
        else
            ++it;
    }
}

// ─── Private helpers ─────────────────────────────────────────────────────────

void ReconTracker::evictOldest_locked() {
    if (history_.empty()) return;
    // Find and erase the single entry with the smallest lastSeen
    auto oldest = history_.begin();
    for (auto it = std::next(oldest); it != history_.end(); ++it)
        if (it->second.lastSeen < oldest->second.lastSeen) oldest = it;
    history_.erase(oldest);
}
