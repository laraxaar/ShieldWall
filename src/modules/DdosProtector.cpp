/**
 * @file DdosProtector.cpp
 * @brief Application-Layer DDoS & Slowloris Mitigation — C++17 implementation.
 *
 * MIGRATED FROM: ddos-protection.js -> DdosProtector
 */

#include "DdosProtector.hpp"

#include <algorithm>
#include <numeric>
#include <regex>
#include <sstream>

// ─── Time helper ────────────────────────────────────────────────────────────

static int64_t nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

// ─── IP validation ──────────────────────────────────────────────────────────

/**
 * MIGRATED FROM: ddos-protection.js -> _isValidIP()
 * FIX BUG_38 — Strict format check before any tracker lookup.
 */
bool DdosProtector::isValidIP(const std::string& ip) {
    if (ip.empty()) return false;
    static const std::regex ipv4(
        R"(^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$)");
    static const std::regex ipv6(
        R"(^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$)");
    return std::regex_match(ip, ipv4) || std::regex_match(ip, ipv6);
}

// ─── Constructor / Destructor ────────────────────────────────────────────────

DdosProtector::DdosProtector(const Options& opts) : opts_(opts) {}
DdosProtector::~DdosProtector() = default;

// ─── Whitelist ───────────────────────────────────────────────────────────────

/**
 * MIGRATED FROM: ddos-protection.js -> addToWhitelist()
 * FIX BUG_38 — Only admit valid IPs to the whitelist.
 */
void DdosProtector::addToWhitelist(const std::string& ip) {
    if (!isValidIP(ip)) return;
    std::unique_lock lk(mu_);
    whitelist_.insert(ip);
}

void DdosProtector::removeFromWhitelist(const std::string& ip) {
    std::unique_lock lk(mu_);
    whitelist_.erase(ip);
}

bool DdosProtector::isWhitelisted(const std::string& ip) const {
    std::shared_lock lk(mu_);
    return whitelist_.count(ip) > 0;
}

// ─── Main check ──────────────────────────────────────────────────────────────

/**
 * MIGRATED FROM: ddos-protection.js -> check()
 * FIX BUG_38 — Early rejection on invalid/missing IP.
 */
std::vector<DdosMatch> DdosProtector::check(const DecodedRequest& req) {
    std::vector<DdosMatch> matches;
    const int64_t now = nowMs();

    // BUG_38 — reject invalid IP immediately
    if (!isValidIP(req.ip)) {
        DdosMatch m;
        m.rule        = "ddos_protection:invalid_ip";
        m.severity    = "critical";
        m.category    = "dos";
        m.description = "IP Spoofing / Invalid IP format: " + (req.ip.empty() ? "missing" : req.ip);
        m.matchedPatterns.push_back({"invalid_ip", req.ip.empty() ? "missing" : req.ip});
        matches.push_back(std::move(m));
        return matches;
    }

    // Whitelist bypass
    if (isWhitelisted(req.ip)) return matches;

    std::vector<std::pair<std::string,std::string>> indicators;  // {type, detail}

    // ── Slowloris / Header bomb checks ──────────────────────────────────────
    for (auto& [type, detail] : checkSlowloris(req, now))
        ; // indicators returned as DdosMatch patterns — merge below

    auto slowMatches = checkSlowloris(req, now);
    auto connMatches = checkConnFlood(req, now);

    // Aggregate all indicator patterns
    std::vector<DdosMatch::Pattern> allPatterns;
    bool hasOversized = false;
    std::vector<std::string> types;

    auto gatherPatterns = [&](const std::vector<DdosMatch>& src) {
        for (const auto& m : src) {
            for (const auto& p : m.matchedPatterns) {
                allPatterns.push_back(p);
                types.push_back(p.name);
                if (p.name == "oversized_body" || p.name == "oversized_headers")
                    hasOversized = true;
            }
        }
    };
    gatherPatterns(slowMatches);
    gatherPatterns(connMatches);

    if (!allPatterns.empty()) {
        metrics_.blockedCount++;

        std::string typeList;
        for (size_t i = 0; i < types.size(); ++i) {
            if (i) typeList += ", ";
            typeList += types[i];
        }

        DdosMatch m;
        m.rule           = "ddos_protection";
        m.severity       = hasOversized ? "critical" : "high";
        m.category       = "dos";
        m.description    = "L7 Volumetric Threat: " + typeList;
        m.matchedPatterns = std::move(allPatterns);
        matches.push_back(std::move(m));
    }
    return matches;
}

// ─── Private Checks ──────────────────────────────────────────────────────────

/**
 * MIGRATED FROM: ddos-protection.js -> checkSlowloris()
 * BUG_37 — OOM guard: evict oldest Slowloris entry when at capacity.
 * BUG_40 — Prototype pollution is impossible in C++; we validate header
 *           key names and sizes instead.
 */
std::vector<DdosMatch> DdosProtector::checkSlowloris(const DecodedRequest& req,
                                                      int64_t now) {
    std::vector<DdosMatch> out;

    // Update Slowloris tracker
    {
        std::unique_lock lk(mu_);
        if (slowTracker_.find(req.ip) == slowTracker_.end()) {
            // BUG_37 — OOM guard
            if (slowTracker_.size() >= opts_.maxTrackerSize)
                evictOldestSlow_locked();
        }
        slowTracker_[req.ip].lastActivity = now;
    }

    // Header byte-size check
    size_t headerBytes = 0;
    for (const auto& [k, v] : req.headers) {
        // BUG_40 — Dangerous header key names
        if (k == "__proto__" || k == "constructor" || k == "prototype") {
            DdosMatch m;
            m.rule     = "ddos_protection";
            m.severity = "critical";
            m.category = "dos";
            m.description = "Prototype pollution attempt in headers";
            m.matchedPatterns.push_back({"protocol_anomaly:prototype_pollution",
                                          "Dangerous header key: " + k});
            out.push_back(std::move(m));
            return out;
        }
        headerBytes += k.size() + v.size() + 4;  // ": " + "\r\n"
    }

    if (headerBytes > opts_.maxHeaderBytes) {
        DdosMatch m;
        m.rule     = "ddos_protection";
        m.severity = "high";
        m.category = "dos";
        m.description = "Oversized header block";
        m.matchedPatterns.push_back({"oversized_headers",
            "Header size " + std::to_string(headerBytes) +
            "B exceeds limit (" + std::to_string(opts_.maxHeaderBytes) + "B)"});
        out.push_back(std::move(m));
    }

    // Query parameter flood check
    if (req.query.size() > opts_.maxQueryParams) {
        DdosMatch m;
        m.rule     = "ddos_protection";
        m.severity = "high";
        m.category = "dos";
        m.description = "Query parameter flood";
        m.matchedPatterns.push_back({"parameter_flood",
            "Hyper-fragmented URL parameters: " + std::to_string(req.query.size()) + " items"});
        out.push_back(std::move(m));
    }

    // Oversized body check
    if (req.contentLength > opts_.maxBodyBytes) {
        DdosMatch m;
        m.rule     = "ddos_protection";
        m.severity = "critical";
        m.category = "dos";
        m.description = "Oversized body";
        m.matchedPatterns.push_back({"oversized_body",
            "Content-Length " + std::to_string(req.contentLength) +
            "B exceeds absolute safety threshold"});
        out.push_back(std::move(m));
    }

    return out;
}

/**
 * MIGRATED FROM: ddos-protection.js -> checkConnectionFlood()
 * BUG_37 — OOM guard: evict oldest Connection entry when at capacity.
 */
std::vector<DdosMatch> DdosProtector::checkConnFlood(const DecodedRequest& req,
                                                      int64_t now) {
    size_t count = 0;
    {
        std::unique_lock lk(mu_);

        if (connTracker_.find(req.ip) == connTracker_.end()) {
            // BUG_37 — OOM guard
            if (connTracker_.size() >= opts_.maxTrackerSize)
                evictOldestConn_locked();
        }

        auto& ce  = connTracker_[req.ip];
        auto& dq  = ce.requests;
        const int64_t cutoff = now - opts_.connectionWindowMs;

        // Slide the window: pop expired front entries
        while (!dq.empty() && dq.front() < cutoff) dq.pop_front();
        dq.push_back(now);
        count = dq.size();
    }

    std::vector<DdosMatch> out;
    if (count > opts_.maxConnectionsPerIp) {
        DdosMatch m;
        m.rule     = "ddos_protection";
        m.severity = "high";
        m.category = "dos";
        m.description = "Connection flood";
        m.matchedPatterns.push_back({"connection_flood",
            "Volumetric Spike: " + std::to_string(count) +
            " socket pulses per min (Safe: " +
            std::to_string(opts_.maxConnectionsPerIp) + ")"});
        out.push_back(std::move(m));
    }
    return out;
}

// ─── GC ──────────────────────────────────────────────────────────────────────

/**
 * MIGRATED FROM: ddos-protection.js -> setInterval GC callback.
 */
void DdosProtector::gc() {
    const int64_t now    = nowMs();
    const int64_t cutoff = now - opts_.connectionWindowMs;
    const int64_t slowCutoff = now - opts_.slowlorisTimeoutMs - 5000;

    std::unique_lock lk(mu_);

    for (auto it = connTracker_.begin(); it != connTracker_.end(); ) {
        auto& dq = it->second.requests;
        while (!dq.empty() && dq.front() < cutoff) dq.pop_front();
        if (dq.empty()) it = connTracker_.erase(it);
        else            ++it;
    }

    for (auto it = slowTracker_.begin(); it != slowTracker_.end(); ) {
        if (it->second.lastActivity < slowCutoff)
            it = slowTracker_.erase(it);
        else
            ++it;
    }
}

// ─── Eviction helpers ────────────────────────────────────────────────────────

void DdosProtector::evictOldestConn_locked() {
    if (!connTracker_.empty()) connTracker_.erase(connTracker_.begin());
}
void DdosProtector::evictOldestSlow_locked() {
    if (!slowTracker_.empty()) slowTracker_.erase(slowTracker_.begin());
}

// ─── Metrics size accessors ──────────────────────────────────────────────────

// NOTE: Metrics::connectionTrackerSize() / slowlorisTrackerSize() require
// access to the parent DdosProtector's maps. Implemented inline in the header
// because Metrics is a nested struct without a back-pointer. In production,
// expose via DdosProtector::snapshotMetrics() to avoid the coupling.
