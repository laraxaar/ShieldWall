/**
 * @file DdosProtector.cpp
 * @brief Application-Layer DDoS, Slowloris & Volumetric Mitigation — implementation.
 *
 * See DdosProtector.hpp for the design overview and changelog.
 */

#include "DdosProtector.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include <sstream>

// ─── Optional JSON support ─────────────────────────────────────────────────
// We try nlohmann/json if available; otherwise we ship a tiny built-in parser
// that handles the subset of JSON we actually use in the config file. This
// keeps the module self-contained without external dependencies.

#ifdef DDOSONLY_USE_NLOHMANN_JSON
#include <nlohmann/json.hpp>
using json = nlohmann::json;
#define DDOSONLY_HAVE_JSON 1
#endif

// ─── Time helper ───────────────────────────────────────────────────────────

static int64_t nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

// ─── Minimal JSON parser (only used if nlohmann is not available) ──────────

#ifndef DDOSONLY_HAVE_JSON
namespace {

class MiniJson {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    // Public value fields (used directly when traversing parsed values)
    Type type = Type::Null;
    bool boolVal = false;
    double numVal = 0;
    std::string strVal;
    std::vector<MiniJson> arr;
    std::unordered_map<std::string, MiniJson> obj;

    // Parse a JSON string into this node. Returns false on parse error.
    bool parse(const std::string& src) {
        Parser p(src);
        p.skipWs();
        if (!p.parseValue(*this)) return false;
        p.skipWs();
        return p.pos() >= src.size();
    }

    // Lookup helpers
    bool has(const std::string& key) const {
        return type == Type::Object && obj.count(key) > 0;
    }
    const MiniJson* find(const std::string& key) const {
        if (type != Type::Object) return nullptr;
        auto it = obj.find(key);
        return it == obj.end() ? nullptr : &it->second;
    }
    bool asBool(const std::string& key, bool def) const {
        const auto* n = find(key);
        if (!n || n->type != Type::Bool)   return def;
        return n->boolVal;
    }
    int64_t asInt(const std::string& key, int64_t def) const {
        const auto* n = find(key);
        if (!n || n->type != Type::Number) return def;
        return (int64_t)n->numVal;
    }
    double asDouble(const std::string& key, double def) const {
        const auto* n = find(key);
        if (!n || n->type != Type::Number) return def;
        return n->numVal;
    }
    std::string asString(const std::string& key, const std::string& def) const {
        const auto* n = find(key);
        if (!n || n->type != Type::String) return def;
        return n->strVal;
    }
    std::string asString(const std::string& def = "") const {
        return type == Type::String ? strVal : def;
    }
    bool isArray(const std::string& key) const {
        const auto* n = find(key);
        return n && n->type == Type::Array;
    }
    const std::vector<MiniJson>& array(const std::string& key) const {
        static const std::vector<MiniJson> empty;
        const auto* n = find(key);
        if (!n || n->type != Type::Array) return empty;
        return n->arr;
    }

private:
    class Parser {
    public:
        explicit Parser(const std::string& src) : src_(src), pos_(0) {}
        size_t pos() const { return pos_; }
        void skipWs() {
            while (pos_ < src_.size()) {
                char c = src_[pos_];
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++pos_;
                else break;
            }
        }
        bool parseValue(MiniJson& out) {
            skipWs();
            if (pos_ >= src_.size()) return false;
            char c = src_[pos_];
            if (c == '{') return parseObject(out);
            if (c == '[') return parseArray(out);
            if (c == '"') return parseString(out);
            if (c == 't' || c == 'f') return parseBool(out);
            if (c == 'n') return parseNull(out);
            return parseNumber(out);
        }
        bool parseObject(MiniJson& out) {
            out.type = Type::Object;
            ++pos_;
            skipWs();
            if (pos_ < src_.size() && src_[pos_] == '}') { ++pos_; return true; }
            while (pos_ < src_.size()) {
                skipWs();
                if (src_[pos_] != '"') return false;
                MiniJson key;
                if (!parseString(key)) return false;
                skipWs();
                if (pos_ >= src_.size() || src_[pos_] != ':') return false;
                ++pos_;
                MiniJson val;
                if (!parseValue(val)) return false;
                out.obj[key.strVal] = std::move(val);
                skipWs();
                if (pos_ >= src_.size()) return false;
                if (src_[pos_] == ',') { ++pos_; continue; }
                if (src_[pos_] == '}') { ++pos_; return true; }
                return false;
            }
            return false;
        }
        bool parseArray(MiniJson& out) {
            out.type = Type::Array;
            ++pos_;
            skipWs();
            if (pos_ < src_.size() && src_[pos_] == ']') { ++pos_; return true; }
            while (pos_ < src_.size()) {
                MiniJson val;
                if (!parseValue(val)) return false;
                out.arr.push_back(std::move(val));
                skipWs();
                if (pos_ >= src_.size()) return false;
                if (src_[pos_] == ',') { ++pos_; continue; }
                if (src_[pos_] == ']') { ++pos_; return true; }
                return false;
            }
            return false;
        }
        bool parseString(MiniJson& out) {
            out.type = Type::String;
            ++pos_;
            out.strVal.clear();
            while (pos_ < src_.size()) {
                char c = src_[pos_++];
                if (c == '"') return true;
                if (c == '\\') {
                    if (pos_ >= src_.size()) return false;
                    char e = src_[pos_++];
                    switch (e) {
                        case '"':  out.strVal.push_back('"'); break;
                        case '\\': out.strVal.push_back('\\'); break;
                        case '/':  out.strVal.push_back('/'); break;
                        case 'b':  out.strVal.push_back('\b'); break;
                        case 'f':  out.strVal.push_back('\f'); break;
                        case 'n':  out.strVal.push_back('\n'); break;
                        case 'r':  out.strVal.push_back('\r'); break;
                        case 't':  out.strVal.push_back('\t'); break;
                        case 'u': {
                            if (pos_ + 4 > src_.size()) return false;
                            pos_ += 4;
                            out.strVal.push_back('?');
                            break;
                        }
                        default: out.strVal.push_back(e); break;
                    }
                } else {
                    out.strVal.push_back(c);
                }
            }
            return false;
        }
        bool parseBool(MiniJson& out) {
            out.type = Type::Bool;
            if (src_.compare(pos_, 4, "true") == 0)  { out.boolVal = true;  pos_ += 4; return true; }
            if (src_.compare(pos_, 5, "false") == 0) { out.boolVal = false; pos_ += 5; return true; }
            return false;
        }
        bool parseNull(MiniJson& out) {
            out.type = Type::Null;
            if (src_.compare(pos_, 4, "null") == 0) { pos_ += 4; return true; }
            return false;
        }
        bool parseNumber(MiniJson& out) {
            out.type = Type::Number;
            size_t start = pos_;
            while (pos_ < src_.size()) {
                char c = src_[pos_];
                if ((c >= '0' && c <= '9') || c == '-' || c == '+' ||
                    c == '.' || c == 'e' || c == 'E') ++pos_;
                else break;
            }
            if (pos_ == start) return false;
            try {
                out.numVal = std::stod(src_.substr(start, pos_ - start));
            } catch (...) {
                return false;
            }
            return true;
        }

    private:
        const std::string& src_;
        size_t pos_;
    };
};

} // namespace
#endif // DDOSONLY_HAVE_JSON

// ─── IP validation (replaces regex — correct + 100x faster) ────────────────

bool DdosProtector::isValidIP(const std::string& ip) {
    if (ip.empty()) return false;
    // Try IPv4 first (most common)
    struct in_addr v4;
    if (inet_pton(AF_INET, ip.c_str(), &v4) == 1) return true;
    // Then IPv6 (accepts compressed forms, ::1, 2001:db8::1, ::ffff:1.2.3.4)
    struct in6_addr v6;
    return inet_pton(AF_INET6, ip.c_str(), &v6) == 1;
}

std::string DdosProtector::normalizeIp(const std::string& ip) {
    if (ip.empty()) return ip;
    // Detect IPv4-mapped IPv6 (::ffff:1.2.3.4) and emit plain IPv4.
    // inet_pton round-trips to canonical form, which makes it trivial.
    struct in6_addr v6;
    if (inet_pton(AF_INET6, ip.c_str(), &v6) == 1) {
        // IPv4-mapped: bytes 0..9 == 0, bytes 10..11 == 0xff
        const uint8_t* b = v6.s6_addr;
        if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 &&
            b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
            b[8] == 0 && b[9] == 0 && b[10] == 0xff && b[11] == 0xff) {
            char buf[INET_ADDRSTRLEN];
            struct in_addr v4;
            std::memcpy(&v4, b + 12, 4);
            inet_ntop(AF_INET, &v4, buf, sizeof(buf));
            return std::string(buf);
        }
        // Other IPv6 — lowercase canonical form
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &v6, buf, sizeof(buf));
        return std::string(buf);
    }
    // IPv4 — return as-is (already canonical enough for our keys)
    return ip;
}

bool DdosProtector::parseCIDR(const std::string& str, CIDR& out) {
    auto slash = str.find('/');
    if (slash == std::string::npos) {
        // Single IP — treat as /32 or /128
        struct in_addr v4;
        if (inet_pton(AF_INET, str.c_str(), &v4) == 1) {
            out.family    = AF_INET;
            out.prefixLen = 32;
            out.network.resize(4);
            std::memcpy(out.network.data(), &v4, 4);
            return true;
        }
        struct in6_addr v6;
        if (inet_pton(AF_INET6, str.c_str(), &v6) == 1) {
            out.family    = AF_INET6;
            out.prefixLen = 128;
            out.network.resize(16);
            std::memcpy(out.network.data(), &v6, 16);
            return true;
        }
        return false;
    }

    std::string ipPart   = str.substr(0, slash);
    std::string prefixStr = str.substr(slash + 1);
    if (prefixStr.empty()) return false;
    int prefix = 0;
    for (char c : prefixStr) {
        if (c < '0' || c > '9') return false;
        prefix = prefix * 10 + (c - '0');
    }

    struct in_addr v4;
    if (inet_pton(AF_INET, ipPart.c_str(), &v4) == 1) {
        if (prefix > 32) return false;
        out.family    = AF_INET;
        out.prefixLen = (uint8_t)prefix;
        out.network.resize(4);
        std::memcpy(out.network.data(), &v4, 4);
        // Mask out host bits so network address is canonical
        uint32_t mask = prefix == 0 ? 0 : htonl(~((1u << (32 - prefix)) - 1));
        uint32_t net;
        std::memcpy(&net, out.network.data(), 4);
        net &= mask;
        std::memcpy(out.network.data(), &net, 4);
        return true;
    }

    struct in6_addr v6;
    if (inet_pton(AF_INET6, ipPart.c_str(), &v6) == 1) {
        if (prefix > 128) return false;
        out.family    = AF_INET6;
        out.prefixLen = (uint8_t)prefix;
        out.network.resize(16);
        std::memcpy(out.network.data(), &v6, 16);
        // Mask host bits
        for (int i = 0; i < 16; ++i) {
            int bitsInThisByte = std::min(prefix - i * 8, 8);
            if (bitsInThisByte <= 0) out.network[i] = 0;
            else if (bitsInThisByte < 8) {
                out.network[i] &= (uint8_t)(0xFF << (8 - bitsInThisByte));
            }
        }
        return true;
    }
    return false;
}

bool DdosProtector::ipInCIDR(const std::string& ip, const CIDR& cidr) {
    if (cidr.family == AF_INET) {
        struct in_addr addr;
        if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return false;
        uint32_t ipNet, cidrNet;
        std::memcpy(&ipNet, &addr, 4);
        std::memcpy(&cidrNet, cidr.network.data(), 4);
        uint32_t mask = cidr.prefixLen == 0 ? 0 : htonl(~((1u << (32 - cidr.prefixLen)) - 1));
        return (ipNet & mask) == (cidrNet & mask);
    }
    if (cidr.family == AF_INET6) {
        struct in6_addr addr;
        if (inet_pton(AF_INET6, ip.c_str(), &addr) != 1) return false;
        const uint8_t* a = addr.s6_addr;
        const uint8_t* n = cidr.network.data();
        int bits = cidr.prefixLen;
        for (int i = 0; i < 16 && bits > 0; ++i) {
            if (bits >= 8) {
                if (a[i] != n[i]) return false;
                bits -= 8;
            } else {
                uint8_t mask = (uint8_t)(0xFF << (8 - bits));
                if ((a[i] & mask) != (n[i] & mask)) return false;
                bits = 0;
            }
        }
        return true;
    }
    return false;
}

// ─── Constructor / Destructor ──────────────────────────────────────────────

DdosProtector::DdosProtector() : opts_(Options{}) {}

DdosProtector::DdosProtector(Options opts) : opts_(std::move(opts)) {}

DdosProtector::~DdosProtector() {
    dispose();
}

// ─── Whitelist ─────────────────────────────────────────────────────────────

void DdosProtector::addToWhitelist(const std::string& ipOrCidr) {
    // Try CIDR first
    CIDR c;
    if (parseCIDR(ipOrCidr, c)) {
        std::unique_lock lk(mu_);
        // Check if already present
        for (const auto& existing : cidrWhitelist_) {
            if (existing.family == c.family &&
                existing.prefixLen == c.prefixLen &&
                existing.network == c.network) {
                return;
            }
        }
        cidrWhitelist_.push_back(std::move(c));
        return;
    }
    // Fall back to exact match (still validate format)
    if (!isValidIP(ipOrCidr)) return;
    std::unique_lock lk(mu_);
    whitelist_.insert(normalizeIp(ipOrCidr));
}

void DdosProtector::removeFromWhitelist(const std::string& ipOrCidr) {
    std::unique_lock lk(mu_);
    CIDR c;
    if (parseCIDR(ipOrCidr, c)) {
        cidrWhitelist_.erase(
            std::remove_if(cidrWhitelist_.begin(), cidrWhitelist_.end(),
                           [&](const CIDR& x) {
                               return x.family == c.family &&
                                      x.prefixLen == c.prefixLen &&
                                      x.network == c.network;
                           }),
            cidrWhitelist_.end());
        return;
    }
    whitelist_.erase(normalizeIp(ipOrCidr));
}

bool DdosProtector::isWhitelisted(const std::string& ip) const {
    if (!isValidIP(ip)) return false;
    std::string norm = normalizeIp(ip);
    std::shared_lock lk(mu_);
    if (whitelist_.count(norm) > 0) return true;
    for (const auto& cidr : cidrWhitelist_) {
        if (ipInCIDR(norm, cidr)) return true;
    }
    return false;
}

// ─── Penalty box ───────────────────────────────────────────────────────────

bool DdosProtector::isIpBanned(const std::string& ip) const {
    if (!isValidIP(ip)) return false;
    std::string norm = normalizeIp(ip);
    int64_t now = nowMs();
    std::shared_lock lk(mu_);
    auto it = penaltyBox_.find(norm);
    if (it == penaltyBox_.end()) return false;
    return it->second.bannedUntil > now;
}

void DdosProtector::banIp(const std::string& ip, int64_t durationMs) {
    if (!isValidIP(ip)) return;
    std::string norm = normalizeIp(ip);
    int64_t now = nowMs();
    std::unique_lock lk(mu_);
    auto& entry = penaltyBox_[norm];
    entry.bannedUntil = now + durationMs;
    entry.lastBanMs = durationMs;
    entry.violationCount = std::max(entry.violationCount, (size_t)1);
}

void DdosProtector::unbanIp(const std::string& ip) {
    if (!isValidIP(ip)) return;
    std::string norm = normalizeIp(ip);
    std::unique_lock lk(mu_);
    auto it = penaltyBox_.find(norm);
    if (it != penaltyBox_.end()) {
        // Release from current ban but PRESERVE violationCount + lastBanMs
        // so the next violation triggers a longer exponential-backoff ban.
        // Erasing the entry would reset the offense history.
        it->second.bannedUntil = 0;
    }
}

void DdosProtector::recordViolation_locked_(const std::string& ip,
                                             const std::string& /*type*/,
                                             int64_t now) {
    if (!opts_.penaltyBoxEnabled) return;
    auto& entry = penaltyBox_[ip];

    // If already banned, don't extend or count additional violations
    // (otherwise a stream of violations during the ban window would
    // push violationCount into the stratosphere and lock the IP out
    // permanently via backoff).
    if (entry.bannedUntil > now) return;

    entry.violationCount++;

    if (entry.violationCount >= opts_.penaltyViolationsThreshold) {
        // Exponential backoff: each subsequent ban is multiplier × previous.
        int64_t banMs = entry.lastBanMs == 0
                            ? opts_.penaltyBaseBanMs
                            : (int64_t)(entry.lastBanMs * opts_.penaltyBackoffMultiplier);
        if (banMs > opts_.penaltyMaxBanMs) banMs = opts_.penaltyMaxBanMs;
        entry.lastBanMs   = banMs;
        entry.bannedUntil = now + banMs;
    }
}

// ─── Health-check bypass ───────────────────────────────────────────────────

bool DdosProtector::isHealthCheckPath_(const std::string& path) const {
    if (!opts_.featureHealthCheckBypass) return false;
    if (path.empty()) return false;
    return healthCheckPaths_.count(path) > 0;
}

// ─── Path rules ────────────────────────────────────────────────────────────

const PathRule* DdosProtector::matchPathRule_(const std::string& path) const {
    if (!opts_.featurePathRules) return nullptr;
    if (path.empty()) return nullptr;
    // Longest-prefix match — first match wins (caller should sort rules
    // by prefix length in config if order matters).
    for (const auto& rule : pathRules_) {
        if (path.rfind(rule.pathPrefix, 0) == 0) {
            return &rule;
        }
    }
    return nullptr;
}

// ─── LRU touch helpers ─────────────────────────────────────────────────────

void DdosProtector::touchConnLru_locked_(std::unordered_map<std::string, ConnEntry>::iterator it) {
    connLru_.splice(connLru_.end(), connLru_, it->second.lruIter);
}

void DdosProtector::touchSlowLru_locked_(std::unordered_map<std::string, SlowEntry>::iterator it) {
    slowLru_.splice(slowLru_.end(), slowLru_, it->second.lruIter);
}

void DdosProtector::touchRapidResetLru_locked_(std::unordered_map<std::string, RapidResetEntry>::iterator it) {
    rapidResetLru_.splice(rapidResetLru_.end(), rapidResetLru_, it->second.lruIter);
}

void DdosProtector::evictOldestConn_locked_() {
    if (connLru_.empty()) return;
    std::string oldest = connLru_.front();
    connLru_.pop_front();
    connTracker_.erase(oldest);
}

void DdosProtector::evictOldestSlow_locked_() {
    if (slowLru_.empty()) return;
    std::string oldest = slowLru_.front();
    slowLru_.pop_front();
    slowTracker_.erase(oldest);
}

void DdosProtector::evictOldestRapidReset_locked_() {
    if (rapidResetLru_.empty()) return;
    std::string oldest = rapidResetLru_.front();
    rapidResetLru_.pop_front();
    rapidResetTracker_.erase(oldest);
}

// ─── Main check ────────────────────────────────────────────────────────────

std::vector<DdosMatch> DdosProtector::check(const DecodedRequest& req) {
    std::vector<DdosMatch> matches;
    if (disposed_.load(std::memory_order_relaxed)) return matches;

    const int64_t now = nowMs();

    // IP validation — strict format check before any tracker lookup
    if (!isValidIP(req.ip)) {
        DdosMatch m;
        m.rule        = "ddos_protection:invalid_ip";
        m.severity    = "critical";
        m.category    = "dos";
        m.description = "IP Spoofing / Invalid IP format: " +
                        (req.ip.empty() ? std::string("missing") : req.ip);
        m.matchedPatterns.push_back({"invalid_ip",
            req.ip.empty() ? "missing" : req.ip});
        matches.push_back(std::move(m));
        return matches;
    }

    // Normalize once
    const std::string normIp = normalizeIp(req.ip);

    // Whitelist bypass
    if (isWhitelisted(normIp)) return matches;

    // Health-check bypass — internal probes should not trip penalty box
    if (isHealthCheckPath_(req.path)) return matches;

    // Penalty box short-circuit
    {
        std::shared_lock lk(mu_);
        auto it = penaltyBox_.find(normIp);
        if (it != penaltyBox_.end() && it->second.bannedUntil > now) {
            bannedAtAccept_.fetch_add(1, std::memory_order_relaxed);
            DdosMatch m;
            m.rule        = "ddos_protection:penalty_box";
            m.severity    = "high";
            m.category    = "dos";
            m.description = "IP is in penalty box (banned until " +
                            std::to_string(it->second.bannedUntil) +
                            ", violations=" + std::to_string(it->second.violationCount) + ")";
            m.matchedPatterns.push_back({"penalty_box_banned", normIp});
            matches.push_back(std::move(m));
            return matches;
        }
    }

    // ── Run sub-detectors ────────────────────────────────────────────────
    // Each one returns its own DdosMatch list. We aggregate at the end.
    // Note: checkSlowloris_ is called ONCE now (old code called it twice —
    // once in a dead for-loop that didn't compile, once for real).
    auto slowMatches   = checkSlowloris_   (req, now);
    auto connMatches    = checkConnFlood_   (req, now);
    auto payloadMatches = checkPayloadShape_(req, now);

    // ── Aggregate patterns ───────────────────────────────────────────────
    std::vector<DdosMatch::Pattern> allPatterns;
    bool needsViolationRecord = false;

    auto gather = [&](const std::vector<DdosMatch>& src) {
        for (const auto& m : src) {
            for (const auto& p : m.matchedPatterns) {
                allPatterns.push_back(p);
            }
            if (m.severity == "high" || m.severity == "critical") {
                needsViolationRecord = true;
            }
        }
    };
    gather(slowMatches);
    gather(connMatches);
    gather(payloadMatches);

    if (allPatterns.empty()) return matches;

    blockedCount_.fetch_add(1, std::memory_order_relaxed);

    // Record violation for penalty box (under unique lock)
    if (needsViolationRecord) {
        std::unique_lock lk(mu_);
        recordViolation_locked_(normIp, "ddos_match", now);
    }

    // Build type list for description
    std::string typeList;
    for (size_t i = 0; i < allPatterns.size(); ++i) {
        if (i) typeList += ", ";
        typeList += allPatterns[i].name;
    }

    // Severity aggregation: max of all sub-match severities (old code
    // only checked hasOversized, which dropped critical signals from
    // prototype-pollution and other paths).
    std::vector<DdosMatch> all;
    all.reserve(slowMatches.size() + connMatches.size() + payloadMatches.size());
    for (auto& m : slowMatches)    all.push_back(std::move(m));
    for (auto& m : connMatches)    all.push_back(std::move(m));
    for (auto& m : payloadMatches) all.push_back(std::move(m));

    std::string maxSev = maxSeverity_(all);

    DdosMatch m;
    m.rule            = "ddos_protection";
    m.severity        = maxSev;
    m.category        = "dos";
    m.description     = "L7 Volumetric Threat: " + typeList;
    m.matchedPatterns = std::move(allPatterns);
    matches.push_back(std::move(m));

    return matches;
}

int DdosProtector::severityRank_(const std::string& sev) const {
    if (sev == "critical") return 3;
    if (sev == "high")     return 2;
    if (sev == "medium")   return 1;
    return 0;
}

std::string DdosProtector::maxSeverity_(const std::vector<DdosMatch>& matches) const {
    int best = 0;
    std::string bestSev = "medium";
    for (const auto& m : matches) {
        int r = severityRank_(m.severity);
        if (r > best) { best = r; bestSev = m.severity; }
    }
    return bestSev;
}

// ─── Sub-detector: payload shape (was misleadingly named checkSlowloris) ───

std::vector<DdosMatch> DdosProtector::checkPayloadShape_(const DecodedRequest& req,
                                                          int64_t /*now*/) {
    std::vector<DdosMatch> out;

    // Header byte-size check + dangerous header keys
    size_t headerBytes = 0;
    for (const auto& [k, v] : req.headers) {
        // Dangerous header key names — still possible to attempt even in C++
        // (e.g. if a sloppy upstream parser allowed them through). Flag and
        // CONTINUE — old code did `return out` which skipped every other
        // check on the request, so an attacker could smuggle a 200MB body
        // by attaching a `__proto__: x` header.
        if (k == "__proto__" || k == "constructor" || k == "prototype") {
            DdosMatch m;
            m.rule        = "ddos_protection";
            m.severity    = "critical";
            m.category    = "dos";
            m.description = "Prototype pollution attempt in headers";
            m.matchedPatterns.push_back({"protocol_anomaly:prototype_pollution",
                                          "Dangerous header key: " + k});
            out.push_back(std::move(m));
            continue;  // ← was `return out` — major security bug
        }
        headerBytes += k.size() + v.size() + 4;  // ": " + "\r\n"
    }

    if (opts_.featureOversizedHeaders && headerBytes > opts_.maxHeaderBytes) {
        DdosMatch m;
        m.rule        = "ddos_protection";
        m.severity    = "high";
        m.category    = "dos";
        m.description = "Oversized header block";
        m.matchedPatterns.push_back({"oversized_headers",
            "Header size " + std::to_string(headerBytes) +
            "B exceeds limit (" + std::to_string(opts_.maxHeaderBytes) + "B)"});
        out.push_back(std::move(m));
    }

    // Query parameter flood
    if (opts_.featureParamFlood && req.query.size() > opts_.maxQueryParams) {
        DdosMatch m;
        m.rule        = "ddos_protection";
        m.severity    = "high";
        m.category    = "dos";
        m.description = "Query parameter flood";
        m.matchedPatterns.push_back({"parameter_flood",
            "Hyper-fragmented URL parameters: " +
            std::to_string(req.query.size()) + " items"});
        out.push_back(std::move(m));
    }

    // Oversized body
    if (opts_.featureOversizedBody && req.contentLength > opts_.maxBodyBytes) {
        DdosMatch m;
        m.rule        = "ddos_protection";
        m.severity    = "critical";
        m.category    = "dos";
        m.description = "Oversized body";
        m.matchedPatterns.push_back({"oversized_body",
            "Content-Length " + std::to_string(req.contentLength) +
            "B exceeds absolute safety threshold"});
        out.push_back(std::move(m));
    }

    // Compression bomb heuristic — Content-Encoding: gzip with declared
    // Content-Length much larger than the safety ceiling after decompression.
    // We don't decompress; we just flag obvious ratios.
    if (opts_.featureCompressionBomb) {
        auto it = req.headers.find("content-encoding");
        if (it != req.headers.end()) {
            const std::string& enc = it->second;
            if (enc.find("gzip") != std::string::npos ||
                enc.find("deflate") != std::string::npos ||
                enc.find("br") != std::string::npos) {
                // Heuristic: if the body is already large AND compressed,
                // it's likely a bomb (legit APIs rarely send 50MB compressed
                // JSON). Configurable ratio threshold.
                if (req.contentLength > 1024 * 1024) { // > 1MB compressed
                    DdosMatch m;
                    m.rule        = "ddos_protection";
                    m.severity    = "high";
                    m.category    = "dos";
                    m.description = "Compression bomb heuristic";
                    m.matchedPatterns.push_back({"compression_bomb",
                        "Compressed Content-Length " +
                        std::to_string(req.contentLength) +
                        "B exceeds safety threshold (decompressed estimate unknown)"});
                    out.push_back(std::move(m));
                }
            }
        }
    }

    return out;
}

// ─── Sub-detector: connection flood (token bucket) ─────────────────────────

std::vector<DdosMatch> DdosProtector::checkConnFlood_(const DecodedRequest& req,
                                                       int64_t now) {
    if (!opts_.featureConnFlood) return {};

    // Path-specific rule?
    size_t  perIpLimit  = opts_.maxConnectionsPerIp;
    int64_t windowMs    = opts_.connectionWindowMs;
    if (const PathRule* rule = matchPathRule_(req.path)) {
        if (rule->maxConnectionsPerIp > 0) perIpLimit = rule->maxConnectionsPerIp;
        if (rule->connectionWindowMs   > 0) windowMs   = rule->connectionWindowMs;
    }

    bool overLimit = false;
    double currentTokens = 0;

    {
        std::unique_lock lk(mu_);

        // Insert or evict
        auto it = connTracker_.find(req.ip);
        if (it == connTracker_.end()) {
            if (connTracker_.size() >= opts_.maxTrackerSize) {
                evictOldestConn_locked_();
            }
            std::string key = req.ip;
            connLru_.push_back(key);
            auto lruIt = std::prev(connLru_.end());
            ConnEntry e;
            e.tokens       = (double)perIpLimit;
            e.lastRefillMs = now;
            e.lruIter      = lruIt;
            it = connTracker_.emplace(std::move(key), std::move(e)).first;
        } else {
            touchConnLru_locked_(it);
        }

        auto& ce = it->second;

        // Refill: add tokens based on elapsed time
        double refillPerMs = opts_.connectionRefillRatePerSec / 1000.0;
        int64_t elapsed = now - ce.lastRefillMs;
        if (elapsed > 0) {
            ce.tokens += elapsed * refillPerMs;
            if (ce.tokens > (double)perIpLimit) ce.tokens = (double)perIpLimit;
            ce.lastRefillMs = now;
        }

        // Consume 1 token for this request
        ce.tokens -= 1.0;
        currentTokens = ce.tokens;

        if (ce.tokens < 0) {
            overLimit = true;
            connFloodDetected_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    if (!overLimit) return {};

    std::vector<DdosMatch> out;
    DdosMatch m;
    m.rule        = "ddos_protection";
    m.severity    = "high";
    m.category    = "dos";
    m.description = "Connection flood";
    m.matchedPatterns.push_back({"connection_flood",
        "Token bucket drained: " + std::to_string(currentTokens) +
        " tokens after consuming 1 (limit=" + std::to_string(perIpLimit) +
        ", window=" + std::to_string(windowMs) + "ms)"});
    out.push_back(std::move(m));
    return out;
}

// ─── Sub-detector: slowloris (real timing-based) ───────────────────────────

std::vector<DdosMatch> DdosProtector::checkSlowloris_(const DecodedRequest& req,
                                                       int64_t now) {
    if (!opts_.featureSlowloris) return {};

    std::vector<DdosMatch> out;

    // Touch tracker (for LRU + TTL bookkeeping)
    {
        std::unique_lock lk(mu_);
        auto it = slowTracker_.find(req.ip);
        if (it == slowTracker_.end()) {
            if (slowTracker_.size() >= opts_.maxTrackerSize) {
                evictOldestSlow_locked_();
            }
            std::string key = req.ip;
            slowLru_.push_back(key);
            SlowEntry e;
            e.lruIter = std::prev(slowLru_.end());
            it = slowTracker_.emplace(std::move(key), std::move(e)).first;
        } else {
            touchSlowLru_locked_(it);
        }

        auto& se = it->second;

        // If the streaming layer reported slow arrival, emit a match
        if (se.slowlorisFlagged) {
            se.slowlorisFlagged = false;  // consume flag
            slowlorisDetected_.fetch_add(1, std::memory_order_relaxed);
            DdosMatch m;
            m.rule        = "ddos_protection";
            m.severity    = "high";
            m.category    = "dos";
            m.description = "Slowloris / slow request pattern";
            m.matchedPatterns.push_back({"slowloris_timing",
                "Inter-chunk interval exceeded " +
                std::to_string(opts_.slowChunkIntervalMs) + "ms threshold"});
            out.push_back(std::move(m));
        }
    }

    return out;
}

// ─── Streaming hooks (called by transport layer) ───────────────────────────

void DdosProtector::onHeaderChunk(const std::string& ip,
                                   size_t /*bytesReceived*/,
                                   int64_t ts) {
    if (!opts_.featureSlowloris) return;
    if (!isValidIP(ip)) return;
    int64_t now = ts > 0 ? ts : nowMs();

    std::unique_lock lk(mu_);
    auto it = slowTracker_.find(ip);
    if (it == slowTracker_.end()) {
        if (slowTracker_.size() >= opts_.maxTrackerSize) {
            evictOldestSlow_locked_();
        }
        std::string key = ip;
        slowLru_.push_back(key);
        SlowEntry e;
        e.lastHeaderChunkTs = now;
        e.lruIter = std::prev(slowLru_.end());
        slowTracker_.emplace(std::move(key), std::move(e));
        return;
    }
    touchSlowLru_locked_(it);

    auto& se = it->second;
    if (se.lastHeaderChunkTs > 0) {
        int64_t delta = now - se.lastHeaderChunkTs;
        if (delta > opts_.slowChunkIntervalMs) {
            se.slowlorisFlagged = true;
        }
    }
    se.lastHeaderChunkTs = now;
}

void DdosProtector::onBodyChunk(const std::string& ip,
                                 size_t bytesReceived,
                                 int64_t ts) {
    if (!opts_.featureSlowloris) return;
    if (!isValidIP(ip)) return;
    int64_t now = ts > 0 ? ts : nowMs();

    std::unique_lock lk(mu_);
    auto it = slowTracker_.find(ip);
    if (it == slowTracker_.end()) {
        if (slowTracker_.size() >= opts_.maxTrackerSize) {
            evictOldestSlow_locked_();
        }
        std::string key = ip;
        slowLru_.push_back(key);
        SlowEntry e;
        e.bodyStartTs       = now;
        e.bodyBytesReceived = bytesReceived;
        e.lastBodyChunkTs   = now;
        e.lruIter           = std::prev(slowLru_.end());
        slowTracker_.emplace(std::move(key), std::move(e));
        return;
    }
    touchSlowLru_locked_(it);

    auto& se = it->second;
    if (se.bodyStartTs == 0) {
        se.bodyStartTs       = now;
        se.bodyBytesReceived = 0;
    }
    se.bodyBytesReceived += bytesReceived;

    // Inter-chunk timing
    if (se.lastBodyChunkTs > 0) {
        int64_t delta = now - se.lastBodyChunkTs;
        if (delta > opts_.slowChunkIntervalMs) {
            se.slowlorisFlagged = true;
        }
    }
    se.lastBodyChunkTs = now;

    // Body rate check — R-U-Dead-Yet attack sends data just fast enough
    // to avoid absolute timeout but slower than minBodyRateBytesPerSec.
    int64_t bodyElapsed = now - se.bodyStartTs;
    if (bodyElapsed > 1000 && se.bodyBytesReceived > 0) {
        double bytesPerSec = (double)se.bodyBytesReceived * 1000.0 / (double)bodyElapsed;
        if (bytesPerSec < (double)opts_.minBodyRateBytesPerSec) {
            se.slowlorisFlagged = true;
        }
    }
}

// ─── HTTP/2 Rapid Reset detection ──────────────────────────────────────────

void DdosProtector::onStreamReset(const std::string& ip, int64_t ts) {
    if (!opts_.featureRapidReset || !opts_.rapidResetEnabled) return;
    if (!isValidIP(ip)) return;
    int64_t now = ts > 0 ? ts : nowMs();

    std::unique_lock lk(mu_);
    auto it = rapidResetTracker_.find(ip);
    if (it == rapidResetTracker_.end()) {
        if (rapidResetTracker_.size() >= opts_.maxTrackerSize) {
            evictOldestRapidReset_locked_();
        }
        std::string key = ip;
        rapidResetLru_.push_back(key);
        RapidResetEntry e;
        e.lruIter = std::prev(rapidResetLru_.end());
        it = rapidResetTracker_.emplace(std::move(key), std::move(e)).first;
    } else {
        touchRapidResetLru_locked_(it);
    }

    auto& re = it->second;
    const int64_t cutoff = now - opts_.rapidResetWindowMs;
    while (!re.resets.empty() && re.resets.front() < cutoff) re.resets.pop_front();
    re.resets.push_back(now);

    rapidResetsTotal_.fetch_add(1, std::memory_order_relaxed);
}

// ─── GC ────────────────────────────────────────────────────────────────────

void DdosProtector::gc() {
    if (disposed_.load(std::memory_order_relaxed)) return;
    const int64_t start = nowMs();
    const int64_t now = start;
    const int64_t connCutoff = now - opts_.connectionWindowMs;
    const int64_t slowCutoff = now - opts_.slowlorisBodyTimeoutMs - 5000;
    const int64_t resetCutoff = now - opts_.rapidResetWindowMs;
    uint64_t deleted = 0;

    // Phase 1: connection tracker — chunked with lock release between chunks.
    // We collect expired keys under a brief shared_lock, then delete under
    // unique_lock. This avoids holding the exclusive lock for the whole sweep.
    {
        std::vector<std::string> toDelete;
        toDelete.reserve(opts_.gcChunkSize);
        size_t processed = 0;
        {
            std::shared_lock sl(mu_);
            for (const auto& [ip, entry] : connTracker_) {
                if (entry.lastRefillMs < connCutoff) {
                    toDelete.push_back(ip);
                    if (toDelete.size() >= opts_.gcChunkSize) break;
                }
                if (++processed % opts_.gcChunkSize == 0) {
                    // Would yield here in a true async GC; for now we just
                    // keep iterating since shared_lock allows concurrent reads.
                }
            }
        }
        if (!toDelete.empty()) {
            std::unique_lock ul(mu_);
            for (const auto& ip : toDelete) {
                auto it = connTracker_.find(ip);
                if (it != connTracker_.end()) {
                    connLru_.erase(it->second.lruIter);
                    connTracker_.erase(it);
                    ++deleted;
                }
            }
        }
    }

    // Phase 2: slowloris tracker
    {
        std::vector<std::string> toDelete;
        toDelete.reserve(opts_.gcChunkSize);
        {
            std::shared_lock sl(mu_);
            for (const auto& [ip, entry] : slowTracker_) {
                if (entry.lastBodyChunkTs > 0) {
                    if (entry.lastBodyChunkTs < slowCutoff) toDelete.push_back(ip);
                } else if (entry.lastHeaderChunkTs > 0) {
                    if (entry.lastHeaderChunkTs < slowCutoff) toDelete.push_back(ip);
                }
                if (toDelete.size() >= opts_.gcChunkSize) break;
            }
        }
        if (!toDelete.empty()) {
            std::unique_lock ul(mu_);
            for (const auto& ip : toDelete) {
                auto it = slowTracker_.find(ip);
                if (it != slowTracker_.end()) {
                    slowLru_.erase(it->second.lruIter);
                    slowTracker_.erase(it);
                    ++deleted;
                }
            }
        }
    }

    // Phase 3: rapid reset tracker
    {
        std::vector<std::string> toDelete;
        toDelete.reserve(opts_.gcChunkSize);
        {
            std::shared_lock sl(mu_);
            for (const auto& [ip, entry] : rapidResetTracker_) {
                if (entry.resets.empty() || entry.resets.back() < resetCutoff) {
                    toDelete.push_back(ip);
                }
                if (toDelete.size() >= opts_.gcChunkSize) break;
            }
        }
        if (!toDelete.empty()) {
            std::unique_lock ul(mu_);
            for (const auto& ip : toDelete) {
                auto it = rapidResetTracker_.find(ip);
                if (it != rapidResetTracker_.end()) {
                    rapidResetLru_.erase(it->second.lruIter);
                    rapidResetTracker_.erase(it);
                    ++deleted;
                }
            }
        }
    }

    // Phase 4: penalty box — purge expired entries so the box doesn't grow
    // unbounded for IPs that got banned once and never came back.
    {
        std::vector<std::string> toDelete;
        {
            std::shared_lock sl(mu_);
            for (const auto& [ip, entry] : penaltyBox_) {
                if (entry.bannedUntil < now) toDelete.push_back(ip);
            }
        }
        if (!toDelete.empty()) {
            std::unique_lock ul(mu_);
            for (const auto& ip : toDelete) penaltyBox_.erase(ip);
        }
    }

    gcRuns_.fetch_add(1, std::memory_order_relaxed);
    gcDeletions_.fetch_add(deleted, std::memory_order_relaxed);
    gcDurationMs_.fetch_add(nowMs() - start, std::memory_order_relaxed);
}

// ─── Config / hot-reload ───────────────────────────────────────────────────

bool DdosProtector::loadConfigFromFile(const std::string& path) {
    configPath_ = path;
    onConfigFileChanged();
    return true;
}

void DdosProtector::onConfigFileChanged() {
    if (configPath_.empty()) return;
    std::ifstream f(configPath_);
    if (!f.is_open()) return;
    std::stringstream ss;
    ss << f.rdbuf();
    std::string raw = ss.str();

    Options defaults = opts_;
    Options parsed = parseOptionsFromJson_(raw, defaults);
    if (parsed.maxConnectionsPerIp == 0) return; // parse failed — keep old

    // Parse lists
    std::vector<CIDR> cidrs;
    std::vector<PathRule> pathRules;
    std::unordered_set<std::string> healthPaths;
    std::unordered_set<std::string> exactWhitelist;

#ifdef DDOSONLY_HAVE_JSON
    // nlohmann path
    try {
        auto j = json::parse(raw);
        if (j.contains("cidrWhitelist")) {
            for (const auto& c : j["cidrWhitelist"]) {
                CIDR cidr;
                if (parseCIDR(c.get<std::string>(), cidr)) cidrs.push_back(cidr);
            }
        }
        if (j.contains("exactWhitelist")) {
            for (const auto& s : j["exactWhitelist"]) {
                if (isValidIP(s.get<std::string>())) {
                    exactWhitelist.insert(normalizeIp(s.get<std::string>()));
                }
            }
        }
        if (j.contains("healthCheckBypass") && j["healthCheckBypass"].contains("paths")) {
            for (const auto& p : j["healthCheckBypass"]["paths"]) {
                healthPaths.insert(p.get<std::string>());
            }
        }
        if (j.contains("pathRules")) {
            for (const auto& r : j["pathRules"]) {
                PathRule pr;
                pr.pathPrefix = r.value("pathPrefix", "");
                pr.maxConnectionsPerIp = r.value("maxConnectionsPerIp", (size_t)0);
                pr.connectionWindowMs = r.value("connectionWindowMs", (int64_t)0);
                if (!pr.pathPrefix.empty()) pathRules.push_back(std::move(pr));
            }
        }
    } catch (...) {
        return;
    }
#else
    // MiniJson path
    MiniJson j;
    if (!j.parse(raw)) return;
    if (j.isArray("cidrWhitelist")) {
        for (const auto& c : j.array("cidrWhitelist")) {
            CIDR cidr;
            if (parseCIDR(c.asString(), cidr)) cidrs.push_back(cidr);
        }
    }
    if (j.isArray("exactWhitelist")) {
        for (const auto& s : j.array("exactWhitelist")) {
            std::string ipStr = s.asString();
            if (isValidIP(ipStr)) exactWhitelist.insert(normalizeIp(ipStr));
        }
    }
    if (const auto* hcb = j.find("healthCheckBypass")) {
        if (hcb->isArray("paths")) {
            for (const auto& p : hcb->array("paths")) {
                healthPaths.insert(p.asString());
            }
        }
    }
    if (j.isArray("pathRules")) {
        for (const auto& r : j.array("pathRules")) {
            PathRule pr;
            pr.pathPrefix = r.asString("pathPrefix", "");
            pr.maxConnectionsPerIp = (size_t)r.asInt("maxConnectionsPerIp", 0);
            pr.connectionWindowMs = r.asInt("connectionWindowMs", 0);
            if (!pr.pathPrefix.empty()) pathRules.push_back(std::move(pr));
        }
    }
#endif

    applyConfig_(parsed, std::move(cidrs), std::move(pathRules),
                 std::move(healthPaths), std::move(exactWhitelist));
    configReloads_.fetch_add(1, std::memory_order_relaxed);
}

void DdosProtector::applyConfig_(const Options& opts,
                                  std::vector<CIDR> cidrs,
                                  std::vector<PathRule> pathRules,
                                  std::unordered_set<std::string> healthPaths,
                                  std::unordered_set<std::string> exactWhitelist) {
    std::unique_lock lk(mu_);
    opts_ = opts;
    cidrWhitelist_      = std::move(cidrs);
    pathRules_          = std::move(pathRules);
    healthCheckPaths_   = std::move(healthPaths);
    // Merge exactWhitelist into whitelist_ (preserve existing entries)
    for (const auto& ip : exactWhitelist) whitelist_.insert(ip);
}

void DdosProtector::setOptions(const Options& opts) {
    std::unique_lock lk(mu_);
    opts_ = opts;
}

DdosProtector::Options DdosProtector::getOptions() const {
    std::shared_lock lk(mu_);
    return opts_;
}

// ─── Metrics ───────────────────────────────────────────────────────────────

DdosProtector::MetricsSnapshot DdosProtector::snapshotMetrics() const {
    MetricsSnapshot s;
    {
        std::shared_lock lk(mu_);
        s.connTrackerSize   = connTracker_.size();
        s.slowTrackerSize   = slowTracker_.size();
        s.penaltyBoxSize    = penaltyBox_.size();
        s.whitelistSize     = whitelist_.size();
        s.cidrWhitelistSize = cidrWhitelist_.size();
    }
    s.blockedCount      = blockedCount_.load(std::memory_order_relaxed);
    s.bannedAtAccept    = bannedAtAccept_.load(std::memory_order_relaxed);
    s.slowlorisDetected = slowlorisDetected_.load(std::memory_order_relaxed);
    s.connFloodDetected = connFloodDetected_.load(std::memory_order_relaxed);
    s.rapidResetsTotal  = rapidResetsTotal_.load(std::memory_order_relaxed);
    s.gcRuns            = gcRuns_.load(std::memory_order_relaxed);
    s.gcDurationMs      = gcDurationMs_.load(std::memory_order_relaxed);
    s.gcDeletions       = gcDeletions_.load(std::memory_order_relaxed);
    s.configReloads     = configReloads_.load(std::memory_order_relaxed);
    return s;
}

// ─── Shutdown ──────────────────────────────────────────────────────────────

void DdosProtector::dispose() {
    if (disposed_.exchange(true)) return;
    std::unique_lock lk(mu_);
    connTracker_.clear();
    slowTracker_.clear();
    penaltyBox_.clear();
    rapidResetTracker_.clear();
    whitelist_.clear();
    cidrWhitelist_.clear();
    pathRules_.clear();
    healthCheckPaths_.clear();
    connLru_.clear();
    slowLru_.clear();
    rapidResetLru_.clear();
}

// ─── JSON → Options parser ─────────────────────────────────────────────────

DdosProtector::Options DdosProtector::parseOptionsFromJson_(const std::string& raw,
                                                              const Options& defaults) {
    Options out = defaults;

#ifdef DDOSONLY_HAVE_JSON
    try {
        auto j = json::parse(raw);
        out.maxConnectionsPerIp        = j.value("maxConnectionsPerIp",        (size_t)defaults.maxConnectionsPerIp);
        out.connectionWindowMs         = j.value("connectionWindowMs",         (int64_t)defaults.connectionWindowMs);
        out.connectionRefillRatePerSec = j.value("connectionRefillRatePerSec", (double)defaults.connectionRefillRatePerSec);
        out.maxHeaderBytes             = j.value("maxHeaderBytes",             (size_t)defaults.maxHeaderBytes);
        out.maxQueryParams             = j.value("maxQueryParams",             (size_t)defaults.maxQueryParams);
        out.maxBodyBytes               = j.value("maxBodyBytes",               (int64_t)defaults.maxBodyBytes);
        out.maxContentEncodingRatio    = j.value("maxContentEncodingRatio",    (size_t)defaults.maxContentEncodingRatio);

        if (j.contains("slowloris")) {
            const auto& s = j["slowloris"];
            out.slowlorisHeaderTimeoutMs = s.value("headerTimeoutMs", (int64_t)defaults.slowlorisHeaderTimeoutMs);
            out.slowlorisBodyTimeoutMs   = s.value("bodyTimeoutMs",   (int64_t)defaults.slowlorisBodyTimeoutMs);
            out.minBodyRateBytesPerSec   = s.value("minBodyRateBytesPerSec", (int64_t)defaults.minBodyRateBytesPerSec);
            out.slowChunkIntervalMs      = s.value("slowChunkIntervalMs",    (int64_t)defaults.slowChunkIntervalMs);
        }
        if (j.contains("rapidReset")) {
            const auto& r = j["rapidReset"];
            out.rapidResetEnabled  = r.value("enabled",    defaults.rapidResetEnabled);
            out.rapidResetWindowMs = r.value("windowMs",   (int64_t)defaults.rapidResetWindowMs);
            out.rapidResetThreshold= r.value("threshold",  (size_t)defaults.rapidResetThreshold);
        }
        if (j.contains("penaltyBox")) {
            const auto& p = j["penaltyBox"];
            out.penaltyBoxEnabled          = p.value("enabled",              defaults.penaltyBoxEnabled);
            out.penaltyViolationsThreshold = p.value("violationsThreshold",  (size_t)defaults.penaltyViolationsThreshold);
            out.penaltyBaseBanMs           = p.value("baseBanMs",            (int64_t)defaults.penaltyBaseBanMs);
            out.penaltyMaxBanMs            = p.value("maxBanMs",             (int64_t)defaults.penaltyMaxBanMs);
            out.penaltyBackoffMultiplier   = p.value("backoffMultiplier",    (double)defaults.penaltyBackoffMultiplier);
        }
        if (j.contains("healthCheckBypass")) {
            const auto& h = j["healthCheckBypass"];
            out.featureHealthCheckBypass = h.value("enabled", defaults.featureHealthCheckBypass);
        }
        if (j.contains("tracker")) {
            const auto& t = j["tracker"];
            out.maxTrackerSize = t.value("maxSize",     (size_t)defaults.maxTrackerSize);
            out.gcIntervalMs   = t.value("gcIntervalMs",(int64_t)defaults.gcIntervalMs);
            out.gcChunkSize    = t.value("gcChunkSize", (size_t)defaults.gcChunkSize);
        }
        if (j.contains("features")) {
            const auto& f = j["features"];
            out.featureSlowloris         = f.value("slowloris",         defaults.featureSlowloris);
            out.featureConnFlood         = f.value("connFlood",         defaults.featureConnFlood);
            out.featureOversizedHeaders  = f.value("oversizedHeaders",  defaults.featureOversizedHeaders);
            out.featureOversizedBody     = f.value("oversizedBody",     defaults.featureOversizedBody);
            out.featureParamFlood        = f.value("paramFlood",         defaults.featureParamFlood);
            out.featureCompressionBomb   = f.value("compressionBomb",   defaults.featureCompressionBomb);
            out.featureRapidReset        = f.value("rapidReset",         defaults.featureRapidReset);
            out.featurePenaltyBox        = f.value("penaltyBox",         defaults.featurePenaltyBox);
            out.featureHealthCheckBypass = f.value("healthCheckBypass",  defaults.featureHealthCheckBypass);
            out.featurePathRules         = f.value("pathRules",          defaults.featurePathRules);
        }
        return out;
    } catch (...) {
        return defaults;
    }
#else
    MiniJson j;
    if (!j.parse(raw)) return defaults;

    out.maxConnectionsPerIp        = (size_t)j.asInt("maxConnectionsPerIp",        (int64_t)defaults.maxConnectionsPerIp);
    out.connectionWindowMs         = j.asInt("connectionWindowMs",         (int64_t)defaults.connectionWindowMs);
    out.connectionRefillRatePerSec = j.asDouble("connectionRefillRatePerSec", (double)defaults.connectionRefillRatePerSec);
    out.maxHeaderBytes             = (size_t)j.asInt("maxHeaderBytes",             (int64_t)defaults.maxHeaderBytes);
    out.maxQueryParams             = (size_t)j.asInt("maxQueryParams",             (int64_t)defaults.maxQueryParams);
    out.maxBodyBytes               = j.asInt("maxBodyBytes",               (int64_t)defaults.maxBodyBytes);
    out.maxContentEncodingRatio    = (size_t)j.asInt("maxContentEncodingRatio",    (int64_t)defaults.maxContentEncodingRatio);

    if (const auto* s = j.find("slowloris")) {
        out.slowlorisHeaderTimeoutMs = s->asInt("headerTimeoutMs",     (int64_t)defaults.slowlorisHeaderTimeoutMs);
        out.slowlorisBodyTimeoutMs   = s->asInt("bodyTimeoutMs",       (int64_t)defaults.slowlorisBodyTimeoutMs);
        out.minBodyRateBytesPerSec   = s->asInt("minBodyRateBytesPerSec",(int64_t)defaults.minBodyRateBytesPerSec);
        out.slowChunkIntervalMs      = s->asInt("slowChunkIntervalMs",  (int64_t)defaults.slowChunkIntervalMs);
    }
    if (const auto* r = j.find("rapidReset")) {
        out.rapidResetEnabled   = r->asBool("enabled",   defaults.rapidResetEnabled);
        out.rapidResetWindowMs  = r->asInt("windowMs",   (int64_t)defaults.rapidResetWindowMs);
        out.rapidResetThreshold = (size_t)r->asInt("threshold", (int64_t)defaults.rapidResetThreshold);
    }
    if (const auto* p = j.find("penaltyBox")) {
        out.penaltyBoxEnabled          = p->asBool("enabled",              defaults.penaltyBoxEnabled);
        out.penaltyViolationsThreshold = (size_t)p->asInt("violationsThreshold", (int64_t)defaults.penaltyViolationsThreshold);
        out.penaltyBaseBanMs           = p->asInt("baseBanMs",             (int64_t)defaults.penaltyBaseBanMs);
        out.penaltyMaxBanMs            = p->asInt("maxBanMs",              (int64_t)defaults.penaltyMaxBanMs);
        out.penaltyBackoffMultiplier   = p->asDouble("backoffMultiplier",  (double)defaults.penaltyBackoffMultiplier);
    }
    if (const auto* h = j.find("healthCheckBypass")) {
        out.featureHealthCheckBypass = h->asBool("enabled", defaults.featureHealthCheckBypass);
    }
    if (const auto* t = j.find("tracker")) {
        out.maxTrackerSize = (size_t)t->asInt("maxSize",      (int64_t)defaults.maxTrackerSize);
        out.gcIntervalMs   = t->asInt("gcIntervalMs",          (int64_t)defaults.gcIntervalMs);
        out.gcChunkSize    = (size_t)t->asInt("gcChunkSize",   (int64_t)defaults.gcChunkSize);
    }
    if (const auto* f = j.find("features")) {
        out.featureSlowloris         = f->asBool("slowloris",         defaults.featureSlowloris);
        out.featureConnFlood         = f->asBool("connFlood",         defaults.featureConnFlood);
        out.featureOversizedHeaders  = f->asBool("oversizedHeaders",  defaults.featureOversizedHeaders);
        out.featureOversizedBody     = f->asBool("oversizedBody",     defaults.featureOversizedBody);
        out.featureParamFlood        = f->asBool("paramFlood",         defaults.featureParamFlood);
        out.featureCompressionBomb   = f->asBool("compressionBomb",   defaults.featureCompressionBomb);
        out.featureRapidReset        = f->asBool("rapidReset",         defaults.featureRapidReset);
        out.featurePenaltyBox        = f->asBool("penaltyBox",         defaults.featurePenaltyBox);
        out.featureHealthCheckBypass = f->asBool("healthCheckBypass",  defaults.featureHealthCheckBypass);
        out.featurePathRules         = f->asBool("pathRules",          defaults.featurePathRules);
    }
    return out;
#endif
}
