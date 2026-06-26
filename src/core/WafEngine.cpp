#include "WafEngine.hpp"
#include "../modules/AnomalyDetector.hpp"
#include "../modules/SmartAnomalyDetector.hpp"
#include <unordered_set>
#include <algorithm>

WafEngine::WafEngine(const WafOptions& options)
    : options(options) {
    startTime = std::chrono::steady_clock::now();

    anomalyDetector = std::make_unique<AnomalyDetector>();
    smartAnomalyDetector = std::make_unique<SmartAnomalyDetector>(options.rulesDir, options.safeMode);

    // Initialize Sensitivity Multiplier Rules Matrix
    // // MIGRATED FROM: engine.js -> ENDPOINT_SENSITIVITY
    endpointSensitivity.push_back({ std::regex("^\\/(auth|login|register|reset-password|oauth|sso)", std::regex_constants::icase), 2.5 });
    endpointSensitivity.push_back({ std::regex("^\\/(admin|cms|wp-admin|dashboard|control-panel)", std::regex_constants::icase), 3.0 });
    endpointSensitivity.push_back({ std::regex("^\\/api\\/v[0-9]+\\/(payment|checkout|cart|billing)", std::regex_constants::icase), 2.0 });
    endpointSensitivity.push_back({ std::regex("^\\/(search|catalog|public|assets|_next|static)", std::regex_constants::icase), 0.2 });
    endpointSensitivity.push_back({ std::regex(".*"), 1.0 });
}

WafEngine::~WafEngine() {}

void WafEngine::reloadRules() {
    smartAnomalyDetector->reload();
}

std::string WafEngine::extractIP(const HttpRequest& req) const {
    if (options.trustProxy) {
        auto it = req.headers.find("x-forwarded-for");
        if (it == req.headers.end()) it = req.headers.find("X-Forwarded-For");
        if (it != req.headers.end() && !it->second.empty()) {
            // Pick first valid IP from comma-separated list
            std::stringstream ss(it->second[0]);
            std::string ipPart;
            while (std::getline(ss, ipPart, ',')) {
                // Trim
                ipPart.erase(0, ipPart.find_first_not_of(" \t"));
                size_t endpos = ipPart.find_last_not_of(" \t");
                if (endpos != std::string::npos) ipPart = ipPart.substr(0, endpos + 1);

                if (isValidIP(ipPart)) {
                    return ipPart;
                }
            }
        }
    }
    return req.ip.empty() ? "unknown" : req.ip;
}

bool WafEngine::isValidIP(const std::string& ip) const {
    if (ip.empty()) return false;
    static const std::regex ipv4Regex("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    static const std::regex ipv6Regex("^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$");
    return std::regex_match(ip, ipv4Regex) || std::regex_match(ip, ipv6Regex);
}

double WafEngine::getEndpointSensitivity(const std::string& path) const {
    for (auto const& rule : endpointSensitivity) {
        if (std::regex_search(path, rule.pattern)) {
            return rule.multiplier;
        }
    }
    return 1.0;
}

std::string WafEngine::getHighestSeverity(const std::vector<WafMatch>& matches) const {
    static const std::unordered_map<std::string, size_t> severityPriority = {
        { "critical", 4 }, { "high", 3 }, { "medium", 2 }, { "low", 1 }, { "info", 0 }
    };
    std::string highest = "info";
    size_t highestPriority = 0;
    for (auto const& m : matches) {
        auto it = severityPriority.find(m.severity);
        size_t p = it != severityPriority.end() ? it->second : 0;
        if (p > highestPriority) {
            highestPriority = p;
            highest = m.severity;
        }
    }
    return highest;
}

bool WafEngine::isExcluded(const HttpRequest& req) const {
    std::string path = req.path.empty() ? "/" : req.path;
    std::string ip = extractIP(req);

    // IP Exclusion
    if (std::find(options.excludeIPs.begin(), options.excludeIPs.end(), ip) != options.excludeIPs.end()) {
        return true;
    }

    // Path Exclusion
    for (auto const& ex : options.excludePaths) {
        if (path.rfind(ex, 0) == 0) {
            return true;
        }
    }
    return false;
}

WafResult WafEngine::analyzeRequest(const HttpRequest& req, double responseTimeMs) {
    totalRequests++;

    WafResult result;
    result.trace.push_back("engine_entry: method=" + req.method + " path=" + req.path);

    if (isExcluded(req)) {
        result.trace.push_back("engine_exit: reason=whitelist_match");
        return result;
    }

    HttpRequest reqCopy = req;
    reqCopy.ip = extractIP(req);

    // 1. Run Anomaly Detector (anomaly.js logic)
    std::vector<WafMatch> anomalyMatches = anomalyDetector->check(reqCopy, responseTimeMs);
    
    // 2. Run Smart Anomaly Detector (smart-anomaly.js logic)
    std::vector<WafMatch> smartMatches = smartAnomalyDetector->check(reqCopy);

    // Combine Matches
    std::vector<WafMatch> allMatches;
    allMatches.insert(allMatches.end(), anomalyMatches.begin(), anomalyMatches.end());
    allMatches.insert(allMatches.end(), smartMatches.begin(), smartMatches.end());

    result.matches = allMatches;
    result.trace.push_back("detectors_executed: matches=" + std::to_string(allMatches.size()));

    if (allMatches.empty()) {
        result.trace.push_back("engine_exit: reason=clean_request");
        return result;
    }

    // Risk scoring weights
    static const std::unordered_map<std::string, double> SEVERITY_WEIGHTS = {
        { "critical", 100.0 }, { "high", 50.0 }, { "medium", 20.0 }, { "low", 10.0 }, { "info", 1.0 }
    };

    double cumulativeScore = 0.0;
    double sensitivity = getEndpointSensitivity(reqCopy.path);

    for (auto const& match : allMatches) {
        double baseCost = 0.0;
        if (match.score > 0) {
            baseCost = match.score;
        } else {
            auto it = SEVERITY_WEIGHTS.find(match.severity);
            baseCost = it != SEVERITY_WEIGHTS.end() ? it->second : 0.0;
        }
        cumulativeScore += (baseCost * sensitivity);
    }

    // --- Cross-Module Signal Boosting ---
    // // MIGRATED FROM: engine.js -> Risk Aggregation Boosts
    std::unordered_set<std::string> categories;
    bool hasBot = false;
    bool hasPayloadAnomaly = false;

    for (auto const& match : allMatches) {
        categories.insert(match.category);
        if (match.rule.find("fingerprinter") != std::string::npos || match.rule.find("bot") != std::string::npos) {
            hasBot = true;
        }
        if (match.rule.find("anomaly") != std::string::npos || match.rule.find("injection") != std::string::npos) {
            hasPayloadAnomaly = true;
        }
    }

    if (categories.size() >= 3) {
        cumulativeScore *= 1.5;
    }
    if (categories.size() >= 4) {
        cumulativeScore *= 2.0;
    }
    if (hasBot && hasPayloadAnomaly) {
        cumulativeScore *= 1.8;
    }

    result.riskScore = cumulativeScore;
    result.highestSeverity = getHighestSeverity(allMatches);

    // Apply policy decision
    bool blocked = options.mode == "block" && result.riskScore >= options.blockThreshold;
    result.blocked = blocked;

    if (blocked) {
        blockedRequests++;
    }
    detectedThreats += allMatches.size();

    result.trace.push_back("risk_aggregation: score=" + std::to_string(result.riskScore) + " verdict=" + (blocked ? "blocked" : "passed"));

    return result;
}

std::unordered_map<std::string, double> WafEngine::getStats() const {
    std::unordered_map<std::string, double> stats;
    auto now = std::chrono::steady_clock::now();
    double uptime = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();

    stats["totalRequests"] = static_cast<double>(totalRequests.load());
    stats["blockedRequests"] = static_cast<double>(blockedRequests.load());
    stats["detectedThreats"] = static_cast<double>(detectedThreats.load());
    stats["uptime"] = uptime;

    return stats;
}
