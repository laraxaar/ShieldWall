#ifndef WAF_ENGINE_HPP
#define WAF_ENGINE_HPP

#include "WafTypes.hpp"
#include <memory>
#include <atomic>
#include <regex>
#include <mutex>
#include <chrono>

// Forward declarations
class AnomalyDetector;
class SmartAnomalyDetector;

/**
 * @struct WafOptions
 * @brief Structured configuration settings for WafEngine.
 */
struct WafOptions {
    std::string mode = "block";                     ///< WAF operational mode: "block" or "log"
    std::string logLevel = "info";                  ///< Diagnostic output verbosity
    std::string rulesDir = "rules";                 ///< Path to directory containing .shield rules
    double blockThreshold = 100.0;                  ///< Risk score at which block action is triggered
    bool safeMode = false;                          ///< Disable advanced heuristics to prevent FPs
    bool trustProxy = false;                        ///< Respect X-Forwarded-For proxy chain headers
    std::vector<std::string> excludePaths;          ///< Request paths that bypass security analysis
    std::vector<std::string> excludeIPs;            ///< Trusted client IPs that bypass checks
};

/**
 * @class WafEngine
 * @brief Primary orchestrator unifying heuristic signature evaluation and security enforcement.
 * 
 * MIGRATED FROM: engine.js -> ShieldWallEngine
 */
class WafEngine {
public:
    /**
     * @brief Constructs the orchestrator and initializes the sub-module detectors.
     * @param options Configuration options parameter set.
     */
    explicit WafEngine(const WafOptions& options = WafOptions());

    /**
     * @brief Cleans up WAF resources and deletes sub-detectors.
     */
    ~WafEngine();

    // Prevent unsafe copying/assignment
    WafEngine(const WafEngine&) = delete;
    WafEngine& operator=(const WafEngine&) = delete;

    /**
     * @brief Processes an inbound request through the security pipelines.
     * @param req The normalized client request structure.
     * @param responseTimeMs Backend response delay tracked for injection analysis.
     * @return Result containing security decisions, matches, and risk scores.
     * 
     * MIGRATED FROM: engine.js -> analyze()
     */
    WafResult analyzeRequest(const HttpRequest& req, double responseTimeMs = 0.0);

    /**
     * @brief Triggers a reload of all rules across engine modules.
     * 
     * MIGRATED FROM: engine.js -> reloadRules()
     */
    void reloadRules();

    /**
     * @brief Aggregates runtime statistics.
     * @return Map of statistics metrics.
     * 
     * MIGRATED FROM: engine.js -> getStats()
     */
    std::unordered_map<std::string, double> getStats() const;

private:
    /**
     * @brief Helper to match path/IP against exclusion configuration.
     * // MIGRATED FROM: engine.js -> _isExcluded()
     */
    bool isExcluded(const HttpRequest& req) const;

    /**
     * @brief Resolves canonical request client IP format.
     * // MIGRATED FROM: engine.js -> _extractIP()
     */
    std::string extractIP(const HttpRequest& req) const;

    /**
     * @brief Verifies if string contains valid IP.
     * // MIGRATED FROM: engine.js -> _isValidIP()
     */
    bool isValidIP(const std::string& ip) const;

    /**
     * @brief Performs endpoint pattern weight lookup.
     * // MIGRATED FROM: engine.js -> _getEndpointSensitivity()
     */
    double getEndpointSensitivity(const std::string& path) const;

    /**
     * @brief Resolves max severity string.
     * // MIGRATED FROM: engine.js -> _getHighestSeverity()
     */
    std::string getHighestSeverity(const std::vector<WafMatch>& matches) const;

    WafOptions options;

    std::unique_ptr<AnomalyDetector> anomalyDetector;
    std::unique_ptr<SmartAnomalyDetector> smartAnomalyDetector;

    // Thread-safe request metrics
    std::atomic<uint64_t> totalRequests{0};
    std::atomic<uint64_t> blockedRequests{0};
    std::atomic<uint64_t> detectedThreats{0};
    std::chrono::steady_clock::time_point startTime;

    // Sensitivity pattern mappings
    struct SensitivityRule {
        std::regex pattern;
        double multiplier;
    };
    std::vector<SensitivityRule> endpointSensitivity;
};

#endif // WAF_ENGINE_HPP
