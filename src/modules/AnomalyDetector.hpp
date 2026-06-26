#ifndef ANOMALY_DETECTOR_HPP
#define ANOMALY_DETECTOR_HPP

#include "../core/WafTypes.hpp"
#include <shared_mutex>
#include <mutex>
#include <regex>
#include <chrono>

/**
 * @class AnomalyDetector
 * @brief Heuristic Character & Distribution Analysis Engine.
 * 
 * MIGRATED FROM: anomaly.js
 */
class AnomalyDetector {
public:
    AnomalyDetector();
    ~AnomalyDetector();

    /**
     * @brief Evaluates an HTTP request for character distribution anomalies.
     * @param decodedReq The normalized request details.
     * @param responseTimeMs Inbound trace response latency.
     * @return List of anomaly match findings.
     * 
     * MIGRATED FROM: anomaly.js -> check()
     */
    std::vector<WafMatch> check(const HttpRequest& decodedReq, double responseTimeMs = 0.0);

private:
    struct ParamStats {
        EwmaTracker entropy;
        EwmaTracker specialRatio;
        std::unordered_map<std::string, size_t> types;
    };

    struct PathStats {
        EwmaTracker entropy;
        EwmaTracker specialRatio;
        std::chrono::system_clock::time_point lastSeen;
        std::unordered_map<std::string, ParamStats> paramProfiles;
        std::unordered_map<std::string, size_t> shapeFrequency;
    };

    struct MutationData {
        size_t count = 0;
        std::chrono::system_clock::time_point ts;
    };

    struct ResourceHistory {
        std::string id;
        std::chrono::system_clock::time_point ts;
    };

    // Helper baseline retrieval method
    PathStats& getStats(const std::string& path);
    ParamStats& getParamStats(PathStats& pathStats, const std::string& key);

    // Analysis heuristics
    double charClassRatio(const std::string& str, const std::regex& regex);
    size_t detectMixedEncoding(const std::string& str);
    size_t countEncodingLayers(const std::string& str);
    size_t nestingDepth(const std::string& str);
    double repeatingRatio(const std::string& str);
    double calculateEntropy(const std::string& str);
    std::vector<std::string> detectParameterPollution(const HttpRequest& decodedReq);
    std::vector<std::string> detectRawBytes(const std::string& str);
    bool detectPayloadInflation(const HttpRequest& decodedReq, double& avgSize, size_t& keyCount, size_t& totalSize);
    std::vector<std::string> detectNakedRequest(const std::unordered_map<std::string, std::vector<std::string>>& headers, const std::string& userAgent);
    std::vector<std::string> detectRichHeaderAnomaly(const std::string& method, const std::unordered_map<std::string, std::vector<std::string>>& headers, const std::vector<std::pair<std::string, std::string>>& rawHeaders, const std::string& userAgent);
    size_t detectInvisibleChars(const std::string& str);
    std::vector<std::string> detectMalformedJsonKeys(const HttpRequest& decodedReq);
    bool detectSSTI(const std::string& str);
    bool detectEmptyBody(const std::unordered_map<std::string, std::vector<std::string>>& headers, const std::string& body);
    bool detectPaddingEvasion(const std::string& str);
    bool detectFragmentedWords(const std::string& str);
    bool detectExecutablePayload(const std::string& str);
    double calculateCodeRatio(const std::string& str);
    size_t detectHomoglyphs(const std::string& str);
    double calculateNgramDeviation(const std::string& str);
    bool detectLocalEntropySpike(const std::string& str, size_t windowSize = 32, size_t step = 16);
    std::string getParamType(const std::string& val);
    std::vector<std::string> detectRequestSmuggling(const HttpRequest& decodedReq);
    size_t checkRaceCondition(const HttpRequest& decodedReq);
    size_t detectSlowBOLA(const std::string& ip, const std::string& paramName, const std::string& paramValue);
    size_t detectGraphQLAbuse(const HttpRequest& decodedReq);
    bool detectHeaderCRLFInjection(const HttpRequest& decodedReq);
    std::string getRequestShape(const HttpRequest& decodedReq);
    bool detectObfuscatedJNDI(const std::string& str);

    // Thread-safe baselines storage
    std::unordered_map<std::string, PathStats> statsMap;
    mutable std::shared_mutex statsMutex;

    // Behavioral state caches and temporal metrics
    std::unordered_map<std::string, MutationData> mutationCache;
    std::unordered_map<std::string, std::vector<std::chrono::system_clock::time_point>> concurrencyMap;
    std::unordered_map<std::string, std::vector<ResourceHistory>> resourceHistogram;
    mutable std::mutex tempMapsMutex;

    // Background baselines cleaner
    void performCleanup();
};

#endif // ANOMALY_DETECTOR_HPP
