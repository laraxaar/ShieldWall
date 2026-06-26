#ifndef SMART_ANOMALY_DETECTOR_HPP
#define SMART_ANOMALY_DETECTOR_HPP

#include "../core/WafTypes.hpp"
#include <shared_mutex>
#include <regex>
#include <chrono>

/**
 * @class SmartAnomalyDetector
 * @brief Hybrid Heuristic Engine (Fuzzy Signature Matching + Behavioral Profiling).
 * 
 * MIGRATED FROM: smart-anomaly.js
 */
class SmartAnomalyDetector {
public:
    /**
     * @brief Constructor for the smart anomaly detector.
     * @param rulesDir Path containing custom `.shield` rules.
     * @param safeMode If true, disables fuzzy comparisons to reduce false positives.
     */
    explicit SmartAnomalyDetector(const std::string& rulesDir = "", bool safeMode = false);
    ~SmartAnomalyDetector();

    /**
     * @brief Processes decoded request parameters, matching signatures and temporal baselines.
     * @param decodedReq client request structure.
     * @return List of heuristic matches.
     * 
     * MIGRATED FROM: smart-anomaly.js -> check()
     */
    std::vector<WafMatch> check(const HttpRequest& decodedReq);

    /**
     * @brief Submits classification feedback to adaptively balance weights.
     * @param signals List of signals triggered.
     * @param result Verdict status ("true_positive" or "false_positive").
     * 
     * MIGRATED FROM: smart-anomaly.js -> feedback()
     */
    void feedback(const std::vector<std::string>& signals, const std::string& result);

    /**
     * @brief Reloads rules from rulesDir directory.
     * 
     * MIGRATED FROM: smart-anomaly.js -> reload()
     */
    void reload();

private:
    struct PatternDef {
        std::string name;
        std::string type;
        std::string pattern;
        std::regex compiled;
        bool hasCompiled = false;
    };

    struct PatternProfile {
        std::string name;
        std::string category;
        std::string severity;
        std::string description;
        std::vector<std::string> targets;
        std::vector<PatternDef> patterns;
        std::string condition;
    };

    struct CategoryProfile {
        std::vector<PatternDef> patterns;
        std::vector<std::string> severities;
        std::vector<std::string> rules;
    };

    struct RequestFeatures {
        std::string url;
        std::string path;
        std::string method;
        std::string query;
        std::string body;
        std::string headers;
        std::string cookies;
        std::string userAgent;
        std::string allFields;
        double entropy = 0.0;
        size_t encodingLayers = 0;
        double specialCharDensity = 0.0;
        size_t controlCharCount = 0;
    };

    struct IndicatorData {
        std::string type;
        double weight = 0.0;
        double baseWeight = 0.0;
        std::string detail;
    };

    struct CategoryMatchDetail {
        std::string pattern;
        std::string field;
        std::string type; // "direct" or "fuzzy"
        double similarity = 0.0;
        double weight = 0.0;
    };

    struct CategoryAnomalyResult {
        double score = 0.0;
        std::string severity;
        std::vector<CategoryMatchDetail> matchedPatterns;
        size_t ruleCount = 0;
    };

    struct SmartAnomalyResult {
        double score = 0.0;
        std::string severity;
        std::vector<IndicatorData> topIndicators;
        std::unordered_map<std::string, CategoryAnomalyResult> categoryScores;
        std::vector<IndicatorData> novelIndicators;
        IndicatorData temporalAnomaly;
        bool hasTemporalAnomaly = false;
    };

    struct AnomalyHistoryEntry {
        std::chrono::system_clock::time_point timestamp;
        double score = 0.0;
        std::vector<std::string> categories;
        std::vector<std::string> indicators;
    };

    struct FeedbackData {
        size_t tp = 0;
        size_t fp = 0;
    };

    // Load and parsing helpers
    void loadRules();
    void buildProfiles();
    void parseShieldFile(const std::string& filePath);

    // Feature extraction helpers
    RequestFeatures extractRequestFeatures(const HttpRequest& decodedReq);
    double calculateEntropy(const std::string& str);
    double calculateChunkEntropy(const std::string& str);
    size_t countEncodingLayers(const std::string& str);
    double charClassRatio(const std::string& str, const std::regex& regex);

    // Scoring engine logic
    std::pair<bool, double> fuzzyPatternMatch(const std::string& value, const PatternDef& patternProfile);
    std::pair<double, std::vector<IndicatorData>> calculateBehavioralScore(const RequestFeatures& features, const std::string& rawFields);
    std::unordered_map<std::string, CategoryAnomalyResult> calculateCategoryAnomaly(const RequestFeatures& features);
    std::vector<IndicatorData> detectCrossFieldCorrelation(const RequestFeatures& features);
    std::vector<IndicatorData> detectNovelAnomalies(const RequestFeatures& features, const std::unordered_map<std::string, CategoryAnomalyResult>& categoryScores);
    bool calculateTemporalAnomaly(const std::string& ip, const SmartAnomalyResult& currentResult, IndicatorData& outAnomaly);
    void updateHistory(const std::string& ip, const SmartAnomalyResult& result);
    
    std::string scoreToSeverity(double score) const;
    double getEffectiveWeight(const std::string& signalType, double baseWeight) const;

    std::string rulesDir;
    bool safeMode;
    double detectionThreshold;

    // Rules representation
    std::unordered_map<std::string, PatternProfile> patternProfiles;
    std::unordered_map<std::string, CategoryProfile> categoryProfiles;
    mutable std::shared_mutex profilesMutex;

    // Temporal storage
    std::unordered_map<std::string, std::vector<AnomalyHistoryEntry>> anomalyHistory;
    mutable std::shared_mutex historyMutex;

    // Feedback learning database
    std::unordered_map<std::string, FeedbackData> feedbackStore;
    mutable std::shared_mutex feedbackMutex;

    // Background cleanups
    void performCleanup();
};

#endif // SMART_ANOMALY_DETECTOR_HPP
