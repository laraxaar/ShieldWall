#ifndef WAF_TYPES_HPP
#define WAF_TYPES_HPP

/**
 * @file WafTypes.hpp
 * @brief Common structures and classes for the WAF Engine.
 * 
 * ROLE IN ARCHITECTURE:
 * Unifies request modeling and threat matching representation across the entire C++ subsystem.
 */

#include <string>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <cmath>

/**
 * @struct HttpRequest
 * @brief Model representing parsed HTTP request fields.
 */
struct HttpRequest {
    std::string method;
    std::string url;
    std::string path;
    std::string ip;
    std::string userAgent;
    std::string body;
    std::unordered_map<std::string, std::vector<std::string>> query;
    std::unordered_map<std::string, std::vector<std::string>> headers;
    std::vector<std::pair<std::string, std::string>> rawHeaders;
    std::unordered_map<std::string, std::string> cookies;
};

/**
 * @struct WafMatch
 * @brief Model representing a specific threat match detected by any engine module.
 */
struct WafMatch {
    std::string rule;
    std::vector<std::string> tags;
    std::string severity;
    std::string category;
    std::string description;
    std::string author;
    std::string sourceFile;
    std::vector<std::pair<std::string, std::string>> matchedPatterns;
    double score = 0.0;
};

/**
 * @struct WafResult
 * @brief Aggregate report from WafEngine analyzeRequest evaluation.
 */
struct WafResult {
    bool blocked = false;
    double riskScore = 0.0;
    std::string highestSeverity = "info";
    std::vector<WafMatch> matches;
    std::vector<std::string> trace;
};

/**
 * @class EwmaTracker
 * @brief Thread-safe Exponentially Weighted Moving Average tracker.
 * 
 * MIGRATED FROM: anomaly.js -> EwmaTracker
 */
class EwmaTracker {
public:
    /**
     * @brief Constructor initializing standard EWMA statistical bounds.
     * @param alpha Weight factor for new values.
     */
    explicit EwmaTracker(double alpha = 0.05)
        : alpha(alpha), mean(0.0), variance(0.0), count(0) {}

    /**
     * @brief Updates internal mean and variance thread-safely.
     * @param x The raw measurement value.
     */
    void update(double x) {
        std::unique_lock<std::shared_mutex> lock(mutex);
        count++;
        if (count == 1) {
            mean = x;
            variance = 0.0;
        } else {
            double diff = x - mean;
            mean += alpha * diff;
            variance = (1.0 - alpha) * (variance + alpha * diff * diff);
        }
    }

    /**
     * @brief Thread-safely fetches calculated mean.
     * @return Current statistical mean.
     */
    double getMean() const {
        std::shared_lock<std::shared_mutex> lock(mutex);
        return mean;
    }

    /**
     * @brief Thread-safely fetches standard deviation.
     * @return Current standard deviation.
     */
    double getStdDev() const {
        std::shared_lock<std::shared_mutex> lock(mutex);
        return std::sqrt(variance);
    }

    /**
     * @brief Computes Z-Score against baseline mean and deviation.
     * @param x Measurement value.
     * @return Z-Score float index.
     */
    double getZScore(double x) const {
        std::shared_lock<std::shared_mutex> lock(mutex);
        if (count < 50 || variance == 0.0) return 0.0;
        double stdDev = std::sqrt(variance);
        return (x - mean) / stdDev;
    }

    /**
     * @brief Retrieves total metrics count processed.
     * @return Total samples size.
     */
    size_t getCount() const {
        std::shared_lock<std::shared_mutex> lock(mutex);
        return count;
    }

private:
    double alpha;
    double mean;
    double variance;
    size_t count;
    mutable std::shared_mutex mutex;
};

#endif // WAF_TYPES_HPP
