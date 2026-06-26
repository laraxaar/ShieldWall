#ifndef RULE_MATCHER_HPP
#define RULE_MATCHER_HPP

/**
 * @file RuleMatcher.hpp
 * @brief Signature Evaluation Engine interpreting DSL parsed rule objects.
 */

#include "WafTypes.hpp"
#include "RuleParser.hpp"
#include "AhoCorasick.hpp"
#include <unordered_set>
#include <string>
#include <vector>

/**
 * @struct MatchData
 * @brief Flat string representation of client request surfaces for pattern execution.
 */
struct MatchData {
    std::string url;
    std::string path;
    std::string body;
    std::string method;
    std::string userAgent;
    std::string ip;
    std::string rawUrl;
    std::string rawBody;
    std::string queryString;
    std::string headerString;
    std::string cookieString;
    std::string sessionId;
    std::string geoipString;
    std::string fingerprintString;
    std::string rateString;
    std::string contentType;
    std::string hostname;
    std::string protocol;
    std::string timestamp;
    std::string full;
};

/**
 * @struct MatcherContext
 * @brief Thread-safe compilation container storing AC index and rule category listings.
 */
struct MatcherContext {
    std::vector<ShieldRule> allRules;
    std::vector<ShieldRule> targetGroupUrl;
    std::vector<ShieldRule> targetGroupBody;
    std::vector<ShieldRule> targetGroupHeaders;
    std::vector<ShieldRule> targetGroupAny;
    AhoCorasick aho;
    std::unordered_set<std::string> literalRules; ///< Names of rules containing mandatory literals
};

/**
 * @class RuleMatcher
 * @brief Evaluator engine executing AST condition node match checking.
 * 
 * MIGRATED FROM: rule-matcher.js
 */
class RuleMatcher {
public:
    /**
     * @brief Normalizes standard decoded request maps into flat payload strings.
     * 
     * MIGRATED FROM: rule-matcher.js -> prepareMatchData()
     */
    static MatchData prepareMatchData(const HttpRequest& d);

    /**
     * @brief Compiles rule definitions into an optimized matching context.
     * 
     * MIGRATED FROM: rule-matcher.js -> compileRules()
     */
    static MatcherContext compileRules(const std::vector<ShieldRule>& rules);

    /**
     * @brief Evaluates inbound requests against compiled rules.
     * 
     * MIGRATED FROM: rule-matcher.js -> matchCompiledRules()
     */
    static std::vector<WafMatch> matchCompiledRules(const MatcherContext& ctx, const HttpRequest& decodedReq);

private:
    /**
     * @brief Tests a pattern definition against target text surface.
     * // MIGRATED FROM: rule-matcher.js -> testPattern()
     */
    static bool testPattern(const RuleString& def, const std::string& text);

    /**
     * @brief Resolves target parameters mapping to internal surfaces.
     * // MIGRATED FROM: rule-matcher.js -> resolveTarget()
     */
    static std::string resolveTarget(const std::string& name, const ShieldRule& rule, const MatchData& md);

    /**
     * @brief Recursive interpreter mapping condition tree node executions.
     * // MIGRATED FROM: rule-matcher.js -> evaluate()
     */
    static bool evaluate(const std::shared_ptr<AstNode>& node, const ShieldRule& rule, const MatchData& md);

    /**
     * @brief Safe formatter converting nested maps into query/body strings.
     * // MIGRATED FROM: rule-matcher.js -> _safeStringify()
     */
    static std::string safeStringify(const std::unordered_map<std::string, std::vector<std::string>>& map);
    static std::string safeStringify(const std::unordered_map<std::string, std::string>& map);
};

#endif // RULE_MATCHER_HPP
