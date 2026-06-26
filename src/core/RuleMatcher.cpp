#include "RuleMatcher.hpp"
#include <chrono>
#include <sstream>
#include <algorithm>

static std::string safeStringify(const std::unordered_map<std::string, std::vector<std::string>>& map) {
    std::string result;
    static const std::unordered_set<std::string> blocked = { "__proto__", "constructor", "prototype" };
    for (auto const& [k, v] : map) {
        if (blocked.count(k)) continue;
        for (auto const& val : v) {
            if (!result.empty()) result += "&";
            result += k + "=" + val;
        }
    }
    return result;
}

static std::string safeStringify(const std::unordered_map<std::string, std::string>& map) {
    std::string result;
    static const std::unordered_set<std::string> blocked = { "__proto__", "constructor", "prototype" };
    for (auto const& [k, v] : map) {
        if (blocked.count(k)) continue;
        if (!result.empty()) result += "&";
        result += k + "=" + v;
    }
    return result;
}

MatchData RuleMatcher::prepareMatchData(const HttpRequest& d) {
    MatchData md;
    md.url = d.url;
    md.path = d.path;
    md.body = d.body;
    md.method = d.method;
    md.userAgent = d.userAgent;
    md.ip = d.ip;
    md.rawUrl = d.url;
    md.rawBody = d.body;
    md.sessionId = "";

    md.queryString = ::safeStringify(d.query);
    md.headerString = ::safeStringify(d.headers);
    md.cookieString = ::safeStringify(d.cookies);

    md.timestamp = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count());

    auto ctIt = d.headers.find("content-type");
    if (ctIt == d.headers.end()) ctIt = d.headers.find("Content-Type");
    if (ctIt != d.headers.end() && !ctIt->second.empty()) md.contentType = ctIt->second[0];

    auto hostIt = d.headers.find("host");
    if (hostIt == d.headers.end()) hostIt = d.headers.find("Host");
    if (hostIt != d.headers.end() && !hostIt->second.empty()) md.hostname = hostIt->second[0];

    md.protocol = "http";
    md.full = md.url + "\n" + md.queryString + "\n" + md.body + "\n" + md.headerString + "\n" + md.cookieString;
    return md;
}

bool RuleMatcher::testPattern(const RuleString& def, const std::string& text) {
    if (!def.hasCompiled || text.empty()) return false;
    return std::regex_search(text, def.compiled);
}

std::string RuleMatcher::resolveTarget(const std::string& name, const ShieldRule& rule, const MatchData& md) {
    static const std::unordered_map<std::string, std::string> TARGET_MAP = {
        { "request.url", "url" }, { "request.path", "path" }, { "request.body", "body" },
        { "request.query", "queryString" }, { "request.headers", "headerString" },
        { "request.cookies", "cookieString" }, { "request.method", "method" },
        { "request.useragent", "userAgent" }, { "request.user_agent", "userAgent" },
        { "request.ip", "ip" }, { "request.raw_url", "rawUrl" }, { "request.raw_body", "rawBody" },
        { "request.session", "sessionId" }, { "request.sessionid", "sessionId" },
        { "request.timestamp", "timestamp" }, { "request.time", "timestamp" },
        { "request.geoip", "geoipString" }, { "request.geo", "geoipString" },
        { "request.fingerprint", "fingerprintString" }, { "request.fp", "fingerprintString" },
        { "request.rate", "rateString" },
        { "request.content_type", "contentType" }, { "request.hostname", "hostname" },
        { "request.protocol", "protocol" }
    };

    auto it = rule.targets.find(name);
    if (it != rule.targets.end()) {
        std::string targetVar = it->second;
        auto mapIt = TARGET_MAP.find(targetVar);
        std::string mapped = mapIt != TARGET_MAP.end() ? mapIt->second : targetVar;
        
        if (mapped == "url") return md.url;
        if (mapped == "path") return md.path;
        if (mapped == "body") return md.body;
        if (mapped == "queryString") return md.queryString;
        if (mapped == "headerString") return md.headerString;
        if (mapped == "cookieString") return md.cookieString;
        if (mapped == "method") return md.method;
        if (mapped == "userAgent") return md.userAgent;
        if (mapped == "ip") return md.ip;
        if (mapped == "rawUrl") return md.rawUrl;
        if (mapped == "rawBody") return md.rawBody;
        if (mapped == "sessionId") return md.sessionId;
        if (mapped == "geoipString") return md.geoipString;
        if (mapped == "fingerprintString") return md.fingerprintString;
        if (mapped == "rateString") return md.rateString;
        if (mapped == "contentType") return md.contentType;
        if (mapped == "hostname") return md.hostname;
        if (mapped == "protocol") return md.protocol;
        if (mapped == "timestamp") return md.timestamp;
    }
    return md.full;
}

bool RuleMatcher::evaluate(const std::shared_ptr<AstNode>& node, const ShieldRule& rule, const MatchData& md) {
    if (!node) return true;
    if (node->type == "and") {
        return evaluate(node->left, rule, md) && evaluate(node->right, rule, md);
    }
    if (node->type == "or") {
        return evaluate(node->left, rule, md) || evaluate(node->right, rule, md);
    }
    if (node->type == "not") {
        return !evaluate(node->expr, rule, md);
    }
    if (node->type == "match") {
        auto it = rule.strings.find(node->pattern);
        if (it != rule.strings.end()) {
            return testPattern(it->second, md.full);
        }
        return false;
    }
    if (node->type == "match_in") {
        auto it = rule.strings.find(node->pattern);
        if (it != rule.strings.end()) {
            return testPattern(it->second, resolveTarget(node->target, rule, md));
        }
        return false;
    }
    if (node->type == "any_of_them") {
        for (auto const& [name, def] : rule.strings) {
            if (testPattern(def, md.full)) return true;
        }
        return false;
    }
    if (node->type == "all_of_them") {
        for (auto const& [name, def] : rule.strings) {
            if (!testPattern(def, md.full)) return false;
        }
        return true;
    }
    if (node->type == "any_of") {
        for (auto const& v : node->vars) {
            auto it = rule.strings.find(v);
            if (it != rule.strings.end() && testPattern(it->second, md.full)) return true;
        }
        return false;
    }
    if (node->type == "all_of") {
        for (auto const& v : node->vars) {
            auto it = rule.strings.find(v);
            if (it == rule.strings.end() || !testPattern(it->second, md.full)) return false;
        }
        return true;
    }
    if (node->type == "boolean") {
        return node->booleanValue;
    }
    return false;
}

MatcherContext RuleMatcher::compileRules(const std::vector<ShieldRule>& rules) {
    MatcherContext ctx;
    ctx.allRules = rules;

    for (auto const& rule : rules) {
        bool hasLiteral = false;
        std::string targetCategory = "any";
        
        bool bodyOnly = true;
        bool urlOnly = true;
        bool headersOnly = true;
        
        if (rule.targets.empty()) {
            bodyOnly = urlOnly = headersOnly = false;
        } else {
            for (auto const& [var, target] : rule.targets) {
                if (target.find("body") == std::string::npos) bodyOnly = false;
                if (target.find("url") == std::string::npos && 
                    target.find("path") == std::string::npos && 
                    target.find("query") == std::string::npos) urlOnly = false;
                if (target.find("header") == std::string::npos && 
                    target.find("cookie") == std::string::npos && 
                    target.find("useragent") == std::string::npos) headersOnly = false;
            }
        }
        
        if (bodyOnly) targetCategory = "body";
        else if (urlOnly) targetCategory = "url";
        else if (headersOnly) targetCategory = "headers";
        
        if (targetCategory == "body") ctx.targetGroupBody.push_back(rule);
        else if (targetCategory == "url") ctx.targetGroupUrl.push_back(rule);
        else if (targetCategory == "headers") ctx.targetGroupHeaders.push_back(rule);
        else ctx.targetGroupAny.push_back(rule);
        
        for (auto const& [name, def] : rule.strings) {
            if (def.type == "literal" && def.pattern.length() >= 3) {
                std::string kw = def.pattern;
                if (def.nocase) {
                    std::transform(kw.begin(), kw.end(), kw.begin(), ::tolower);
                }
                ctx.aho.add(kw, rule.name);
                hasLiteral = true;
            }
        }
        if (hasLiteral) {
            ctx.literalRules.insert(rule.name);
        }
    }
    ctx.aho.build();
    return ctx;
}

std::vector<WafMatch> RuleMatcher::matchCompiledRules(const MatcherContext& ctx, const HttpRequest& decodedReq) {
    MatchData md = prepareMatchData(decodedReq);
    std::vector<WafMatch> matches;

    std::vector<ShieldRule> activeRules = ctx.targetGroupAny;
    activeRules.insert(activeRules.end(), ctx.targetGroupUrl.begin(), ctx.targetGroupUrl.end());
    if (!md.body.empty()) {
        activeRules.insert(activeRules.end(), ctx.targetGroupBody.begin(), ctx.targetGroupBody.end());
    }
    if (!md.headerString.empty()) {
        activeRules.insert(activeRules.end(), ctx.targetGroupHeaders.begin(), ctx.targetGroupHeaders.end());
    }

    std::string fullPayloadLower = md.full;
    std::transform(fullPayloadLower.begin(), fullPayloadLower.end(), fullPayloadLower.begin(), ::tolower);
    
    std::vector<std::string> hits = ctx.aho.search(fullPayloadLower);
    std::unordered_set<std::string> fastPathHits(hits.begin(), hits.end());

    for (auto const& rule : activeRules) {
        if (ctx.literalRules.count(rule.name) && !fastPathHits.count(rule.name)) {
            continue;
        }

        if (!evaluate(rule.condition, rule, md)) continue;

        WafMatch match;
        match.rule = rule.name;
        match.tags = rule.tags;

        auto sevIt = rule.meta.find("severity");
        match.severity = sevIt != rule.meta.end() ? sevIt->second : "medium";

        auto catIt = rule.meta.find("category");
        match.category = catIt != rule.meta.end() ? catIt->second : (!rule.tags.empty() ? rule.tags[0] : "unknown");

        auto descIt = rule.meta.find("description");
        match.description = descIt != rule.meta.end() ? descIt->second : "";

        auto authIt = rule.meta.find("author");
        match.author = authIt != rule.meta.end() ? authIt->second : "ShieldWall";

        match.sourceFile = rule.sourceFile.empty() ? "inline" : rule.sourceFile;

        for (auto const& [name, def] : rule.strings) {
            if (testPattern(def, md.full)) {
                match.matchedPatterns.push_back({ name, "(matched)" });
            }
        }
        matches.push_back(std::move(match));
    }
    return matches;
}
