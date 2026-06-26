#include "SmartAnomalyDetector.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <iostream>

SmartAnomalyDetector::SmartAnomalyDetector(const std::string& rulesDir, bool safeMode)
    : rulesDir(rulesDir), safeMode(safeMode) {
    if (this->rulesDir.empty()) {
        this->rulesDir = "rules";
    }
    detectionThreshold = safeMode ? 35.0 : 25.0;
    loadRules();
}

SmartAnomalyDetector::~SmartAnomalyDetector() {}

void SmartAnomalyDetector::reload() {
    std::unique_lock<std::shared_mutex> lock(profilesMutex);
    patternProfiles.clear();
    categoryProfiles.clear();
    loadRules();
}

void SmartAnomalyDetector::loadRules() {
    try {
        if (!std::filesystem::exists(rulesDir)) return;
        for (const auto& entry : std::filesystem::directory_iterator(rulesDir)) {
            if (entry.path().extension() == ".shield") {
                parseShieldFile(entry.path().string());
            }
        }
    } catch (...) {
        // Suppress directory scanning failures
    }
}

void SmartAnomalyDetector::parseShieldFile(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) return;

    std::string line;
    PatternProfile currentProfile;
    bool inMeta = false;
    bool inStrings = false;
    bool inTarget = false;
    bool inCondition = false;
    bool inRule = false;

    static const std::regex ruleRegex(R"(rule\s+(\w+)\s*:\s*(\w+))");
    static const std::regex metaRegex(R"((\w+)\s*=\s*"([^"]+)")");
    static const std::regex targetRegex(R"(\$(\w+)\s*=\s*([\w\.]+))");
    static const std::regex stringRegex(R"(\$(\w+)\s*=\s*\/([^\/]+)\/([a-z]*))");
    static const std::regex literalRegex(R"(\$(\w+)\s*=\s*"([^"]+)")");

    while (std::getline(file, line)) {
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        size_t endpos = line.find_last_not_of(" \t\r\n");
        if (endpos != std::string::npos) line = line.substr(0, endpos + 1);

        if (line.empty()) continue;

        std::smatch match;
        if (std::regex_search(line, match, ruleRegex)) {
            currentProfile = PatternProfile();
            currentProfile.name = match[1];
            currentProfile.category = match[2];
            inRule = true;
            inMeta = false;
            inStrings = false;
            inTarget = false;
            inCondition = false;
            continue;
        }

        if (inRule) {
            if (line.find("meta:") != std::string::npos) {
                inMeta = true; inStrings = false; inTarget = false; inCondition = false;
                continue;
            }
            if (line.find("target:") != std::string::npos) {
                inTarget = true; inMeta = false; inStrings = false; inCondition = false;
                continue;
            }
            if (line.find("strings:") != std::string::npos) {
                inStrings = true; inMeta = false; inTarget = false; inCondition = false;
                continue;
            }
            if (line.find("condition:") != std::string::npos) {
                inCondition = true; inMeta = false; inStrings = false; inTarget = false;
                continue;
            }
            if (line == "}") {
                // Save profile
                patternProfiles[currentProfile.name] = currentProfile;
                
                auto& catProfile = categoryProfiles[currentProfile.category];
                for (auto const& pat : currentProfile.patterns) {
                    catProfile.patterns.push_back(pat);
                }
                catProfile.severities.push_back(currentProfile.severity);
                catProfile.rules.push_back(currentProfile.name);

                inRule = false;
                continue;
            }

            if (inMeta) {
                if (std::regex_search(line, match, metaRegex)) {
                    std::string key = match[1];
                    std::string val = match[2];
                    if (key == "severity") currentProfile.severity = val;
                    else if (key == "description") currentProfile.description = val;
                }
            } else if (inTarget) {
                if (std::regex_search(line, match, targetRegex)) {
                    currentProfile.targets.push_back(match[2]);
                }
            } else if (inStrings) {
                if (std::regex_search(line, match, stringRegex)) {
                    PatternDef def;
                    def.name = match[1];
                    def.type = "regex";
                    def.pattern = match[2];
                    std::string flags = match[3];
                    
                    std::regex_constants::syntax_option_type opt = std::regex_constants::ECMAScript;
                    if (flags.find('i') != std::string::npos) {
                        opt |= std::regex_constants::icase;
                    }
                    try {
                        def.compiled = std::regex(def.pattern, opt);
                        def.hasCompiled = true;
                    } catch(...) {
                        def.hasCompiled = false;
                    }
                    currentProfile.patterns.push_back(std::move(def));
                } else if (std::regex_search(line, match, literalRegex)) {
                    PatternDef def;
                    def.name = match[1];
                    def.type = "literal";
                    def.pattern = match[2];
                    currentProfile.patterns.push_back(std::move(def));
                }
            } else if (inCondition) {
                currentProfile.condition += line + " ";
            }
        }
    }
}

double SmartAnomalyDetector::calculateEntropy(const std::string& str) {
    if (str.length() < 10) return 0.0;
    size_t windowSize = 64;
    if (str.length() <= windowSize) return calculateChunkEntropy(str);
    
    double maxEntropy = 0.0;
    for (size_t i = 0; i < str.length() - windowSize; i += 32) {
        std::string chunk = str.substr(i, windowSize);
        maxEntropy = std::max(maxEntropy, calculateChunkEntropy(chunk));
    }
    return maxEntropy;
}

double SmartAnomalyDetector::calculateChunkEntropy(const std::string& str) {
    std::unordered_map<char, size_t> freq;
    for (char ch : str) freq[ch]++;
    double entropy = 0.0;
    double len = static_cast<double>(str.length());
    for (auto const& [ch, count] : freq) {
        double p = static_cast<double>(count) / len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

static std::string decodeURI(const std::string& str) {
    std::string decoded;
    decoded.reserve(str.length());
    for (size_t i = 0; i < str.length(); ) {
        if (str[i] == '%' && i + 2 < str.length()) {
            char h1 = str[i + 1];
            char h2 = str[i + 2];
            if (std::isxdigit(static_cast<unsigned char>(h1)) && 
                std::isxdigit(static_cast<unsigned char>(h2))) {
                char hex[3] = { h1, h2, '\0' };
                char byte = static_cast<char>(std::strtol(hex, nullptr, 16));
                decoded.push_back(byte);
                i += 3;
                continue;
            }
        }
        decoded.push_back(str[i]);
        i++;
    }
    return decoded;
}

size_t SmartAnomalyDetector::countEncodingLayers(const std::string& str) {
    if (str.empty()) return 0;
    size_t layers = 0;
    std::string current = str;
    for (size_t i = 0; i < 5; ++i) {
        std::string decoded = decodeURI(current);
        if (decoded == current) break;
        current = decoded;
        layers++;
    }
    return layers;
}

double SmartAnomalyDetector::charClassRatio(const std::string& str, const std::regex& regex) {
    if (str.empty()) return 0.0;
    std::sregex_iterator it(str.begin(), str.end(), regex);
    std::sregex_iterator end;
    size_t count = 0;
    for (; it != end; ++it) {
        count += it->length();
    }
    return static_cast<double>(count) / static_cast<double>(str.length());
}

std::pair<bool, double> SmartAnomalyDetector::fuzzyPatternMatch(const std::string& value, const PatternDef& patternProfile) {
    if (value.empty()) return { false, 0.0 };
    bool directMatch = false;
    if (patternProfile.hasCompiled) {
        directMatch = std::regex_search(value, patternProfile.compiled);
    }
    
    if (safeMode) {
        return { directMatch, directMatch ? 1.0 : 0.0 };
    }
    
    double similarity = 0.0;
    std::string patternStr = patternProfile.pattern;
    std::string valLower = value;
    std::transform(valLower.begin(), valLower.end(), valLower.begin(), ::tolower);
    
    if (patternStr.find('|') != std::string::npos) {
        std::stringstream ss(patternStr);
        std::string alt;
        while (std::getline(ss, alt, '|')) {
            alt.erase(std::remove(alt.begin(), alt.end(), '('), alt.end());
            alt.erase(std::remove(alt.begin(), alt.end(), ')'), alt.end());
            alt.erase(0, alt.find_first_not_of(" \t"));
            size_t endpos = alt.find_last_not_of(" \t");
            if (endpos != std::string::npos) alt = alt.substr(0, endpos + 1);
            
            if (alt.length() > 3 && valLower.find(alt) != std::string::npos) {
                similarity = std::max(similarity, 0.7);
            }
        }
    }
    
    if (patternStr.find("select") != std::string::npos || patternStr.find("union") != std::string::npos) {
        static const std::vector<std::string> sql = { "select", "union", "from", "where", "insert", "delete" };
        size_t found = 0;
        for (auto const& s : sql) {
            if (valLower.find(s) != std::string::npos) found++;
        }
        if (found >= 2) similarity = std::max(similarity, 0.6);
    }
    
    if (patternStr.find("script") != std::string::npos || patternStr.find("javascript") != std::string::npos) {
        static const std::vector<std::string> xss = { "script", "alert", "onerror", "onload", "javascript", "eval" };
        size_t found = 0;
        for (auto const& x : xss) {
            if (valLower.find(x) != std::string::npos) found++;
        }
        if (found >= 1) similarity = std::max(similarity, 0.5);
    }
    
    if (patternStr.find("127.0.0.1") != std::string::npos || patternStr.find("localhost") != std::string::npos) {
        static const std::vector<std::string> ssrf = { "localhost", "127.", "0.0.0.0", "169.254", "metadata" };
        size_t found = 0;
        for (auto const& s : ssrf) {
            if (valLower.find(s) != std::string::npos) found++;
        }
        if (found >= 1) similarity = std::max(similarity, 0.8);
    }
    
    if (patternStr.find("admin") != std::string::npos || patternStr.find("role") != std::string::npos) {
        static const std::vector<std::string> mass = { "admin", "role", "permission", "isadmin", "is_root" };
        size_t found = 0;
        for (auto const& m : mass) {
            if (valLower.find(m) != std::string::npos) found++;
        }
        if (found >= 1) similarity = std::max(similarity, 0.75);
    }
    
    return { directMatch, std::min(similarity, 0.95) };
}

SmartAnomalyDetector::RequestFeatures SmartAnomalyDetector::extractRequestFeatures(const HttpRequest& decodedReq) {
    RequestFeatures f;
    f.url = decodedReq.url;
    f.path = decodedReq.path;
    f.method = decodedReq.method;
    std::transform(f.url.begin(), f.url.end(), f.url.begin(), ::tolower);
    std::transform(f.path.begin(), f.path.end(), f.path.begin(), ::tolower);
    std::transform(f.method.begin(), f.method.end(), f.method.begin(), ::toupper);
    
    std::vector<std::string> vals;
    for (auto const& [k, v] : decodedReq.query) {
        for (auto const& val : v) vals.push_back(val.substr(0, 1000));
    }
    f.query = "";
    for (auto const& v : vals) f.query += v + " ";
    std::transform(f.query.begin(), f.query.end(), f.query.begin(), ::tolower);

    vals.clear();
    // Estimate parameters from decodedReq.body string
    f.body = decodedReq.body;
    std::transform(f.body.begin(), f.body.end(), f.body.begin(), ::tolower);

    vals.clear();
    for (auto const& [k, v] : decodedReq.headers) {
        for (auto const& val : v) vals.push_back(val.substr(0, 1000));
    }
    f.headers = "";
    for (auto const& v : vals) f.headers += v + " ";
    std::transform(f.headers.begin(), f.headers.end(), f.headers.begin(), ::tolower);

    vals.clear();
    for (auto const& [k, v] : decodedReq.cookies) {
        vals.push_back(v.substr(0, 1000));
    }
    f.cookies = "";
    for (auto const& v : vals) f.cookies += v + " ";
    std::transform(f.cookies.begin(), f.cookies.end(), f.cookies.begin(), ::tolower);

    f.userAgent = decodedReq.userAgent;
    std::transform(f.userAgent.begin(), f.userAgent.end(), f.userAgent.begin(), ::tolower);

    f.allFields = f.url + " " + f.body + " " + f.query + " " + f.headers + " " + f.cookies;
    
    f.entropy = calculateEntropy(f.allFields);
    f.encodingLayers = countEncodingLayers(f.allFields);
    
    static const std::regex specRegex("[^\\w\\s]");
    f.specialCharDensity = charClassRatio(f.allFields, specRegex);
    
    static const std::regex ctrlRegex("[\\x00-\\x08\\x0b-\\x0c\\x0e-\\x1f\\x7f]");
    std::sregex_iterator it(f.allFields.begin(), f.allFields.end(), ctrlRegex);
    std::sregex_iterator end;
    f.controlCharCount = 0;
    for (; it != end; ++it) f.controlCharCount++;

    return f;
}

std::pair<double, std::vector<SmartAnomalyDetector::IndicatorData>> SmartAnomalyDetector::calculateBehavioralScore(const RequestFeatures& features, const std::string& rawFields) {
    double score = 0.0;
    std::vector<IndicatorData> indicators;
    std::unordered_map<std::string, size_t> seen;

    auto add = [&](double baseWeight, const std::string& type, const std::string& detail) {
        size_t count = seen[type];
        double feedbackWeight = getEffectiveWeight(type, baseWeight);
        double effective = feedbackWeight / (1.0 + static_cast<double>(count) * 0.7);
        seen[type] = count + 1;
        score += effective;
        indicators.push_back({ type, effective, baseWeight, detail });
    };

    if (features.entropy > 5.0 && features.specialCharDensity > 0.15) {
        add(3.0, "high_entropy", "Entropy " + std::to_string(features.entropy) + " + special chars");
    }
    if (features.encodingLayers > 2) {
        add(features.encodingLayers * 2.0, "deep_encoding", std::to_string(features.encodingLayers) + " encoding layers");
    }
    if (features.specialCharDensity > 0.3) {
        add(4.0, "high_special_chars", std::to_string(features.specialCharDensity * 100.0) + "% special chars");
    }
    if (features.controlCharCount > 0) {
        add(features.controlCharCount * 3.0, "control_chars", std::to_string(features.controlCharCount) + " control characters");
    }
    if (rawFields.find('\0') != std::string::npos) {
        add(5.0, "null_byte", "Null byte detected - possible bypass attempt");
    }
    
    static const std::regex mixedRegex("%[0-9a-f]{2}", std::regex_constants::icase);
    static const std::regex hexRegex("\\\\x[0-9a-f]{2}", std::regex_constants::icase);
    if (std::regex_search(rawFields, mixedRegex) && std::regex_search(rawFields, hexRegex)) {
        add(4.0, "mixed_encoding", "Mixed URL and hex encoding");
    }
    if (features.allFields.find("../") != std::string::npos || features.allFields.find("..\\") != std::string::npos) {
        add(5.0, "path_traversal", "Directory traversal patterns");
    }
    
    size_t nestingLevel = 0;
    for (char c : rawFields) {
        if (c == '{' || c == '[') nestingLevel++;
    }
    if (nestingLevel > 15) {
        add(4.0, "excessive_nesting", "High data structure nesting (" + std::to_string(nestingLevel) + " levels)");
    }

    return { score, indicators };
}

std::unordered_map<std::string, SmartAnomalyDetector::CategoryAnomalyResult> SmartAnomalyDetector::calculateCategoryAnomaly(const RequestFeatures& features) {
    std::unordered_map<std::string, CategoryAnomalyResult> categoryScores;

    std::shared_lock<std::shared_mutex> lock(profilesMutex);
    for (auto const& [category, profile] : categoryProfiles) {
        double catScore = 0.0;
        std::vector<CategoryMatchDetail> matched;

        auto evaluateField = [&](const std::string& fieldName, const std::string& val) {
            for (auto const& pattern : profile.patterns) {
                auto matchRes = fuzzyPatternMatch(val, pattern);
                if (matchRes.first) {
                    double w = profile.severity == "critical" ? 30.0 : (profile.severity == "high" ? 20.0 : 10.0);
                    catScore += w;
                    matched.push_back({ pattern.name, fieldName, "direct", 1.0, w });
                } else if (matchRes.second > 0.7 && !safeMode) {
                    double w = (profile.severity == "critical" ? 10.0 : 5.0) * matchRes.second;
                    catScore += w;
                    matched.push_back({ pattern.name, fieldName, "fuzzy", matchRes.second, w });
                }
            }
        };

        evaluateField("url", features.url);
        evaluateField("body", features.body);
        evaluateField("query", features.query);
        evaluateField("headers", features.headers);
        evaluateField("cookies", features.cookies);
        evaluateField("userAgent", features.userAgent);

        size_t criticalCount = std::count(profile.severities.begin(), profile.severities.end(), "critical");
        size_t highCount = std::count(profile.severities.begin(), profile.severities.end(), "high");
        catScore += std::min(criticalCount, static_cast<size_t>(2)) + std::min(highCount, static_cast<size_t>(2)) * 0.5;

        if (catScore > 0.0) {
            CategoryAnomalyResult res;
            res.score = catScore;
            res.severity = scoreToSeverity(catScore);
            res.ruleCount = profile.rules.size();
            for (size_t i = 0; i < std::min(matched.size(), static_cast<size_t>(5)); ++i) {
                res.matchedPatterns.push_back(matched[i]);
            }
            categoryScores[category] = std::move(res);
        }
    }

    return categoryScores;
}

std::vector<SmartAnomalyDetector::IndicatorData> SmartAnomalyDetector::detectCrossFieldCorrelation(const RequestFeatures& features) {
    std::vector<IndicatorData> signals;

    auto add = [&](double baseWeight, const std::string& type, const std::string& detail) {
        signals.push_back({ type, getEffectiveWeight(type, baseWeight), baseWeight, detail });
    };

    static const std::regex selectRegex("(select\\s+.*|['\"`;]\\s*select)", std::regex_constants::icase);
    static const std::regex fromRegex("(from\\s+.*|--|#|\\/\\*)", std::regex_constants::icase);
    if (std::regex_search(features.query, selectRegex) && std::regex_search(features.body, fromRegex)) {
        add(6.0, "distributed_sqli", "SELECT in query + FROM/comments in body");
    }

    static const std::regex unionRegex("(union\\s+.*|['\"`;]\\s*union)", std::regex_constants::icase);
    if (std::regex_search(features.url, unionRegex) && std::regex_search(features.body, selectRegex)) {
        add(5.0, "fragmented_union", "UNION/SELECT split across fields");
    }

    if (features.allFields.find("script") != std::string::npos && 
        (features.allFields.find("onerror") != std::string::npos || features.allFields.find("onload") != std::string::npos)) {
        add(4.0, "xss_correlation", "Script tag + event handler");
    }

    if (features.entropy > 5.0 && features.encodingLayers >= 2) {
        add(6.0, "encoded_payload", "High entropy with deep encoding");
    }

    static const std::regex blindPatterns("(sleep\\s*\\(|pg_sleep\\s*\\(|waitfor\\s+delay|benchmark\\s*\\()", std::regex_constants::icase);
    if (std::regex_search(features.allFields, blindPatterns)) {
        add(8.0, "blind_sqli_indicators", "Time-based blind attack functions detected (sleep/waitfor/benchmark)");
    }

    return signals;
}

std::vector<SmartAnomalyDetector::IndicatorData> SmartAnomalyDetector::detectNovelAnomalies(
    const RequestFeatures& features,
    const std::unordered_map<std::string, CategoryAnomalyResult>& categoryScores
) {
    std::vector<IndicatorData> novelIndicators;
    double totalCategoryScore = 0.0;
    for (auto const& [cat, res] : categoryScores) totalCategoryScore += res.score;

    if (totalCategoryScore > 0.0 && totalCategoryScore < 5.0) {
        novelIndicators.push_back({
            "fragmented_attack",
            "Partial indicators across multiple categories - possible evasion attempt",
            getEffectiveWeight("fragmented_attack", 5.0),
            5.0
        });
    }

    if (features.encodingLayers > 1 && totalCategoryScore > 10.0) {
        novelIndicators.push_back({
            "encoded_attack",
            "Encoded payload with attack indicators - likely obfuscated exploit",
            getEffectiveWeight("encoded_attack", 8.0),
            8.0
        });
    }

    size_t fuzzyCount = 0;
    for (auto const& [cat, res] : categoryScores) {
        for (auto const& pat : res.matchedPatterns) {
            if (pat.type == "fuzzy") {
                fuzzyCount++;
                break;
            }
        }
    }

    if (fuzzyCount >= 2) {
        novelIndicators.push_back({
            "multi_vector_fuzzy",
            "Fuzzy matches in multiple categories - possible variant attack",
            getEffectiveWeight("multi_vector_fuzzy", 6.0),
            6.0
        });
    }

    if (features.controlCharCount > 2 && features.specialCharDensity > 0.2) {
        bool hasKnownCat = false;
        for (auto const& [cat, res] : categoryScores) {
            if (cat == "injection" || cat == "xss" || cat == "ssrf" || cat == "traversal" || cat == "command_injection") {
                hasKnownCat = true;
                break;
            }
        }
        if (!hasKnownCat) {
            novelIndicators.push_back({
                "unknown_binary_payload",
                "Binary payload with control chars - possible novel exploit or protocol abuse",
                getEffectiveWeight("unknown_binary_payload", 7.0),
                7.0
            });
        }
    }

    return novelIndicators;
}

bool SmartAnomalyDetector::calculateTemporalAnomaly(const std::string& ip, const SmartAnomalyResult& currentResult, IndicatorData& outAnomaly) {
    std::shared_lock<std::shared_mutex> lock(historyMutex);
    auto it = anomalyHistory.find(ip);
    if (it == anomalyHistory.end()) return false;
    const auto& history = it->second;
    if (history.size() < 2) return false;

    // Grab recent 5
    size_t recentSize = std::min(history.size(), static_cast<size_t>(5));
    std::vector<AnomalyHistoryEntry> recent(history.end() - recentSize, history.end());

    // 1. Cross-Request Fragmentation check
    static const std::unordered_set<std::string> partialSignals = {
        "sql_indicator", "xss_indicator", "path_indicator"
    };
    bool pastHasSignal = false;
    for (auto const& entry : recent) {
        for (auto const& ind : entry.indicators) {
            if (partialSignals.count(ind)) {
                pastHasSignal = true;
                break;
            }
        }
        if (pastHasSignal) break;
    }

    bool currentHasSignal = false;
    for (auto const& entry : currentResult.topIndicators) {
        if (partialSignals.count(entry.type)) {
            currentHasSignal = true;
            break;
        }
    }

    if (pastHasSignal && currentHasSignal) {
        outAnomaly.type = "cross_request_fragmentation";
        outAnomaly.baseWeight = 15.0;
        outAnomaly.weight = getEffectiveWeight("cross_request_fragmentation", 15.0);
        outAnomaly.detail = "Attack indicators correlated across sequential requests from same IP";
        return true;
    }

    // 2. Score spike check
    double sum = 0.0;
    for (auto const& entry : recent) sum += entry.score;
    double avg = sum / recent.size();
    if (currentResult.score > avg * 2.0 && currentResult.score > 10.0) {
        outAnomaly.type = "behavioral_shift";
        outAnomaly.baseWeight = 5.0;
        outAnomaly.weight = getEffectiveWeight("behavioral_shift", 5.0);
        outAnomaly.detail = "Score spike: " + std::to_string(currentResult.score) + " vs avg " + std::to_string(avg);
        return true;
    }

    return false;
}

void SmartAnomalyDetector::updateHistory(const std::string& ip, const SmartAnomalyResult& result) {
    std::unique_lock<std::shared_mutex> lock(historyMutex);
    auto& history = anomalyHistory[ip];
    auto now = std::chrono::system_clock::now();
    
    AnomalyHistoryEntry entry;
    entry.timestamp = now;
    entry.score = result.score;
    for (auto const& [cat, sc] : result.categoryScores) entry.categories.push_back(cat);
    for (auto const& ind : result.topIndicators) entry.indicators.push_back(ind.type);
    
    history.push_back(std::move(entry));

    // Sweep history window (5 mins = 300,000 ms)
    while (!history.empty()) {
        auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(now - history.front().timestamp).count();
        if (diff > 300000) {
            history.erase(history.begin());
        } else {
            break;
        }
    }

    if (history.size() > 1000) {
        history.erase(history.begin());
    }
}

void SmartAnomalyDetector::feedback(const std::vector<std::string>& signals, const std::string& result) {
    std::unique_lock<std::shared_mutex> lock(feedbackMutex);
    for (auto const& sig : signals) {
        auto& data = feedbackStore[sig];
        if (result == "true_positive") data.tp++;
        else data.fp++;
    }
}

double SmartAnomalyDetector::getEffectiveWeight(const std::string& signalType, double baseWeight) const {
    std::shared_lock<std::shared_mutex> lock(feedbackMutex);
    auto it = feedbackStore.find(signalType);
    if (it == feedbackStore.end()) return baseWeight;
    size_t total = it->second.tp + it->second.fp;
    if (total < 5) return baseWeight; // cold start
    double confidence = static_cast<double>(it->second.tp) / static_cast<double>(total);
    return baseWeight * std::max(0.1, confidence);
}

std::string SmartAnomalyDetector::scoreToSeverity(double score) const {
    if (score >= 25.0) return "critical";
    if (score >= 15.0) return "high";
    if (score >= 8.0) return "medium";
    if (score >= 3.0) return "low";
    return "info";
}

std::vector<WafMatch> SmartAnomalyDetector::check(const HttpRequest& decodedReq) {
    RequestFeatures features = extractRequestFeatures(decodedReq);
    
    std::string rawFields = decodedReq.url + " " + decodedReq.body;
    
    // Evaluate sub-pipelines
    auto behavioral = calculateBehavioralScore(features, rawFields);
    auto categoryScores = calculateCategoryAnomaly(features);
    auto correlationSignals = detectCrossFieldCorrelation(features);
    auto novelIndicators = detectNovelAnomalies(features, categoryScores);

    double totalScore = behavioral.first;
    std::vector<IndicatorData> allIndicators = behavioral.second;

    for (auto const& [cat, res] : categoryScores) {
        totalScore += res.score;
        allIndicators.push_back({
            cat + "_anomaly",
            res.score,
            res.score,
            cat + ": " + std::to_string(res.matchedPatterns.size()) + " patterns, severity " + res.severity
        });
    }

    for (auto const& ind : novelIndicators) {
        totalScore += ind.weight;
        allIndicators.push_back(ind);
    }

    for (auto const& sig : correlationSignals) {
        totalScore += sig.weight;
        allIndicators.push_back(sig);
    }

    SmartAnomalyResult result;
    result.score = totalScore;
    result.severity = scoreToSeverity(totalScore);
    result.topIndicators = allIndicators;
    result.categoryScores = categoryScores;
    result.novelIndicators = novelIndicators;

    // Temporal checks
    IndicatorData temporalAnomaly;
    if (calculateTemporalAnomaly(decodedReq.ip, result, temporalAnomaly)) {
        result.temporalAnomaly = temporalAnomaly;
        result.hasTemporalAnomaly = true;
        result.score += temporalAnomaly.weight;
        allIndicators.push_back(temporalAnomaly);
    }

    updateHistory(decodedReq.ip, result);

    if (result.score > 0) {
        WafMatch match;
        match.rule = "smart_anomaly_detection";
        
        // Find top tags from category scores
        match.tags = { "anomaly", "heuristic" };
        for (auto const& [cat, res] : categoryScores) {
            match.tags.push_back(cat);
        }
        
        match.severity = result.severity;
        
        // Find highest category score
        std::string highestCat = "unknown";
        double maxCatScore = 0.0;
        for (auto const& [cat, res] : categoryScores) {
            if (res.score > maxCatScore) {
                maxCatScore = res.score;
                highestCat = cat;
            }
        }
        match.category = highestCat;
        
        // Build description
        std::string primary = allIndicators.empty() ? "" : allIndicators[0].type;
        match.description = "Score " + std::to_string(result.score) + " (" + result.severity + ") | Primary: " + primary;
        match.author = "shieldwall-core";
        match.sourceFile = "builtin:smart-anomaly";
        match.score = result.score;
        
        // Format matched patterns list
        for (auto const& ind : allIndicators) {
            match.matchedPatterns.push_back({ ind.type, ind.detail });
        }
        return { match };
    }

    return {};
}
