#include "AnomalyDetector.hpp"
#include <sstream>
#include <algorithm>
#include <unordered_set>
#include <cmath>
#include <iostream>

// Helper to decode URI components
static std::string decodeURIComponent(const std::string& str) {
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

AnomalyDetector::AnomalyDetector() {
    startTime = std::chrono::system_clock::now();
}

AnomalyDetector::~AnomalyDetector() {}

AnomalyDetector::PathStats& AnomalyDetector::getStats(const std::string& path) {
    std::unique_lock<std::shared_mutex> lock(statsMutex);
    auto it = statsMap.find(path);
    if (it != statsMap.end()) {
        it->second.lastSeen = std::chrono::system_clock::now();
        return it->second;
    }
    
    // Enforce MAX_BASELINES limit to prevent OOM
    if (statsMap.size() >= 5000) {
        // Evict oldest by lastSeen
        auto oldestIt = statsMap.begin();
        for (auto tempIt = statsMap.begin(); tempIt != statsMap.end(); ++tempIt) {
            if (tempIt->second.lastSeen < oldestIt->second.lastSeen) {
                oldestIt = tempIt;
            }
        }
        statsMap.erase(oldestIt);
    }
    
    PathStats newStats;
    newStats.lastSeen = std::chrono::system_clock::now();
    auto result = statsMap.emplace(path, std::move(newStats));
    return result.first->second;
}

AnomalyDetector::ParamStats& AnomalyDetector::getParamStats(PathStats& pathStats, const std::string& key) {
    // Note: PathStats is passed as reference and caller is expected to have locked statsMutex.
    auto it = pathStats.paramProfiles.find(key);
    if (it != pathStats.paramProfiles.end()) {
        return it->second;
    }
    if (pathStats.paramProfiles.size() > 100) {
        static ParamStats fallbackStats;
        return fallbackStats;
    }
    ParamStats newStats;
    auto result = pathStats.paramProfiles.emplace(key, std::move(newStats));
    return result.first->second;
}

double AnomalyDetector::charClassRatio(const std::string& str, const std::regex& regex) {
    if (str.empty()) return 0.0;
    size_t capLen = std::min(str.length(), static_cast<size_t>(5000));
    std::string capped = str.substr(0, capLen);
    
    std::sregex_iterator it(capped.begin(), capped.end(), regex);
    std::sregex_iterator end;
    size_t count = 0;
    for (; it != end; ++it) {
        count += it->length();
    }
    return static_cast<double>(count) / static_cast<double>(capLen);
}

size_t AnomalyDetector::detectMixedEncoding(const std::string& str) {
    if (str.empty()) return 0;
    size_t capLen = std::min(str.length(), static_cast<size_t>(5000));
    std::string capped = str.substr(0, capLen);
    
    size_t n = 0;
    static const std::regex percentRegex("%[0-9A-Fa-f]{2}");
    static const std::regex entityRegex("&#(x[0-9A-Fa-f]+|\\d+);?");
    static const std::regex unicodeRegex("\\\\u[0-9A-Fa-f]{4}");
    static const std::regex hexRegex("\\\\x[0-9A-Fa-f]{2}");
    
    if (std::regex_search(capped, percentRegex)) n++;
    if (std::regex_search(capped, entityRegex)) n++;
    if (std::regex_search(capped, unicodeRegex)) n++;
    if (std::regex_search(capped, hexRegex)) n++;
    
    return n;
}

size_t AnomalyDetector::countEncodingLayers(const std::string& str) {
    if (str.empty()) return 0;
    size_t layers = 0;
    std::string current = str;
    for (size_t i = 0; i < 5; ++i) {
        std::string decoded = decodeURIComponent(current);
        if (decoded == current) break;
        current = decoded.substr(0, 5000);
        layers++;
    }
    return layers;
}

size_t AnomalyDetector::nestingDepth(const std::string& str) {
    size_t maxDepth = 0;
    size_t depth = 0;
    for (char ch : str) {
        if (ch == '(' || ch == '[' || ch == '{') {
            depth++;
            if (depth > maxDepth) maxDepth = depth;
        } else if (ch == ')' || ch == ']' || ch == '}') {
            if (depth > 0) depth--;
        }
    }
    return maxDepth;
}

double AnomalyDetector::repeatingRatio(const std::string& str) {
    if (str.length() < 8) return 0.0;
    size_t capLen = std::min(str.length(), static_cast<size_t>(5000));
    
    size_t runCharsLength = 0;
    size_t consecutive = 1;
    for (size_t i = 1; i < capLen; ++i) {
        if (str[i] == str[i - 1]) {
            consecutive++;
        } else {
            if (consecutive >= 5) {
                runCharsLength += consecutive;
            }
            consecutive = 1;
        }
    }
    if (consecutive >= 5) {
        runCharsLength += consecutive;
    }

    size_t traversalRunLen = 0;
    size_t i = 0;
    while (i < capLen) {
        size_t countSlash = 0;
        size_t countBackslash = 0;
        
        size_t tempI = i;
        while (tempI + 2 < capLen && str[tempI] == '.' && str[tempI+1] == '.' && str[tempI+2] == '/') {
            countSlash++;
            tempI += 3;
        }
        size_t tempJ = i;
        while (tempJ + 2 < capLen && str[tempJ] == '.' && str[tempJ+1] == '.' && str[tempJ+2] == '\\') {
            countBackslash++;
            tempJ += 3;
        }
        
        if (countSlash >= 3) {
            traversalRunLen += countSlash * 3;
            i += countSlash * 3;
        } else if (countBackslash >= 3) {
            traversalRunLen += countBackslash * 3;
            i += countBackslash * 3;
        } else {
            i++;
        }
    }

    double totalRuns = static_cast<double>(runCharsLength + traversalRunLen);
    return totalRuns / static_cast<double>(capLen);
}

double AnomalyDetector::calculateEntropy(const std::string& str) {
    if (str.length() < 10) return 0.0;
    std::unordered_map<char, size_t> freq;
    for (char ch : str) {
        freq[ch]++;
    }
    double entropy = 0.0;
    double len = static_cast<double>(str.length());
    for (auto const& [ch, count] : freq) {
        double p = static_cast<double>(count) / len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

std::vector<std::string> AnomalyDetector::detectParameterPollution(const HttpRequest& decodedReq) {
    std::vector<std::string> indicators;
    for (auto const& [key, val] : decodedReq.query) {
        if (val.size() > 1) {
            indicators.push_back("query:" + key + "(" + std::to_string(val.size()) + "x)");
        }
    }
    // Also parse from raw query string if rawUrl is available to count raw duplicate keys
    size_t qPos = decodedReq.url.find('?');
    if (qPos != std::string::npos && qPos + 1 < decodedReq.url.length()) {
        std::string qs = decodedReq.url.substr(qPos + 1, 5000);
        std::unordered_map<std::string, size_t> rawKeys;
        std::stringstream ss(qs);
        std::string part;
        while (std::getline(ss, part, '&')) {
            if (part.empty()) continue;
            size_t eqIdx = part.find('=');
            std::string key = eqIdx != std::string::npos ? part.substr(0, eqIdx) : part;
            rawKeys[key]++;
            if (rawKeys[key] == 2) {
                indicators.push_back("raw:" + key);
            }
        }
    }
    return indicators;
}

std::vector<std::string> AnomalyDetector::detectRawBytes(const std::string& str) {
    std::vector<std::string> found;
    for (size_t i = 0; i < str.length(); ++i) {
        unsigned char code = str[i];
        if ((code >= 0 && code <= 8) || (code >= 14 && code <= 31) || code == 127) {
            char hexStr[16];
            snprintf(hexStr, sizeof(hexStr), "0x%02x@pos%zu", code, i);
            found.push_back(hexStr);
        }
    }
    return found;
}

bool AnomalyDetector::detectPayloadInflation(const HttpRequest& decodedReq, double& avgSize, size_t& keyCount, size_t& totalSize) {
    if (decodedReq.body.empty()) return false;
    // Estimate parameters count from parsed JSON/Form body if possible.
    // If not, count boundaries or keys. Let's make an approximation.
    // Since we don't have JSON library built-in standard library, let's do a simple count of key-value structures.
    // We count commas and colons in JSON to estimate.
    size_t colons = 0;
    for (char c : decodedReq.body) {
        if (c == ':') colons++;
    }
    keyCount = colons == 0 ? 1 : colons;
    totalSize = decodedReq.body.length();
    avgSize = static_cast<double>(totalSize) / static_cast<double>(keyCount);
    if (avgSize > 100000.0 && keyCount <= 3) {
        return true;
    }
    return false;
}

std::vector<std::string> AnomalyDetector::detectNakedRequest(const std::unordered_map<std::string, std::vector<std::string>>& headers, const std::string& userAgent) {
    std::vector<std::string> indicators;
    
    auto hasHeader = [&headers](const std::string& name) {
        return headers.find(name) != headers.end();
    };

    if (!hasHeader("accept") && !hasHeader("Accept")) {
        indicators.push_back("missing_accept");
    }
    if (!hasHeader("accept-language") && !hasHeader("Accept-Language")) {
        indicators.push_back("missing_accept_language");
    }
    if (!hasHeader("accept-encoding") && !hasHeader("Accept-Encoding")) {
        indicators.push_back("missing_accept_encoding");
    }
    
    static const std::regex autoUARegex(
        "^(python-requests|axios|node-fetch|http\\.client|Go-http)",
        std::regex_constants::icase
    );
    if (std::regex_search(userAgent, autoUARegex)) {
        indicators.push_back("automation_ua");
    }
    return indicators;
}

std::vector<std::string> AnomalyDetector::detectRichHeaderAnomaly(
    const std::string& method,
    const std::unordered_map<std::string, std::vector<std::string>>& headers,
    const std::vector<std::pair<std::string, std::string>>& rawHeaders,
    const std::string& userAgent
) {
    std::vector<std::string> indicators;
    bool isBrowser = std::regex_search(userAgent, std::regex("(Chrome|Firefox|Safari|Edge)", std::regex_constants::icase));

    auto hasHeader = [&headers](const std::string& name, std::string& valOut) {
        auto it = headers.find(name);
        if (it != headers.end() && !it->second.empty()) {
            valOut = it->second[0];
            return true;
        }
        return false;
    };

    std::string alpn, h2Fingerprint;
    bool isHttp2 = hasHeader("x-alpn", alpn) && alpn == "h2";
    if (hasHeader("x-h2-fingerprint", h2Fingerprint)) isHttp2 = true;

    if (!rawHeaders.empty() && !isHttp2) {
        std::vector<std::string> keys;
        for (auto const& pair : rawHeaders) {
            keys.push_back(pair.first);
        }

        static const std::unordered_set<std::string> coreHeaders = {
            "host", "user-agent", "connection", "accept", "referer", "origin"
        };
        
        size_t lowercaseAnomalies = 0;
        for (auto const& key : keys) {
            std::string lowerKey = key;
            std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
            if (coreHeaders.count(lowerKey) && std::regex_match(key, std::regex("^[a-z\\-]+$"))) {
                lowercaseAnomalies++;
            }
        }
        
        if (lowercaseAnomalies >= 2 && isBrowser) {
            indicators.push_back("impersonation_casing_anomaly");
        }

        if (!keys.empty()) {
            std::string firstLower = keys[0];
            std::transform(firstLower.begin(), firstLower.end(), firstLower.begin(), ::tolower);
            if (firstLower != "host") {
                indicators.push_back("abnormal_header_order_host");
            }
        }
        
        // Connection order check
        auto connIt = std::find(keys.begin(), keys.end(), "Connection");
        if (connIt != keys.end() && std::distance(connIt, keys.end()) <= 1) {
            indicators.push_back("abnormal_header_order_connection");
        }
    }

    static const std::vector<std::string> rareHeaders = {
        "x-scanner", "x-http-method-override", "acunetix-product", "x-forwarded-host", "x-req-id"
    };
    for (auto const& h : rareHeaders) {
        std::string val;
        if (hasHeader(h, val)) {
            indicators.push_back("suspicious_header_" + h);
        }
    }

    if (isBrowser) {
        std::string dummy;
        if (!hasHeader("accept", dummy) && !hasHeader("Accept", dummy)) {
            indicators.push_back("browser_no_accept");
        }
        if (!hasHeader("accept-language", dummy) && !hasHeader("Accept-Language", dummy)) {
            indicators.push_back("browser_no_lang");
        }
    }

    if (method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE") {
        std::string dummy;
        if (!hasHeader("origin", dummy) && !hasHeader("Origin", dummy) && 
            !hasHeader("referer", dummy) && !hasHeader("Referer", dummy)) {
            indicators.push_back("post_no_origin");
        }
    }

    return indicators;
}

size_t AnomalyDetector::detectInvisibleChars(const std::string& str) {
    if (str.empty()) return 0;
    size_t count = 0;
    // UTF-8 representations for zero-width / invisible chars:
    // U+200B: E2 80 8B
    // U+200C: E2 80 8C
    // U+200D: E2 80 8D
    // U+200E: E2 80 8E
    // U+200F: E2 80 8F
    // U+2028: E2 80 A8
    // U+2029: E2 80 A9
    // U+202A to U+202F: E2 80 AA to E2 80 AF
    // U+FEFF: EF BB BF
    for (size_t i = 0; i < str.length(); ) {
        unsigned char c1 = str[i];
        if (c1 == 0xE2 && i + 2 < str.length()) {
            unsigned char c2 = str[i + 1];
            unsigned char c3 = str[i + 2];
            if (c2 == 0x80) {
                if ((c3 >= 0x8B && c3 <= 0x8F) || (c3 >= 0xAA && c3 <= 0xAF)) {
                    count++;
                    i += 3;
                    continue;
                }
            } else if (c2 == 0x8A) {
                if (c3 == 0xA8 || c3 == 0xA9) {
                    count++;
                    i += 3;
                    continue;
                }
            }
        } else if (c1 == 0xEF && i + 2 < str.length()) {
            unsigned char c2 = str[i + 1];
            unsigned char c3 = str[i + 2];
            if (c2 == 0xBB && c3 == 0xBF) {
                count++;
                i += 3;
                continue;
            }
        }
        i++;
    }
    return count;
}

std::vector<std::string> AnomalyDetector::detectMalformedJsonKeys(const HttpRequest& decodedReq) {
    std::vector<std::string> found;
    if (decodedReq.body.empty() || decodedReq.body[0] != '{') return found;
    
    // Quick search for prototype pollution keys in JSON body string
    // e.g. "__proto__", "constructor", "prototype"
    static const std::vector<std::string> dangerous = {
        "\"__proto__\"", "\"constructor\"", "\"prototype\""
    };
    for (auto const& d : dangerous) {
        if (decodedReq.body.find(d) != std::string::npos) {
            found.push_back(d.substr(1, d.length() - 2));
        }
    }
    return found;
}

bool AnomalyDetector::detectSSTI(const std::string& str) {
    if (str.empty()) return false;
    size_t capLen = std::min(str.length(), static_cast<size_t>(5000));
    std::string capped = str.substr(0, capLen);
    
    static const std::regex sstiRegex("(\\{\\{[^}]*\\}\\}|\\$\\{[^}]*\\}|<%[^%]*%>|#\\{[^}]*\\})");
    static const std::regex specialDunder("__(class|init|globals|mro|subclasses)__");
    
    return std::regex_search(capped, sstiRegex) || std::regex_search(capped, specialDunder);
}

bool AnomalyDetector::detectEmptyBody(const std::unordered_map<std::string, std::vector<std::string>>& headers, const std::string& body) {
    auto it = headers.find("content-type");
    if (it == headers.end()) it = headers.find("Content-Type");
    if (it != headers.end() && !it->second.empty() && it->second[0].find("application/json") != std::string::npos) {
        if (body.empty()) return true;
        // Check if whitespace only
        bool empty = true;
        for (char c : body) {
            if (!std::isspace(static_cast<unsigned char>(c))) {
                empty = false;
                break;
            }
        }
        return empty;
    }
    return false;
}

bool AnomalyDetector::detectPaddingEvasion(const std::string& str) {
    if (str.empty()) return false;
    size_t capLen = std::min(str.length(), static_cast<size_t>(5000));
    std::string capped = str.substr(0, capLen);
    static const std::regex paddingRegex(
        "\\b(select|union|from|where|insert|delete|update|drop)\\s{5,}",
        std::regex_constants::icase
    );
    return std::regex_search(capped, paddingRegex);
}

bool AnomalyDetector::detectFragmentedWords(const std::string& str) {
    if (str.empty()) return false;
    size_t capLen = std::min(str.length(), static_cast<size_t>(5000));
    std::string capped = str.substr(0, capLen);
    
    static const std::regex concatSyntax("(['\"]\\w['\"]\\s*(\\+|\\|\\|)\\s*){3,}", std::regex_constants::icase);
    static const std::regex sqlConcat("concat\\(\\s*['\"]\\w['\"]\\s*(,\\s*['\"]\\w['\"]\\s*){3,}\\)", std::regex_constants::icase);
    static const std::regex inlineChr("(chr|char)\\(\\d{2,3}\\)\\s*(\\|\\||\\+)\\s*(chr|char)\\(", std::regex_constants::icase);
    
    return std::regex_search(capped, concatSyntax) || 
           std::regex_search(capped, sqlConcat) || 
           std::regex_search(capped, inlineChr);
}

bool AnomalyDetector::detectExecutablePayload(const std::string& str) {
    if (str.empty()) return false;
    size_t capLen = std::min(str.length(), static_cast<size_t>(5000));
    std::string capped = str.substr(0, capLen);
    
    static const std::regex execRegex("(MZ[^\\n]*\\n|TVqQ[A-Za-z0-9+/=]{10,}|f0VMR[A-Za-z0-9+/=]{10,})");
    return std::regex_search(capped, execRegex);
}

size_t AnomalyDetector::detectHomoglyphs(const std::string& str) {
    if (str.empty()) return 0;
    
    size_t mixedCount = 0;
    bool inWord = false;
    bool wordHasLatin = false;
    bool wordHasCyrillic = false;
    
    auto isLatin = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    };
    auto isCyrillicLead = [](unsigned char c) {
        return c == 0xD0 || c == 0xD1;
    };
    
    for (size_t i = 0; i < str.length(); ) {
        unsigned char c = str[i];
        bool isWordChar = false;
        bool charIsLatin = false;
        bool charIsCyrillic = false;
        size_t charLen = 1;
        
        if (isLatin(c)) {
            isWordChar = true;
            charIsLatin = true;
        } else if (isCyrillicLead(c) && i + 1 < str.length()) {
            unsigned char next = str[i + 1];
            if (next >= 0x80 && next <= 0xBF) {
                isWordChar = true;
                charIsCyrillic = true;
                charLen = 2;
            }
        }
        
        if (isWordChar) {
            if (!inWord) {
                inWord = true;
                wordHasLatin = charIsLatin;
                wordHasCyrillic = charIsCyrillic;
            } else {
                if (charIsLatin) wordHasLatin = true;
                if (charIsCyrillic) wordHasCyrillic = true;
            }
            i += charLen;
        } else {
            if (inWord) {
                if (wordHasLatin && wordHasCyrillic) {
                    mixedCount++;
                }
                inWord = false;
            }
            i++;
        }
    }
    if (inWord && wordHasLatin && wordHasCyrillic) {
        mixedCount++;
    }
    
    return mixedCount;
}

double AnomalyDetector::calculateNgramDeviation(const std::string& str) {
    if (str.length() < 20) return 0.0;
    std::string lower;
    lower.reserve(str.length());
    for (char ch : str) {
        char lowerCh = std::tolower(static_cast<unsigned char>(ch));
        if (lowerCh >= 'a' && lowerCh <= 'z') {
            lower.push_back(lowerCh);
        }
    }
    if (lower.length() < 20) return 0.0;

    static const std::unordered_set<std::string> COMMON_BIGRAMS = {
        "th","he","in","er","an","re","on","at","en","nd","ti","es","or","te","of","ed","is","it","al","ar",
        "st","to","nt","ng","se","ha","as","ou","io","le","ve","co","me","de","hi","ri","ro","ic","ne","ea",
        "ra","ce"
    };

    size_t total = 0;
    size_t valid = 0;
    for (size_t i = 0; i < lower.length() - 1; ++i) {
        total++;
        if (COMMON_BIGRAMS.count(lower.substr(i, 2))) {
            valid++;
        }
    }
    if (total == 0) return 0.0;
    return 1.0 - (static_cast<double>(valid) / static_cast<double>(total));
}

bool AnomalyDetector::detectLocalEntropySpike(const std::string& str, size_t windowSize, size_t step) {
    if (str.length() < windowSize * 2) return false;
    double maxLocalSpecial = 0.0;
    static const std::regex specRegex("[^a-zA-Z0-9\\s.,\\-_@]");
    
    for (size_t i = 0; i <= str.length() - windowSize; i += step) {
        std::string chunk = str.substr(i, windowSize);
        double ratio = charClassRatio(chunk, specRegex);
        if (ratio > maxLocalSpecial) maxLocalSpecial = ratio;
    }
    return maxLocalSpecial > 0.40;
}

std::string AnomalyDetector::getParamType(const std::string& val) {
    if (std::regex_match(val, std::regex("^\\d+$"))) return "int";
    if (std::regex_match(val, std::regex("^[0-9a-f]{8}-[0-9a-f]{4}", std::regex_constants::icase))) return "uuid";
    if (std::regex_match(val, std::regex("^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$", std::regex_constants::icase))) return "email";
    return "string";
}

std::vector<std::string> AnomalyDetector::detectRequestSmuggling(const HttpRequest& decodedReq) {
    std::vector<std::string> indicators;
    
    auto hasHeader = [&decodedReq](const std::string& name, std::string& valOut) {
        auto it = decodedReq.headers.find(name);
        if (it != decodedReq.headers.end() && !it->second.empty()) {
            valOut = it->second[0];
            return true;
        }
        return false;
    };

    std::string clVal, teVal;
    bool hasCL = hasHeader("content-length", clVal) || hasHeader("Content-Length", clVal);
    bool hasTE = hasHeader("transfer-encoding", teVal) || hasHeader("Transfer-Encoding", teVal);

    if (hasCL && hasTE) {
        indicators.push_back("cl_te_conflict");
    }

    if (hasTE) {
        std::string lowerTE = teVal;
        std::transform(lowerTE.begin(), lowerTE.end(), lowerTE.begin(), ::tolower);
        if (lowerTE.find("chunked") != std::string::npos && 
            (lowerTE.find(',') != std::string::npos || lowerTE.find(';') != std::string::npos)) {
            indicators.push_back("te_obfuscation");
        }
    }

    if (hasCL && clVal.find(',') != std::string::npos) {
        std::stringstream ss(clVal);
        std::string item;
        std::unordered_set<std::string> lengths;
        while (std::getline(ss, item, ',')) {
            // Trim
            size_t first = item.find_first_not_of(" ");
            size_t last = item.find_last_not_of(" ");
            if (first != std::string::npos) {
                lengths.insert(item.substr(first, last - first + 1));
            }
        }
        if (lengths.size() > 1) {
            indicators.push_back("double_cl_mismatch");
        }
    }

    return indicators;
}

size_t AnomalyDetector::checkRaceCondition(const HttpRequest& decodedReq) {
    std::string method = decodedReq.method;
    std::transform(method.begin(), method.end(), method.begin(), ::toupper);
    if (method != "POST" && method != "PUT" && method != "PATCH") return 0;
    
    std::string ip = decodedReq.ip.empty() ? "unknown" : decodedReq.ip;
    std::string path = decodedReq.path.empty() ? "/" : decodedReq.path;
    std::string key = ip + ":" + path;
    
    auto now = std::chrono::system_clock::now();
    
    std::lock_guard<std::mutex> lock(tempMapsMutex);
    
    auto& attempts = concurrencyMap[key];
    
    // Filter attempts older than 100ms
    std::vector<std::chrono::system_clock::time_point> recent;
    for (auto const& t : attempts) {
        auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(now - t).count();
        if (diff < 100) {
            recent.push_back(t);
        }
    }
    recent.push_back(now);
    attempts = recent;

    // Cleanup concurrency map if it grows too large
    if (concurrencyMap.size() > 10000) {
        concurrencyMap.erase(concurrencyMap.begin());
    }

    if (recent.size() > 3) return recent.size();
    return 0;
}

size_t AnomalyDetector::detectSlowBOLA(const std::string& ip, const std::string& paramName, const std::string& paramValue) {
    // Check if integer or UUID prefix
    bool isNumeric = std::regex_match(paramValue, std::regex("^\\d+$"));
    bool isUuid = std::regex_match(paramValue, std::regex("^[0-9a-f]{8}", std::regex_constants::icase));
    if (!isNumeric && !isUuid) return 0;

    std::string key = ip + ":" + paramName;
    auto now = std::chrono::system_clock::now();
    
    std::lock_guard<std::mutex> lock(tempMapsMutex);
    
    auto& history = resourceHistogram[key];
    history.push_back({ paramValue, now });
    
    // 1-hour window
    std::vector<ResourceHistory> recent;
    std::unordered_set<std::string> uniqueIds;
    for (auto const& entry : history) {
        auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(now - entry.ts).count();
        if (diff < 3600000) {
            recent.push_back(entry);
            uniqueIds.insert(entry.id);
        }
    }
    history = recent;

    if (resourceHistogram.size() > 10000) {
        resourceHistogram.erase(resourceHistogram.begin());
    }

    if (uniqueIds.size() > 30 && uniqueIds.size() > (recent.size() * 0.8)) {
        return uniqueIds.size();
    }
    return 0;
}

size_t AnomalyDetector::detectGraphQLAbuse(const HttpRequest& decodedReq) {
    if (decodedReq.path.rfind("/graphql") == std::string::npos && 
        decodedReq.path.rfind("/gql") == std::string::npos) return 0;
        
    // Extract query parameter from body or parsed params
    // Simply check in raw body
    if (decodedReq.body.empty()) return 0;
    
    size_t score = 0;
    size_t maxDepth = 0;
    size_t currentDepth = 0;
    
    for (char charCode : decodedReq.body) {
        if (charCode == '{') {
            currentDepth++;
            if (currentDepth > maxDepth) maxDepth = currentDepth;
        } else if (charCode == '}') {
            if (currentDepth > 0) currentDepth--;
        }
    }
    if (maxDepth > 7) score += maxDepth * 2;

    // Simple regex to count GraphQL aliases: word + spaces + colon + spaces + word + open bracket
    static const std::regex aliasRegex("\\w+\\s*:\\s*\\w+\\s*\\(");
    std::sregex_iterator it(decodedReq.body.begin(), decodedReq.body.end(), aliasRegex);
    std::sregex_iterator end;
    size_t aliasCount = 0;
    for (; it != end; ++it) {
        aliasCount++;
    }
    if (aliasCount > 5) score += aliasCount * 2;

    return score;
}

bool AnomalyDetector::detectHeaderCRLFInjection(const HttpRequest& decodedReq) {
    for (auto const& [key, values] : decodedReq.headers) {
        for (auto const& val : values) {
            if (val.find('\r') != std::string::npos || val.find('\n') != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

std::string AnomalyDetector::getRequestShape(const HttpRequest& decodedReq) {
    std::string method = decodedReq.method;
    std::string path = decodedReq.path;
    std::string shape = method + ":" + path + "|";
    
    // Add keys from query sorted
    std::vector<std::string> queryKeys;
    for (auto const& [k, v] : decodedReq.query) queryKeys.push_back(k);
    std::sort(queryKeys.begin(), queryKeys.end());
    for (auto const& k : queryKeys) {
        shape += "q:" + k + ":str,"; // simple estimation
    }
    
    // Add simple hash (for estimation)
    size_t hashVal = std::hash<std::string>{}(shape);
    char hashStr[32];
    snprintf(hashStr, sizeof(hashStr), "%012zx", hashVal);
    return std::string(hashStr).substr(0, 12);
}

std::vector<WafMatch> AnomalyDetector::check(const HttpRequest& decodedReq, double responseTimeMs) {
    std::string path = decodedReq.path.empty() ? "/" : decodedReq.path;
    std::string method = decodedReq.method;
    std::transform(method.begin(), method.end(), method.begin(), ::toupper);

    // FAST PATH: Static Assets
    if (method == "GET" && decodedReq.query.empty()) {
        static const std::regex staticAssetRegex(
            "\\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2|ttf|mp4)$",
            std::regex_constants::icase
        );
        if (std::regex_search(path, staticAssetRegex)) {
            return {}; // Clean (Static Asset)
        }
    }

    double score = 0.0;
    std::vector<std::pair<std::string, std::string>> matches;

    auto addIndicator = [&](double weight, const std::string& name, const std::string& detail) {
        score += weight;
        matches.push_back({ name, detail });
    };

    // Prepare candidates
    std::string urlCapped = decodedReq.url.substr(0, 10000);
    std::string bodyCapped = decodedReq.body.substr(0, 10000);
    
    std::vector<std::string> queryVals;
    for (auto const& [k, v] : decodedReq.query) {
        for (auto const& val : v) {
            queryVals.push_back(val.substr(0, 500));
        }
    }

    std::vector<std::string> cookieVals;
    for (auto const& [k, v] : decodedReq.cookies) {
        cookieVals.push_back(v.substr(0, 500));
    }

    std::vector<std::string> candidates;
    if (!urlCapped.empty()) candidates.push_back(urlCapped);
    if (!bodyCapped.empty()) candidates.push_back(bodyCapped);
    for (auto const& q : queryVals) candidates.push_back(q);
    for (auto const& c : cookieVals) candidates.push_back(c);

    // 1. Content-Type anomaly check
    std::string contentType;
    auto ctIt = decodedReq.headers.find("content-type");
    if (ctIt == decodedReq.headers.end()) ctIt = decodedReq.headers.find("Content-Type");
    if (ctIt != decodedReq.headers.end() && !ctIt->second.empty()) {
        contentType = ctIt->second[0];
        std::transform(contentType.begin(), contentType.end(), contentType.begin(), ::tolower);
    }
    
    // Trim leading whitespace for body prefix checks
    std::string bodyTrimmed = bodyCapped;
    bodyTrimmed.erase(bodyTrimmed.begin(), std::find_if(bodyTrimmed.begin(), bodyTrimmed.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));

    if (!contentType.empty() && !bodyTrimmed.empty()) {
        if (contentType.find("application/json") != std::string::npos && bodyTrimmed[0] == '<') {
            addIndicator(8.0, "content_type_mismatch", "JSON Content-Type but XML/HTML payload structure detected");
        } else if (contentType.find("application/xml") != std::string::npos && bodyTrimmed[0] == '{') {
            addIndicator(5.0, "content_type_mismatch", "XML Content-Type but JSON payload structure detected");
        }
    }

    std::string allFields;
    for (auto const& c : candidates) allFields += c + " ";

    if (detectObfuscatedJNDI(allFields)) {
        addIndicator(8.0, "obfuscated_jndi", "Obfuscated JNDI/Log4Shell pattern detected");
    }

    size_t encLayers = countEncodingLayers(decodedReq.url);
    if (encLayers >= 2) {
        addIndicator(4.0 * encLayers, "multi_layer_encoding", std::to_string(encLayers) + " encoding layers detected");
    }

    size_t maxMixedEnc = 0;
    for (auto const& c : candidates) {
        maxMixedEnc = std::max(maxMixedEnc, detectMixedEncoding(c));
    }
    if (maxMixedEnc >= 2) {
        addIndicator(4.0 * (maxMixedEnc - 1), "mixed_encoding", std::to_string(maxMixedEnc) + " different encoding schemes in one request");
    }

    // Baselines checking
    PathStats& stats = getStats(path);

    double maxSpecialRatio = 0.0;
    static const std::regex specialCharsPattern("[^a-zA-Z0-9\\s.,\\-_@]");
    for (auto const& c : candidates) {
        maxSpecialRatio = std::max(maxSpecialRatio, charClassRatio(c, specialCharsPattern));
    }

    double specialZ = 0.0;
    bool hasLongCandidate = false;
    for (auto const& c : candidates) {
        if (c.length() > 20) {
            hasLongCandidate = true;
            break;
        }
    }
    if (hasLongCandidate) {
        specialZ = stats.specialRatio.getZScore(maxSpecialRatio);
    }

    if (specialZ > 3.0) {
        addIndicator(3.0 * (specialZ > 5.0 ? 2.0 : 1.0), "unusual_chars", "Mathematical Z-Score Anomaly: SpecChar z=" + std::to_string(specialZ) + " (baseline mean=" + std::to_string(stats.specialRatio.getMean()) + ")");
    } else if (maxSpecialRatio > 0.30) {
        addIndicator(3.0 * std::ceil(maxSpecialRatio * 10.0), "unusual_chars", std::to_string(static_cast<int>(maxSpecialRatio * 100)) + "% special characters");
    }

    size_t totalCtrlChars = 0;
    static const std::regex controlCharsPattern("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]");
    for (auto const& c : candidates) {
        // Simple approximate regex search
        std::sregex_iterator it(c.begin(), c.end(), controlCharsPattern);
        std::sregex_iterator end;
        for (; it != end; ++it) totalCtrlChars++;
    }
    if (totalCtrlChars > 0) {
        addIndicator(5.0, "control_chars", std::to_string(totalCtrlChars) + " control characters found");
    }

    size_t maxDepth = 0;
    for (auto const& c : candidates) {
        maxDepth = std::max(maxDepth, nestingDepth(c));
    }
    if (maxDepth >= 3) {
        addIndicator(3.0, "deep_nesting", "Nesting depth " + std::to_string(maxDepth));
    }

    for (auto const& val : queryVals) {
        if (val.length() > 500) {
            addIndicator(2.0, "oversized_param", std::to_string(val.length()) + " char parameter");
            break;
        }
    }

    for (auto const& c : candidates) {
        if (detectPaddingEvasion(c)) {
            addIndicator(4.0, "padding_evasion", "Suspicious whitespace padding evasion");
            break;
        }
        if (detectFragmentedWords(c)) {
            addIndicator(5.0, "fragmented_words", "String concatenation / character evasion");
            break;
        }
        if (detectExecutablePayload(c)) {
            addIndicator(6.0, "executable_payload", "Executable header detected");
            break;
        }
    }

    double maxRepRatio = 0.0;
    for (auto const& c : candidates) {
        maxRepRatio = std::max(maxRepRatio, repeatingRatio(c));
    }
    if (maxRepRatio > 0.15) {
        addIndicator(3.0, "repeating_patterns", std::to_string(static_cast<int>(maxRepRatio * 100)) + "% repetitive content");
    }

    size_t totalTerminators = 0;
    for (auto const& c : candidates) {
        for (char ch : c) {
            if (ch == '\'' || ch == '`') totalTerminators++;
        }
    }
    if (totalTerminators >= 4) {
        addIndicator(3.0, "string_terminators", std::to_string(totalTerminators) + " quote characters");
    }

    size_t totalComments = 0;
    static const std::regex commentPattern("(--|\\/\\*|#|\\/\\/)");
    for (auto const& c : candidates) {
        std::sregex_iterator it(c.begin(), c.end(), commentPattern);
        std::sregex_iterator end;
        for (; it != end; ++it) totalComments++;
    }
    if (totalComments >= 2) {
        addIndicator(3.0, "comment_syntax", std::to_string(totalComments) + " comment tokens");
    }

    // Programming keywords Soft checks
    size_t totalKeywords = 0;
    static const std::regex kwRegex(
        "\\b(select|union|insert|update|delete|drop|alter|exec|eval|system|passthru|shell_exec|require|include)\\b",
        std::regex_constants::icase
    );
    for (auto const& c : candidates) {
        std::sregex_iterator it(c.begin(), c.end(), kwRegex);
        std::sregex_iterator end;
        for (; it != end; ++it) totalKeywords++;
    }
    if (totalKeywords >= 3) {
        addIndicator(2.0, "keywords", std::to_string(totalKeywords) + " programming keywords");
    }

    // Non-standard method
    static const std::unordered_set<std::string> normalMethods = {
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
    };
    if (normalMethods.find(method) == normalMethods.end()) {
        addIndicator(5.0, "abnormal_method", "Non-standard method \"" + method + "\"");
    }

    if (decodedReq.userAgent.length() < 5) {
        addIndicator(2.0, "no_user_agent", "Missing User-Agent");
    }

    // Count path segments
    size_t pathSegs = 0;
    std::stringstream pathSs(path);
    std::string seg;
    while (std::getline(pathSs, seg, '/')) {
        if (!seg.empty()) pathSegs++;
    }
    if (pathSegs > 10) {
        addIndicator(2.0, "deep_path", std::to_string(pathSegs) + " path segments");
    }

    double maxEntropy = 0.0;
    for (auto const& c : candidates) {
        if (c.length() > 50) {
            maxEntropy = std::max(maxEntropy, calculateEntropy(c));
        }
    }
    if (maxEntropy > 0.0) {
        double entropyZ = stats.entropy.getZScore(maxEntropy);
        if (entropyZ > 3.0) {
            addIndicator(4.0 * (entropyZ > 5.0 ? 2.0 : 1.0), "high_entropy", "Mathematical Z-Score Anomaly: Entropy z=" + std::to_string(entropyZ) + " (baseline mean=" + std::to_string(stats.entropy.getMean()) + ")");
        } else if (maxEntropy > 5.5) {
            addIndicator(4.0, "high_entropy", "Entropy " + std::to_string(maxEntropy) + " (likely encoded payload)");
        }
    }

    // Parameter checks
    std::vector<std::string> paramAnomalies;
    for (auto const& [key, vals] : decodedReq.query) {
        for (auto const& val : vals) {
            std::string strVal = val.substr(0, 500);
            if (strVal.length() < 2) continue;
            
            // Check BOLA
            size_t bolaScore = detectSlowBOLA(decodedReq.ip, key, strVal);
            if (bolaScore > 0) {
                addIndicator(8.0, "slow_bola_enumeration", "Slow IDOR pattern: " + std::to_string(bolaScore) + " unique IDs for param \"" + key + "\" in 1h");
            }
            
            // Stats checks
            ParamStats& pStats = getParamStats(stats, key);
            std::string currentType = getParamType(strVal);
            if (currentType != "string") {
                pStats.types[currentType]++;
            }
            
            bool isUsuallyNumeric = pStats.types["int"] > 20 || pStats.types["uuid"] > 20;
            if (isUsuallyNumeric && currentType == "string") {
                static const std::regex logicKeywords(
                    "\\b(OR|AND|UNION|SELECT|FROM|WHERE|LIKE|BETWEEN|WAITFOR|SLEEP)\\b",
                    std::regex_constants::icase
                );
                if (std::regex_search(strVal, logicKeywords) || charClassRatio(strVal, specialCharsPattern) > 0.05) {
                    paramAnomalies.push_back("Query param \"" + key + "\" type mutation with logic keywords (" + strVal.substr(0, 20) + ")");
                }
            }

            if (strVal.length() < 10) continue;

            double vEnt = calculateEntropy(strVal);
            double vSpec = charClassRatio(strVal, specialCharsPattern);
            
            double zEnt = pStats.entropy.getZScore(vEnt);
            double zSpec = pStats.specialRatio.getZScore(vSpec);
            
            if (zEnt > 3.0) paramAnomalies.push_back("Query param \"" + key + "\" entropy z=" + std::to_string(zEnt));
            if (zSpec > 3.0) paramAnomalies.push_back("Query param \"" + key + "\" spec_chars z=" + std::to_string(zSpec));
        }
    }

    if (!paramAnomalies.empty()) {
        addIndicator(4.0 * paramAnomalies.size(), "param_entropy_anomaly", paramAnomalies[0]);
    }

    if (maxEntropy > 5.0 && maxSpecialRatio > 0.25) {
        addIndicator(4.0 + 3.0, "obfuscated_payload", "High entropy + High special chars correlation");
    } else if (maxEntropy < 3.5 && maxSpecialRatio > 0.25) {
        addIndicator(3.0 * 2.0, "structural_injection", "Low entropy + High special chars correlation (Injection/SSTI)");
    }

    size_t invisibleChars = 0;
    for (auto const& c : candidates) {
        invisibleChars += detectInvisibleChars(c);
    }
    if (invisibleChars > 0) {
        addIndicator(5.0 * 2.0, "invisible_chars", std::to_string(invisibleChars) + " zero-width/invisible unicode chars detected");
    }

    std::vector<std::string> jsonAnomalies = detectMalformedJsonKeys(decodedReq);
    if (!jsonAnomalies.empty()) {
        std::string list;
        for (auto const& j : jsonAnomalies) list += j + " ";
        addIndicator(8.0, "json_structure_anomaly", "Dangerous JSON keys: " + list);
    }

    bool hasSSTI = false;
    for (auto const& c : candidates) {
        if (detectSSTI(c)) {
            hasSSTI = true;
            break;
        }
    }
    if (hasSSTI) {
        addIndicator(5.0, "ssti_indicator", "Server-Side Template Injection syntax detected");
    }

    std::vector<std::string> pollution = detectParameterPollution(decodedReq);
    if (!pollution.empty()) {
        addIndicator(5.0, "parameter_pollution", std::to_string(pollution.size()) + " duplicate keys");
    }

    std::vector<std::string> rawBytesList;
    for (auto const& c : candidates) {
        std::vector<std::string> temp = detectRawBytes(c);
        rawBytesList.insert(rawBytesList.end(), temp.begin(), temp.end());
    }
    if (!rawBytesList.empty()) {
        addIndicator(6.0, "raw_bytes", std::to_string(rawBytesList.size()) + " control bytes: " + rawBytesList[0]);
    }

    double inflationRatio = 0.0;
    size_t inflationKeys = 0;
    size_t inflationTotal = 0;
    if (detectPayloadInflation(decodedReq, inflationRatio, inflationKeys, inflationTotal)) {
        addIndicator(3.0, "payload_inflation", std::to_string(static_cast<int>(inflationRatio / 1024.0)) + "KB avg per " + std::to_string(inflationKeys) + " keys");
    }

    std::vector<std::string> naked = detectNakedRequest(decodedReq.headers, decodedReq.userAgent);
    if (!naked.empty()) {
        addIndicator(3.0, "naked_request", naked[0]);
    }

    std::vector<std::string> headerIssues = detectRichHeaderAnomaly(decodedReq.method, decodedReq.headers, decodedReq.rawHeaders, decodedReq.userAgent);
    if (!headerIssues.empty()) {
        addIndicator(2.0, "header_integrity", headerIssues[0]);
    }

    if (detectEmptyBody(decodedReq.headers, decodedReq.body)) {
        addIndicator(2.0, "empty_json_body", "Content-Type: application/json but body is empty");
    }

    double maxCodeRatio = 0.0;
    for (auto const& c : candidates) {
        maxCodeRatio = std::max(maxCodeRatio, calculateCodeRatio(c));
    }
    if (maxCodeRatio > 0.2) {
        addIndicator(5.0 * (maxCodeRatio > 0.4 ? 2.0 : 1.0), "code_execution_ratio", "High operator-to-operand ratio (" + std::to_string(maxCodeRatio) + ") indicates code execution attempt");
    }

    bool hasLocalEntropySpike = false;
    for (auto const& c : candidates) {
        if (detectLocalEntropySpike(c)) {
            hasLocalEntropySpike = true;
            break;
        }
    }
    if (hasLocalEntropySpike) {
        addIndicator(4.0, "local_entropy_spike", "Local structural anomaly detected (embedded payload)");
    }

    size_t homoglyphs = 0;
    for (auto const& c : candidates) {
        homoglyphs = std::max(homoglyphs, detectHomoglyphs(c));
    }
    if (homoglyphs > 0) {
        addIndicator(5.0, "homoglyph_evasion", std::to_string(homoglyphs) + " words with mixed latin/cyrillic detected (bypass attempt)");
    }

    if (maxEntropy > 4.5) {
        double maxNgramDev = 0.0;
        for (auto const& c : candidates) {
            maxNgramDev = std::max(maxNgramDev, calculateNgramDeviation(c));
        }
        if (maxNgramDev > 0.9) {
            addIndicator(4.0, "linguistic_anomaly", "High N-gram deviation (" + std::to_string(maxNgramDev) + ") indicates obfuscated payload");
        }
    }

    if (detectHeaderCRLFInjection(decodedReq)) {
        addIndicator(8.0, "header_crlf_injection", "CR/LF characters detected in HTTP headers (H2 Smuggling attempt)");
    }

    std::vector<std::string> smuggling = detectRequestSmuggling(decodedReq);
    if (!smuggling.empty()) {
        addIndicator(8.0, "protocol_smuggling", "HTTP Desync indicator: " + smuggling[0]);
    }

    size_t raceScore = checkRaceCondition(decodedReq);
    if (raceScore > 0) {
        addIndicator(8.0, "race_condition", "Concurrency spike detected (" + std::to_string(raceScore) + " requests in 100ms window)");
    }

    size_t gqlScore = detectGraphQLAbuse(decodedReq);
    if (gqlScore > 0) {
        addIndicator(5.0 + gqlScore, "graphql_complexity_abuse", "GraphQL DoS pattern: depth/aliases score " + std::to_string(gqlScore));
    }

    std::string shapeHash;
    if (stats.entropy.getCount() > 100) {
        shapeHash = getRequestShape(decodedReq);
        size_t shapeRarity = stats.shapeFrequency[shapeHash];
        
        // Lookup reputation taint (mocked or dynamic from reputation lookup if linked, here we assume clean 0 for self-containment)
        double ipTaint = 0.0; 
        if (shapeRarity < 2 && ipTaint > 10.0) {
            addIndicator(8.0, "novel_request_shape", "Zero-Day indicator: Novel request structure from suspicious IP on calibrated endpoint");
        }
    }

    // Fuzzing/Mutation & Blind penalty
    if (score >= 5.0 && score < 15.0) {
        std::string mutationKey = "mutation:" + decodedReq.ip + ":" + path;
        auto now = std::chrono::system_clock::now();
        
        std::lock_guard<std::mutex> lock(tempMapsMutex);
        auto& mutationData = mutationCache[mutationKey];
        mutationData.count++;
        mutationData.ts = now;

        if (mutationData.count >= 3) {
            score += 8.0;
            matches.push_back({ "payload_mutation_fuzzing", std::to_string(mutationData.count) + " suspicious variants from same IP" });
        }

        if (mutationCache.size() > 10000) {
            mutationCache.erase(mutationCache.begin());
        }
    }

    if (score > 5.0 && responseTimeMs > 2000.0) {
        score += 4.0; // blindAnomaly weight
        matches.push_back({ "blind_time_anomaly", "Response time " + std::to_string(responseTimeMs) + "ms with low-score payload" });
    }

    // Baseline updates (benign traffic)
    if (score < 15.0 * 0.3) {
        if (maxEntropy > 0.0) stats.entropy.update(maxEntropy);
        if (maxSpecialRatio > 0.0) stats.specialRatio.update(maxSpecialRatio);
        
        // Update param-specific baselines
        for (auto const& [key, vals] : decodedReq.query) {
            for (auto const& val : vals) {
                std::string strVal = val.substr(0, 500);
                if (strVal.length() < 10) continue;
                ParamStats& pStats = getParamStats(stats, key);
                pStats.entropy.update(calculateEntropy(strVal));
                pStats.specialRatio.update(charClassRatio(strVal, specialCharsPattern));
            }
        }
        
        if (!shapeHash.empty()) {
            stats.shapeFrequency[shapeHash]++;
        }
        return {}; // Benign
    }

    // Generate security threat match
    std::string level = "low";
    if (score >= 30.0) level = "critical";
    else if (score >= 15.0) level = "high";
    else if (score >= 15.0 * 0.6) level = "medium";

    WafMatch threat;
    threat.rule = "anomaly_detection";
    threat.tags = { "anomaly", (level == "critical" ? "confirmed" : "suspicious") };
    threat.severity = level;
    threat.category = "anomaly";
    threat.description = "Anomaly score " + std::to_string(score) + "/30: " + (matches.empty() ? "" : matches[0].first);
    threat.author = "laraxaar";
    threat.sourceFile = "builtin:anomaly";
    threat.score = score;
    for (auto const& m : matches) {
        threat.matchedPatterns.push_back({ m.first, m.second });
    }

    return { threat };
}
