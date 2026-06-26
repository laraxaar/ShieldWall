#include "RuleParser.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <filesystem>
#include <iostream>

// ReDoS safety validation
static bool isSafeRegExp(const std::string& pattern) {
    static const std::regex nestedQuantifier(R"((\([^)]*[\*\+][^)]*\)[\*\+])|(\[[^\]]*[\*\+][^\]]*\][\*\+])");
    static const std::regex overlappingQuantifier(R"(\([^)]*\|[^)]*\)[\*\+])");
    static const std::regex consecutiveQuantifiers(R"(([\*\+\?]{4,}))");

    if (std::regex_search(pattern, nestedQuantifier)) return false;
    if (std::regex_search(pattern, overlappingQuantifier)) return false;
    if (std::regex_search(pattern, consecutiveQuantifiers)) return false;

    return true;
}

// Helper to escape regex literal strings
static std::string escapeRegexLiteral(const std::string& str) {
    static const std::string specialChars = R"(.*+?^${}()|[]\)";
    std::string escaped;
    escaped.reserve(str.length() * 2);
    for (char ch : str) {
        if (specialChars.find(ch) != std::string::npos) {
            escaped.push_back('\\');
        }
        escaped.push_back(ch);
    }
    return escaped;
}

RuleParser::Lexer::Lexer(const std::string& source)
    : source(source), pos(0), line(1), col(1) {}

char RuleParser::Lexer::peek() const {
    return pos < source.length() ? source[pos] : '\0';
}

char RuleParser::Lexer::advance() {
    char ch = source[pos++];
    if (ch == '\n') {
        line++;
        col = 1;
    } else {
        col++;
    }
    return ch;
}

void RuleParser::Lexer::skipWhitespace() {
    while (pos < source.length()) {
        char ch = source[pos];
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
            advance();
        } else if (ch == '/' && pos + 1 < source.length() && source[pos + 1] == '/') {
            while (pos < source.length() && source[pos] != '\n') {
                advance();
            }
        } else if (ch == '/' && pos + 1 < source.length() && source[pos + 1] == '*') {
            advance(); advance();
            while (pos < source.length()) {
                if (source[pos] == '*' && pos + 1 < source.length() && source[pos + 1] == '/') {
                    advance(); advance();
                    break;
                }
                advance();
            }
        } else {
            break;
        }
    }
}

RuleParser::Token RuleParser::Lexer::readString() {
    char quote = advance();
    std::string value;
    int startLine = line;

    while (pos < source.length()) {
        char ch = source[pos];
        if (ch == '\\' && pos + 1 < source.length()) {
            advance();
            char esc = advance();
            if (esc == 'n') value += '\n';
            else if (esc == 't') value += '\t';
            else if (esc == 'r') value += '\r';
            else if (esc == '\\') value += '\\';
            else if (esc == '"') value += '"';
            else if (esc == '\'') value += '\'';
            else {
                value.push_back('\\');
                value.push_back(esc);
            }
        } else if (ch == quote) {
            advance();
            Token t;
            t.type = TokenType::STRING;
            t.value = value;
            t.line = startLine;
            return t;
        } else {
            value.push_back(advance());
        }
    }
    throw std::runtime_error("[ShieldWall] Lexer error: Unterminated string at line " + std::to_string(startLine));
}

RuleParser::Token RuleParser::Lexer::readRegex() {
    advance(); // Skip leading '/'
    std::string pattern;
    bool escaped = false;
    bool inCC = false;
    int startLine = line;

    while (pos < source.length()) {
        char ch = source[pos];
        if (escaped) {
            pattern.push_back(ch);
            escaped = false;
            advance();
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            pattern.push_back(ch);
            advance();
            continue;
        }
        if (ch == '[') inCC = true;
        if (ch == ']') inCC = false;

        if (ch == '/' && !inCC) {
            advance();
            std::string flags;
            while (pos < source.length() && std::string("gimsuy").find(source[pos]) != std::string::npos) {
                flags.push_back(advance());
            }
            Token t;
            t.type = TokenType::REGEX;
            t.value = pattern;
            t.flags = flags;
            t.line = startLine;
            return t;
        }
        pattern.push_back(advance());
    }
    throw std::runtime_error("[ShieldWall] Lexer error: Unterminated regex at line " + std::to_string(startLine));
}

std::string RuleParser::Lexer::readIdentifier() {
    std::string v;
    while (pos < source.length() && (std::isalnum(static_cast<unsigned char>(source[pos])) || source[pos] == '_' || source[pos] == '.')) {
        v.push_back(advance());
    }
    return v;
}

RuleParser::Token RuleParser::Lexer::readNumber() {
    std::string v;
    int startLine = line;
    while (pos < source.length() && std::isdigit(static_cast<unsigned char>(source[pos]))) {
        v.push_back(advance());
    }
    Token t;
    t.type = TokenType::NUMBER;
    t.value = v;
    t.line = startLine;
    return t;
}

std::vector<RuleParser::Token> RuleParser::Lexer::tokenize() {
    std::vector<Token> tokens;
    
    std::unordered_map<std::string, TokenType> keywords = {
        { "rule", TokenType::RULE }, { "meta", TokenType::META }, 
        { "target", TokenType::TARGET }, { "strings", TokenType::STRINGS }, 
        { "condition", TokenType::CONDITION }, { "and", TokenType::AND }, 
        { "or", TokenType::OR }, { "not", TokenType::NOT }, 
        { "in", TokenType::IN }, { "them", TokenType::THEM }, 
        { "true", TokenType::TRUE }, { "false", TokenType::FALSE }
    };

    while (pos < source.length()) {
        skipWhitespace();
        if (pos >= source.length()) break;

        char ch = source[pos];
        int currentLine = line;

        if (ch == '{') { advance(); tokens.push_back({ TokenType::LBRACE, "{", currentLine }); continue; }
        if (ch == '}') { advance(); tokens.push_back({ TokenType::RBRACE, "}", currentLine }); continue; }
        if (ch == '(') { advance(); tokens.push_back({ TokenType::LPAREN, "(", currentLine }); continue; }
        if (ch == ')') { advance(); tokens.push_back({ TokenType::RPAREN, ")", currentLine }); continue; }
        if (ch == ':') { advance(); tokens.push_back({ TokenType::COLON, ":", currentLine }); continue; }
        if (ch == '=') { advance(); tokens.push_back({ TokenType::EQUALS, "=", currentLine }); continue; }
        if (ch == '$') {
            advance();
            std::string id = "$" + readIdentifier();
            tokens.push_back({ TokenType::DOLLAR_ID, id, currentLine });
            continue;
        }
        if (ch == '"' || ch == '\'') {
            tokens.push_back(readString());
            continue;
        }
        if (ch == '/') {
            tokens.push_back(readRegex());
            continue;
        }
        if (std::isdigit(static_cast<unsigned char>(ch))) {
            tokens.push_back(readNumber());
            continue;
        }

        if (std::isalpha(static_cast<unsigned char>(ch)) || ch == '_') {
            std::string val = readIdentifier();
            if (val == "any" || val == "all") {
                skipWhitespace();
                std::string next = readIdentifier();
                if (next == "of") {
                    tokens.push_back({ val == "any" ? TokenType::ANY_OF : TokenType::ALL_OF, val + " of", currentLine });
                } else {
                    tokens.push_back({ TokenType::IDENTIFIER, val, currentLine });
                    if (!next.empty()) {
                        tokens.push_back({ TokenType::IDENTIFIER, next, currentLine });
                    }
                }
            } else {
                auto it = keywords.find(val);
                if (it != keywords.end()) {
                    tokens.push_back({ it->second, val, currentLine });
                } else {
                    tokens.push_back({ TokenType::IDENTIFIER, val, currentLine });
                }
            }
            continue;
        }

        // Fallbacks for commas, brackets, etc.
        if (ch == ',' || ch == ';' || ch == '[' || ch == ']') {
            advance();
            continue;
        }

        throw std::runtime_error("[ShieldWall] Lexer error: Unexpected character '" + std::string(1, ch) + "' at line " + std::to_string(currentLine));
    }
    tokens.push_back({ TokenType::EOF_TOKEN, "", line });
    return tokens;
}

RuleParser::Parser::Parser(const std::vector<Token>& tokens)
    : tokens(tokens), pos(0) {}

RuleParser::Token RuleParser::Parser::peek() const {
    return pos < tokens.size() ? tokens[pos] : Token{ TokenType::EOF_TOKEN, "" };
}

RuleParser::Token RuleParser::Parser::advance() {
    if (pos < tokens.size()) return tokens[pos++];
    return Token{ TokenType::EOF_TOKEN, "" };
}

RuleParser::Token RuleParser::Parser::expect(TokenType type) {
    Token t = advance();
    if (t.type != type) {
        throw std::runtime_error("[ShieldWall] Parse error at line " + std::to_string(t.line) + ": Expected token type mismatch");
    }
    return t;
}

RuleParser::Token RuleParser::Parser::match(TokenType type) {
    if (peek().type == type) return advance();
    return Token{ TokenType::EOF_TOKEN, "" };
}

std::vector<ShieldRule> RuleParser::Parser::parseFile() {
    std::vector<ShieldRule> rules;
    while (peek().type != TokenType::EOF_TOKEN) {
        rules.push_back(parseRule());
    }
    return rules;
}

ShieldRule RuleParser::Parser::parseRule() {
    expect(TokenType::RULE);
    std::string name = expect(TokenType::IDENTIFIER).value;
    std::vector<std::string> tags;
    if (!match(TokenType::COLON).value.empty()) {
        while (peek().type == TokenType::IDENTIFIER) {
            tags.push_back(advance().value);
        }
    }
    expect(TokenType::LBRACE);

    ShieldRule rule;
    rule.name = name;
    rule.tags = tags;

    while (peek().type != TokenType::RBRACE) {
        Token sec = peek();
        if (sec.type == TokenType::META) {
            advance(); expect(TokenType::COLON);
            rule.meta = parseMeta();
        } else if (sec.type == TokenType::TARGET) {
            advance(); expect(TokenType::COLON);
            rule.targets = parseTarget();
        } else if (sec.type == TokenType::STRINGS) {
            advance(); expect(TokenType::COLON);
            rule.strings = parseStrings();
        } else if (sec.type == TokenType::CONDITION) {
            advance(); expect(TokenType::COLON);
            rule.condition = parseOr();
        } else {
            throw std::runtime_error("[ShieldWall] Parse error: Unexpected section in rule " + name);
        }
    }
    expect(TokenType::RBRACE);

    // ReDoS check and compiles strings regexes
    for (auto& [key, def] : rule.strings) {
        std::string pattern = def.type == "regex" ? def.pattern : escapeRegexLiteral(def.pattern);
        if (!isSafeRegExp(pattern)) {
            throw std::runtime_error("[ShieldWall] Bad regex: Unsafe RegExp pattern in \"" + name + "\" string \"" + key + "\" (ReDoS risk)");
        }
        std::regex_constants::syntax_option_type opt = std::regex_constants::ECMAScript;
        if (def.nocase) opt |= std::regex_constants::icase;
        
        try {
            def.compiled = std::regex(pattern, opt);
            def.hasCompiled = true;
        } catch (const std::regex_error& e) {
            throw std::runtime_error("[ShieldWall] Bad regex in \"" + name + "\" string \"" + key + "\": " + e.what());
        }
    }

    return rule;
}

std::unordered_map<std::string, std::string> RuleParser::Parser::parseMeta() {
    std::unordered_map<std::string, std::string> meta;
    while (peek().type == TokenType::IDENTIFIER) {
        std::string key = advance().value;
        expect(TokenType::EQUALS);
        Token v = advance();
        if (v.type == TokenType::STRING || v.type == TokenType::NUMBER) {
            meta[key] = v.value;
        } else if (v.type == TokenType::TRUE) {
            meta[key] = "true";
        } else if (v.type == TokenType::FALSE) {
            meta[key] = "false";
        } else {
            throw std::runtime_error("[ShieldWall] Parse error: Invalid meta value type");
        }
    }
    return meta;
}

std::unordered_map<std::string, std::string> RuleParser::Parser::parseTarget() {
    std::unordered_map<std::string, std::string> targets;
    while (peek().type == TokenType::DOLLAR_ID) {
        std::string n = advance().value;
        expect(TokenType::EQUALS);
        targets[n] = expect(TokenType::IDENTIFIER).value;
    }
    return targets;
}

std::unordered_map<std::string, RuleString> RuleParser::Parser::parseStrings() {
    std::unordered_map<std::string, RuleString> strings;
    while (peek().type == TokenType::DOLLAR_ID) {
        std::string name = advance().value;
        expect(TokenType::EQUALS);
        Token v = advance();
        if (v.type == TokenType::REGEX) {
            RuleString rs;
            rs.name = name;
            rs.type = "regex";
            rs.pattern = v.value;
            rs.nocase = v.flags.find('i') != std::string::npos;
            strings[name] = std::move(rs);
        } else if (v.type == TokenType::STRING) {
            bool nocase = false;
            if (peek().type == TokenType::IDENTIFIER && peek().value == "nocase") {
                advance();
                nocase = true;
            }
            RuleString rs;
            rs.name = name;
            rs.type = "literal";
            rs.pattern = v.value;
            rs.nocase = nocase;
            strings[name] = std::move(rs);
        } else {
            throw std::runtime_error("[ShieldWall] Parse error: Expected string or regex definition");
        }
    }
    return strings;
}

std::shared_ptr<AstNode> RuleParser::Parser::parseOr() {
    auto left = parseAnd();
    while (peek().type == TokenType::OR) {
        advance();
        auto node = std::make_shared<AstNode>();
        node->type = "or";
        node->left = left;
        node->right = parseAnd();
        left = node;
    }
    return left;
}

std::shared_ptr<AstNode> RuleParser::Parser::parseAnd() {
    auto left = parseNot();
    while (peek().type == TokenType::AND) {
        advance();
        auto node = std::make_shared<AstNode>();
        node->type = "and";
        node->left = left;
        node->right = parseNot();
        left = node;
    }
    return left;
}

std::shared_ptr<AstNode> RuleParser::Parser::parseNot() {
    if (peek().type == TokenType::NOT) {
        advance();
        auto node = std::make_shared<AstNode>();
        node->type = "not";
        node->expr = parsePrimary();
        return node;
    }
    return parsePrimary();
}

std::shared_ptr<AstNode> RuleParser::Parser::parsePrimary() {
    Token t = peek();
    if (t.type == TokenType::LPAREN) {
        advance();
        auto e = parseOr();
        expect(TokenType::RPAREN);
        return e;
    }
    if (t.type == TokenType::ANY_OF) {
        advance();
        if (!match(TokenType::THEM).value.empty()) {
            auto node = std::make_shared<AstNode>();
            node->type = "any_of_them";
            return node;
        }
        expect(TokenType::LPAREN);
        std::vector<std::string> vars;
        while (peek().type == TokenType::DOLLAR_ID) {
            vars.push_back(advance().value);
        }
        expect(TokenType::RPAREN);
        auto node = std::make_shared<AstNode>();
        node->type = "any_of";
        node->vars = vars;
        return node;
    }
    if (t.type == TokenType::ALL_OF) {
        advance();
        if (!match(TokenType::THEM).value.empty()) {
            auto node = std::make_shared<AstNode>();
            node->type = "all_of_them";
            return node;
        }
        expect(TokenType::LPAREN);
        std::vector<std::string> vars;
        while (peek().type == TokenType::DOLLAR_ID) {
            vars.push_back(advance().value);
        }
        expect(TokenType::RPAREN);
        auto node = std::make_shared<AstNode>();
        node->type = "all_of";
        node->vars = vars;
        return node;
    }
    if (t.type == TokenType::DOLLAR_ID) {
        std::string n = advance().value;
        if (peek().type == TokenType::IN) {
            advance();
            std::string target = expect(TokenType::DOLLAR_ID).value;
            auto node = std::make_shared<AstNode>();
            node->type = "match_in";
            node->pattern = n;
            node->target = target;
            return node;
        }
        auto node = std::make_shared<AstNode>();
        node->type = "match";
        node->pattern = n;
        return node;
    }
    if (t.type == TokenType::TRUE) {
        advance();
        auto node = std::make_shared<AstNode>();
        node->type = "boolean";
        node->booleanValue = true;
        return node;
    }
    if (t.type == TokenType::FALSE) {
        advance();
        auto node = std::make_shared<AstNode>();
        node->type = "boolean";
        node->booleanValue = false;
        return node;
    }
    throw std::runtime_error("[ShieldWall] Parse error at line " + std::to_string(t.line) + ": Unexpected token \"" + t.value + "\"");
}

std::vector<ShieldRule> RuleParser::parseRules(const std::string& source) {
    Lexer lexer(source);
    Parser parser(lexer.tokenize());
    return parser.parseFile();
}

std::vector<ShieldRule> RuleParser::parseRuleFile(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        throw std::runtime_error("[ShieldWall] Could not open file: " + filePath);
    }
    std::stringstream ss;
    ss << file.rdbuf();
    std::vector<ShieldRule> rules = parseRules(ss.str());
    
    // Set rule source file
    std::string baseName = std::filesystem::path(filePath).filename().string();
    for (auto& r : rules) {
        r.sourceFile = baseName;
    }
    return rules;
}

std::vector<ShieldRule> RuleParser::loadRulesFromDir(const std::string& dirPath) {
    std::vector<ShieldRule> allRules;
    if (!std::filesystem::exists(dirPath)) return allRules;
    
    for (auto const& entry : std::filesystem::directory_iterator(dirPath)) {
        if (entry.path().extension() == ".shield") {
            try {
                auto fileRules = parseRuleFile(entry.path().string());
                allRules.insert(allRules.end(), fileRules.begin(), fileRules.end());
            } catch (const std::exception& err) {
                std::cerr << "[ShieldWall] Error parsing " << entry.path().filename().string() << ": " << err.what() << "\n";
            }
        }
    }
    return allRules;
}
