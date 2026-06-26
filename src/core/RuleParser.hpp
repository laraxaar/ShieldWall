#ifndef RULE_PARSER_HPP
#define RULE_PARSER_HPP

/**
 * @file RuleParser.hpp
 * @brief Lexer and Recursive-Descent parser for compiling .shield signature rules.
 */

#include "WafTypes.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <regex>

/**
 * @struct AstNode
 * @brief Node in AST Condition tree.
 */
struct AstNode {
    std::string type; ///< "and", "or", "not", "match", "match_in", "any_of_them", "all_of_them", "any_of", "all_of", "boolean"
    std::shared_ptr<AstNode> left = nullptr;
    std::shared_ptr<AstNode> right = nullptr;
    std::shared_ptr<AstNode> expr = nullptr;
    std::string pattern;
    std::string target;
    std::vector<std::string> vars;
    bool booleanValue = false;
};

/**
 * @struct RuleString
 * @brief Pattern string definition (literal or regex).
 */
struct RuleString {
    std::string name;
    std::string type; ///< "regex" or "literal"
    std::string pattern;
    std::regex compiled;
    bool hasCompiled = false;
    bool nocase = false;
};

/**
 * @struct ShieldRule
 * @brief Abstract representation of compiled .shield DSL rule.
 */
struct ShieldRule {
    std::string name;
    std::vector<std::string> tags;
    std::unordered_map<std::string, std::string> meta;
    std::unordered_map<std::string, std::string> targets;
    std::unordered_map<std::string, RuleString> strings;
    std::shared_ptr<AstNode> condition = nullptr;
    std::string sourceFile;
};

/**
 * @class RuleParser
 * @brief Compiles rule definitions into parsed memory profiles.
 */
class RuleParser {
public:
    enum class TokenType {
        RULE, IDENTIFIER, COLON, LBRACE, RBRACE, LPAREN, RPAREN,
        EQUALS, DOLLAR_ID, STRING, REGEX, NUMBER, META, TARGET,
        STRINGS, CONDITION, AND, OR, NOT, IN, ANY_OF, ALL_OF,
        THEM, TRUE, FALSE, EOF_TOKEN
    };

    struct Token {
        TokenType type;
        std::string value;
        int line = 1;
        // Regex flag value
        std::string flags;
    };

    class Lexer {
    public:
        explicit Lexer(const std::string& source);
        std::vector<Token> tokenize();

    private:
        char peek() const;
        char advance();
        void skipWhitespace();
        Token readString();
        Token readRegex();
        std::string readIdentifier();
        Token readNumber();

        std::string source;
        size_t pos;
        int line;
        int col;
    };

    class Parser {
    public:
        explicit Parser(const std::vector<Token>& tokens);
        std::vector<ShieldRule> parseFile();

    private:
        Token peek() const;
        Token advance();
        Token expect(TokenType type);
        Token match(TokenType type);

        ShieldRule parseRule();
        std::unordered_map<std::string, std::string> parseMeta();
        std::unordered_map<std::string, std::string> parseTarget();
        std::unordered_map<std::string, RuleString> parseStrings();
        
        std::shared_ptr<AstNode> parseOr();
        std::shared_ptr<AstNode> parseAnd();
        std::shared_ptr<AstNode> parseNot();
        std::shared_ptr<AstNode> parsePrimary();

        std::vector<Token> tokens;
        size_t pos;
    };

    static std::vector<ShieldRule> parseRules(const std::string& source);
    static std::vector<ShieldRule> parseRuleFile(const std::string& filePath);
    static std::vector<ShieldRule> loadRulesFromDir(const std::string& dirPath);
};

#endif // RULE_PARSER_HPP
