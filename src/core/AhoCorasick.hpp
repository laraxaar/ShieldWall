#ifndef AHO_CORASICK_HPP
#define AHO_CORASICK_HPP

/**
 * @file AhoCorasick.hpp
 * @brief Flat node multi-pattern string search trie.
 * 
 * ROLE IN ARCHITECTURE:
 * Performs linear O(n) fast-path checks to pre-filter rule validations.
 */

#include <vector>
#include <unordered_map>
#include <string>
#include <shared_mutex>

/**
 * @class AhoCorasick
 * @brief High-performance Aho-Corasick automaton.
 * 
 * MIGRATED FROM: aho-corasick.js
 */
class AhoCorasick {
public:
    AhoCorasick();
    ~AhoCorasick();

    /**
     * @brief Inserts a literal keyword into the tree.
     * @param keyword The keyword string.
     * @param output Rule identifier associated with match.
     */
    void add(const std::string& keyword, const std::string& output);

    /**
     * @brief Compiles failure links using BFS.
     */
    void build();

    /**
     * @brief Scans a string in a single linear pass.
     * @param text The input search text.
     * @return List of matching rule output identifiers.
     */
    std::vector<std::string> search(const std::string& text) const;

private:
    struct Node {
        std::unordered_map<char, size_t> children;
        size_t fail = 0;
        std::vector<std::string> outputs;
    };

    std::vector<Node> nodes;
    bool compiled;
    mutable std::shared_mutex mutex;
};

#endif // AHO_CORASICK_HPP
