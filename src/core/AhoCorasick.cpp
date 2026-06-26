#include "AhoCorasick.hpp"
#include <queue>
#include <unordered_set>

AhoCorasick::AhoCorasick() : compiled(false) {
    nodes.emplace_back(); // Root node at index 0
}

AhoCorasick::~AhoCorasick() {}

void AhoCorasick::add(const std::string& keyword, const std::string& output) {
    std::unique_lock<std::shared_mutex> lock(mutex);
    if (compiled) return;
    if (keyword.empty()) return;

    size_t nodeIdx = 0;
    for (char ch : keyword) {
        auto it = nodes[nodeIdx].children.find(ch);
        if (it == nodes[nodeIdx].children.end()) {
            size_t nextIdx = nodes.size();
            nodes[nodeIdx].children[ch] = nextIdx;
            nodes.emplace_back();
            nodeIdx = nextIdx;
        } else {
            nodeIdx = it->second;
        }
    }
    nodes[nodeIdx].outputs.push_back(output);
}

void AhoCorasick::build() {
    std::unique_lock<std::shared_mutex> lock(mutex);
    if (compiled) return;
    compiled = true;

    std::queue<size_t> q;
    for (auto const& [ch, childIdx] : nodes[0].children) {
        nodes[childIdx].fail = 0;
        q.push(childIdx);
    }

    while (!q.empty()) {
        size_t currentIdx = q.front();
        q.pop();

        for (auto const& [ch, childIdx] : nodes[currentIdx].children) {
            q.push(childIdx);

            size_t failNodeIdx = nodes[currentIdx].fail;
            while (failNodeIdx > 0 && nodes[failNodeIdx].children.find(ch) == nodes[failNodeIdx].children.end()) {
                failNodeIdx = nodes[failNodeIdx].fail;
            }

            auto it = nodes[failNodeIdx].children.find(ch);
            if (it != nodes[failNodeIdx].children.end()) {
                nodes[childIdx].fail = it->second;
            } else {
                nodes[childIdx].fail = 0;
            }

            size_t failLinkIdx = nodes[childIdx].fail;
            if (!nodes[failLinkIdx].outputs.empty()) {
                std::unordered_set<std::string> uniqueOutputs(nodes[childIdx].outputs.begin(), nodes[childIdx].outputs.end());
                uniqueOutputs.insert(nodes[failLinkIdx].outputs.begin(), nodes[failLinkIdx].outputs.end());
                nodes[childIdx].outputs.assign(uniqueOutputs.begin(), uniqueOutputs.end());
            }
        }
    }
}

std::vector<std::string> AhoCorasick::search(const std::string& text) const {
    std::shared_lock<std::shared_mutex> lock(mutex);
    if (!compiled) return {};
    if (text.empty()) return {};

    std::unordered_set<std::string> results;
    size_t nodeIdx = 0;

    for (char ch : text) {
        while (nodeIdx > 0 && nodes[nodeIdx].children.find(ch) == nodes[nodeIdx].children.end()) {
            nodeIdx = nodes[nodeIdx].fail;
        }
        auto it = nodes[nodeIdx].children.find(ch);
        if (it != nodes[nodeIdx].children.end()) {
            nodeIdx = it->second;
        } else {
            nodeIdx = 0;
        }

        for (auto const& out : nodes[nodeIdx].outputs) {
            results.insert(out);
        }
    }

    return std::vector<std::string>(results.begin(), results.end());
}
