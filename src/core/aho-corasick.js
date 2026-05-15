'use strict';

/**
 * @file aho-corasick.js
 * @description Zero-dependency Aho-Corasick automaton for lightning-fast multi-pattern string search.
 * This is used to pre-filter rule evaluations. Instead of running 60+ RegExp tests, 
 * we do a single linear O(n) pass over the payload to find literal 'hooks'.
 */
class AhoCorasick {
  constructor() {
    this.root = this.createNode();
    this.compiled = false;
  }

  createNode() {
    return {
      children: new Map(),
      fail: null,
      outputs: [] // Array of rule IDs/Names that trigger here
    };
  }

  /**
   * Add a keyword to the Trie.
   * @param {string} keyword - The literal string to search for.
   * @param {any} output - The metadata (e.g. Rule Name) to return when matched.
   */
  add(keyword, output) {
    if (this.compiled) throw new Error("Cannot add keywords after compilation.");
    if (!keyword) return;

    let node = this.root;
    // We normalize case for search if nocase is needed, 
    // but the engine will pass pre-lowercased payloads to the search if it expects case-insensitivity.
    for (const char of keyword) {
      if (!node.children.has(char)) {
        node.children.set(char, this.createNode());
      }
      node = node.children.get(char);
    }
    node.outputs.push(output);
  }

  /**
   * Compile the failure links (BFS).
   */
  build() {
    this.compiled = true;
    const queue = [];
    
    // Set fail links for depth 1 nodes to root and push to queue
    for (const child of this.root.children.values()) {
      child.fail = this.root;
      queue.push(child);
    }

    while (queue.length > 0) {
      const current = queue.shift();

      for (const [char, child] of current.children.entries()) {
        queue.push(child);

        let failNode = current.fail;
        while (failNode !== null && !failNode.children.has(char)) {
          failNode = failNode.fail;
        }

        child.fail = failNode ? failNode.children.get(char) : this.root;
        
        // Merge outputs from fail link
        if (child.fail.outputs.length > 0) {
          child.outputs = [...new Set([...child.outputs, ...child.fail.outputs])];
        }
      }
    }
  }

  /**
   * Scan text in a single O(n) pass.
   * @param {string} text - The payload to scan.
   * @returns {Array} List of unique outputs (e.g. rule names) that had matches.
   */
  search(text) {
    if (!this.compiled) this.build();
    if (!text) return [];

    const results = new Set();
    let node = this.root;

    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      while (node !== null && !node.children.has(char)) {
        node = node.fail;
      }
      node = node ? node.children.get(char) : this.root;
      
      for (const output of node.outputs) {
        results.add(output);
      }
    }
    
    return Array.from(results);
  }
}

module.exports = AhoCorasick;
