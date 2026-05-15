'use strict';

// .shield rule parser — lexer + recursive-descent parser for the YARA-inspired DSL

const fs = require('fs');
const path = require('path');

const TOKEN = {
  RULE: 'RULE', IDENTIFIER: 'IDENTIFIER', COLON: 'COLON',
  LBRACE: 'LBRACE', RBRACE: 'RBRACE', LPAREN: 'LPAREN', RPAREN: 'RPAREN',
  EQUALS: 'EQUALS', DOLLAR_ID: 'DOLLAR_ID', STRING: 'STRING',
  REGEX: 'REGEX', NUMBER: 'NUMBER', META: 'META', TARGET: 'TARGET',
  STRINGS: 'STRINGS', CONDITION: 'CONDITION', AND: 'AND', OR: 'OR',
  NOT: 'NOT', IN: 'IN', ANY_OF: 'ANY_OF', ALL_OF: 'ALL_OF',
  THEM: 'THEM', TRUE: 'TRUE', FALSE: 'FALSE', EOF: 'EOF',
};

class Lexer {
  constructor(source) { this.source = source; this.pos = 0; this.line = 1; this.col = 1; this.tokens = []; }
  error(msg) { throw new Error(`[ShieldWall] Lexer error at line ${this.line}: ${msg}`); }
  peek() { return this.pos < this.source.length ? this.source[this.pos] : null; }

  advance() {
    const ch = this.source[this.pos++];
    if (ch === '\n') { this.line++; this.col = 1; } else { this.col++; }
    return ch;
  }

  skipWhitespace() {
    while (this.pos < this.source.length) {
      const ch = this.source[this.pos];
      if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') { this.advance(); }
      else if (ch === '/' && this.source[this.pos + 1] === '/') { while (this.pos < this.source.length && this.source[this.pos] !== '\n') this.advance(); }
      else if (ch === '/' && this.source[this.pos + 1] === '*') {
        this.advance(); this.advance();
        while (this.pos < this.source.length) { if (this.source[this.pos] === '*' && this.source[this.pos + 1] === '/') { this.advance(); this.advance(); break; } this.advance(); }
      } else break;
    }
  }

  readString() {
    const quote = this.advance();
    let value = '';
    while (this.pos < this.source.length) {
      const ch = this.source[this.pos];
      if (ch === '\\') { this.advance(); const esc = this.advance(); const m = { n: '\n', t: '\t', r: '\r', '\\': '\\', '"': '"', "'": "'" }; value += m[esc] || '\\' + esc; }
      else if (ch === quote) { this.advance(); return { type: TOKEN.STRING, value, line: this.line }; }
      else { value += this.advance(); }
    }
    this.error('Unterminated string');
  }

  readRegex() {
    this.advance();
    let pattern = '', escaped = false, inCC = false;
    while (this.pos < this.source.length) {
      const ch = this.source[this.pos];
      if (escaped) { pattern += ch; escaped = false; this.advance(); continue; }
      if (ch === '\\') { escaped = true; pattern += ch; this.advance(); continue; }
      if (ch === '[') inCC = true;
      if (ch === ']') inCC = false;
      if (ch === '/' && !inCC) {
        this.advance();
        let flags = '';
        while (this.pos < this.source.length && /[gimsuy]/.test(this.source[this.pos])) flags += this.advance();
        return { type: TOKEN.REGEX, value: { pattern, flags }, line: this.line };
      }
      pattern += ch; this.advance();
    }
    this.error('Unterminated regex');
  }

  readIdentifier() {
    let v = '';
    while (this.pos < this.source.length && /[a-zA-Z0-9_.]/.test(this.source[this.pos])) v += this.advance();
    return v;
  }

  readNumber() {
    let v = '';
    while (this.pos < this.source.length && /[0-9]/.test(this.source[this.pos])) v += this.advance();
    return { type: TOKEN.NUMBER, value: parseInt(v, 10), line: this.line };
  }

  tokenize() {
    const kw = { rule: TOKEN.RULE, meta: TOKEN.META, target: TOKEN.TARGET, strings: TOKEN.STRINGS, condition: TOKEN.CONDITION, and: TOKEN.AND, or: TOKEN.OR, not: TOKEN.NOT, in: TOKEN.IN, them: TOKEN.THEM, true: TOKEN.TRUE, false: TOKEN.FALSE };

    while (this.pos < this.source.length) {
      this.skipWhitespace();
      if (this.pos >= this.source.length) break;
      const ch = this.source[this.pos], line = this.line;

      if (ch === '{') { this.advance(); this.tokens.push({ type: TOKEN.LBRACE, line }); continue; }
      if (ch === '}') { this.advance(); this.tokens.push({ type: TOKEN.RBRACE, line }); continue; }
      if (ch === '(') { this.advance(); this.tokens.push({ type: TOKEN.LPAREN, line }); continue; }
      if (ch === ')') { this.advance(); this.tokens.push({ type: TOKEN.RPAREN, line }); continue; }
      if (ch === ':') { this.advance(); this.tokens.push({ type: TOKEN.COLON, line }); continue; }
      if (ch === '=') { this.advance(); this.tokens.push({ type: TOKEN.EQUALS, line }); continue; }
      if (ch === '$') { this.advance(); this.tokens.push({ type: TOKEN.DOLLAR_ID, value: '$' + this.readIdentifier(), line }); continue; }
      if (ch === '"' || ch === "'") { this.tokens.push(this.readString()); continue; }
      if (ch === '/') { this.tokens.push(this.readRegex()); continue; }
      if (/[0-9]/.test(ch)) { this.tokens.push(this.readNumber()); continue; }

      if (/[a-zA-Z_]/.test(ch)) {
        const val = this.readIdentifier();
        if (val === 'any' || val === 'all') {
          this.skipWhitespace();
          const next = this.readIdentifier();
          if (next === 'of') { this.tokens.push({ type: val === 'any' ? TOKEN.ANY_OF : TOKEN.ALL_OF, line }); }
          else { this.tokens.push({ type: TOKEN.IDENTIFIER, value: val, line }); if (next) this.tokens.push({ type: TOKEN.IDENTIFIER, value: next, line }); }
        } else if (kw[val]) { this.tokens.push({ type: kw[val], value: val, line }); }
        else { this.tokens.push({ type: TOKEN.IDENTIFIER, value: val, line }); }
        continue;
      }

      // Robust fallback: Skip common symbols that might cause Lexer errors if regex fails
      if (ch === ',' || ch === ';' || ch === '[' || ch === ']') { this.advance(); continue; }

      this.error(`Unexpected character: '${ch}'`);
    }
    this.tokens.push({ type: TOKEN.EOF, line: this.line });
    return this.tokens;
  }
}

class Parser {
  constructor(tokens) { this.tokens = tokens; this.pos = 0; }
  error(msg) { const t = this.tokens[this.pos] || { line: '?' }; throw new Error(`[ShieldWall] Parse error at line ${t.line}: ${msg}`); }
  peek() { return this.tokens[this.pos] || { type: TOKEN.EOF }; }
  advance() { return this.tokens[this.pos++]; }
  expect(type) { const t = this.advance(); if (t.type !== type) this.error(`Expected ${type}, got ${t.type}`); return t; }
  match(type) { return this.peek().type === type ? this.advance() : null; }

  parseFile() { const rules = []; while (this.peek().type !== TOKEN.EOF) rules.push(this.parseRule()); return rules; }

  parseRule() {
    this.expect(TOKEN.RULE);
    const name = this.expect(TOKEN.IDENTIFIER).value;
    let tags = [];
    if (this.match(TOKEN.COLON)) { while (this.peek().type === TOKEN.IDENTIFIER) tags.push(this.advance().value); }
    this.expect(TOKEN.LBRACE);

    const rule = { name, tags, meta: {}, targets: {}, strings: {}, condition: null };

    while (this.peek().type !== TOKEN.RBRACE) {
      const sec = this.peek();
      if (sec.type === TOKEN.META) { this.advance(); this.expect(TOKEN.COLON); rule.meta = this._parseMeta(); }
      else if (sec.type === TOKEN.TARGET) { this.advance(); this.expect(TOKEN.COLON); rule.targets = this._parseTarget(); }
      else if (sec.type === TOKEN.STRINGS) { this.advance(); this.expect(TOKEN.COLON); rule.strings = this._parseStrings(); }
      else if (sec.type === TOKEN.CONDITION) { this.advance(); this.expect(TOKEN.COLON); rule.condition = this._parseOr(); }
      else this.error(`Unexpected section: ${sec.value || sec.type}`);
    }
    this.expect(TOKEN.RBRACE);

    for (const [key, def] of Object.entries(rule.strings)) {
      try {
        def.compiled = def.type === 'regex'
          ? new RegExp(def.pattern, def.flags || '')
          : new RegExp(def.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), def.nocase ? 'i' : '');
      } catch (e) { throw new Error(`[ShieldWall] Bad regex in "${name}" string "${key}": ${e.message}`); }
    }
    return rule;
  }

  _parseMeta() {
    const meta = {};
    while (this.peek().type === TOKEN.IDENTIFIER) {
      const key = this.advance().value; this.expect(TOKEN.EQUALS); const v = this.advance();
      if (v.type === TOKEN.STRING) meta[key] = v.value;
      else if (v.type === TOKEN.NUMBER) meta[key] = v.value;
      else if (v.type === TOKEN.TRUE) meta[key] = true;
      else if (v.type === TOKEN.FALSE) meta[key] = false;
      else this.error(`Invalid meta value: ${v.type}`);
    }
    return meta;
  }

  _parseTarget() {
    const targets = {};
    while (this.peek().type === TOKEN.DOLLAR_ID) { const n = this.advance().value; this.expect(TOKEN.EQUALS); targets[n] = this.expect(TOKEN.IDENTIFIER).value; }
    return targets;
  }

  _parseStrings() {
    const strings = {};
    while (this.peek().type === TOKEN.DOLLAR_ID) {
      const name = this.advance().value; this.expect(TOKEN.EQUALS); const v = this.advance();
      if (v.type === TOKEN.REGEX) { strings[name] = { type: 'regex', pattern: v.value.pattern, flags: v.value.flags }; }
      else if (v.type === TOKEN.STRING) {
        let nocase = false; if (this.peek().type === TOKEN.IDENTIFIER && this.peek().value === 'nocase') { this.advance(); nocase = true; }
        strings[name] = { type: 'literal', value: v.value, nocase };
      } else this.error(`Expected regex or string, got ${v.type}`);
    }
    return strings;
  }

  _parseOr() { let l = this._parseAnd(); while (this.peek().type === TOKEN.OR) { this.advance(); l = { type: 'or', left: l, right: this._parseAnd() }; } return l; }
  _parseAnd() { let l = this._parseNot(); while (this.peek().type === TOKEN.AND) { this.advance(); l = { type: 'and', left: l, right: this._parseNot() }; } return l; }
  _parseNot() { return this.peek().type === TOKEN.NOT ? (this.advance(), { type: 'not', expr: this._parsePrimary() }) : this._parsePrimary(); }

  _parsePrimary() {
    const t = this.peek();
    if (t.type === TOKEN.LPAREN) { this.advance(); const e = this._parseOr(); this.expect(TOKEN.RPAREN); return e; }
    if (t.type === TOKEN.ANY_OF) { this.advance(); if (this.match(TOKEN.THEM)) return { type: 'any_of_them' }; this.expect(TOKEN.LPAREN); const v = []; while (this.peek().type === TOKEN.DOLLAR_ID) v.push(this.advance().value); this.expect(TOKEN.RPAREN); return { type: 'any_of', vars: v }; }
    if (t.type === TOKEN.ALL_OF) { this.advance(); if (this.match(TOKEN.THEM)) return { type: 'all_of_them' }; this.expect(TOKEN.LPAREN); const v = []; while (this.peek().type === TOKEN.DOLLAR_ID) v.push(this.advance().value); this.expect(TOKEN.RPAREN); return { type: 'all_of', vars: v }; }
    if (t.type === TOKEN.DOLLAR_ID) { const n = this.advance().value; if (this.peek().type === TOKEN.IN) { this.advance(); return { type: 'match_in', pattern: n, target: this.expect(TOKEN.DOLLAR_ID).value }; } return { type: 'match', pattern: n }; }
    if (t.type === TOKEN.TRUE) { this.advance(); return { type: 'boolean', value: true }; }
    if (t.type === TOKEN.FALSE) { this.advance(); return { type: 'boolean', value: false }; }
    this.error(`Unexpected token: ${t.type}`);
  }
}

function parseRules(source) { return new Parser(new Lexer(source).tokenize()).parseFile(); }

function parseRuleFile(filePath) {
  const rules = parseRules(fs.readFileSync(filePath, 'utf-8'));
  for (const r of rules) r.sourceFile = path.basename(filePath);
  return rules;
}

function loadRulesFromDir(dirPath) {
  const all = [];
  for (const file of fs.readdirSync(dirPath)) {
    if (!file.endsWith('.shield')) continue;
    try { all.push(...parseRuleFile(path.join(dirPath, file))); }
    catch (err) { console.error(`[ShieldWall] Error parsing ${file}: ${err.message}`); }
  }
  return all;
}

module.exports = { parseRules, parseRuleFile, loadRulesFromDir, Lexer, Parser };
