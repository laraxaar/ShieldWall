<p align="center">
  <img src="https://img.shields.io/badge/node-%3E%3D16.0.0-brightgreen?logo=node.js" alt="Node.js">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License">
  <img src="https://img.shields.io/badge/dependencies-0-success" alt="Zero Dependencies">
  <img src="https://img.shields.io/badge/status-alpha-yellow" alt="Status">
</p>

<h1 align="center">🛡️ ShieldWall Next-Gen</h1>

<p align="center">
  <b>EDR-level Web Application Firewall for Node.js</b><br>
  <i>Context-aware security engine with Stateful Session Analysis & Behavioral Fingerprinting</i>
</p>

---

> **⚠️ DISCLAIMER**
>
> This project is provided **"as-is"** for educational and research purposes.
> It requires **adaptation and tuning** for any specific deployment.  The
> authors accept **no responsibility** for vulnerabilities, false positives,
> or security incidents in applications that use this middleware.  Always
> combine ShieldWall with other security layers — it is not a silver bullet.

---

## How It Works

ShieldWall takes a **layered approach** instead of trying to enumerate every
known attack signature:

```
HTTP Request (Gateway)
  │
  ├─ 1. TLS Interception         JA3/JA4 extraction, Client Random entropy, GREASE detection
  │
Request Payload (Engine)
  │
  ├─ 2. Multi-layer Decoder      URL / HTML / Unicode / Base64 normalization
  ├─ 3. Anomaly Scoring          N-Gram deviation, Shannon entropy, SSTI, Prototype Pollution
  ├─ 4. Adaptive Baselines       Per-parameter profiling (EWMA length/type tracking)
  ├─ 5. Session EDR (Stateful)   Request Lineage (Graph), BOLA/IDOR tracking
  ├─ 6. Sequence Analysis        Mathematical scraping & ID enumeration detection
  ├─ 7. Honeypot Traps           Invisible forms, fake endpoints, bot detection
  ├─ 8. .shield Rule Engine      YARA-inspired DSL for custom logic
  ├─ 9. Rate Limiter             Sliding window per-IP & Brute-force guard
  ├─ 10. Cross-Module Boosting   Non-linear risk aggregation (Bot + Payload)
  ├─ 11. Feedback Loop           Backend Timing (Blind SQLi) & Exfiltration detection
  └─ 12. Security Headers        CSP, HSTS, X-Frame-Options, Permissions-Policy
```

The key insight: instead of hardcoding thousands of exploit payloads, ShieldWall
asks *"does this request look normal?"*  The **anomaly scorer** assigns a
suspicion score based on behavioral signals (encoding layers, character entropy,
nesting depth, mixed encoding schemes), while **baseline patterns** and
**.shield rules** catch the most obvious structural attack shapes.

This makes it **database-agnostic** and **adaptive** — it works against SQL,
NoSQL, LDAP, GraphQL, or any other injection target.

---

## Architecture Boundaries

ShieldWall has strict separation between layers. Each makes promises about
what it **does** and **does not** do, ensuring predictable, non-destructive behavior:

| Layer | Role | Does NOT |
|---|---|---|
| **Decoder** | Normalizes encoding (URL, HTML, Unicode, Base64). Produces canonical request representation | Make security decisions. Mutate original request. Call network |
| **Feature Extractor** | Calculates entropy, encoding depth, char distribution | Block or allow anything. Persist state |
| **Detectors** (modules) | Match patterns, score signals, detect anomalies | Write to disk. Make network calls |
| **Scoring Engine** | Aggregates detector outputs into risk score | Enforce policy (block/allow) |
| **Decision Engine** | Applies policy (block/detect/log) based on score + severity | Normalize input. Score signals |
| **Auto-Rule Generator** | Creates candidate signatures from zero-day anomalies | Promote rules without TTL. Override existing rules |

### Design Guarantees

- **Decoding is bounded** (`MAX_DECODE_DEPTH = 5`).
- **No network calls** in the hot path.
- **No mutation** of the original `req` object.
- **Deterministic output** for identical input (no randomness).
- **Auto-generated rules expire** after 7 days (must be manually promoted).
- **Feedback loop adapts signal weights** but never drops below 10% base weight, preventing self-muting.

---

## Installation

```bash
npm install shieldwall
```

## Quick Start

```javascript
const express = require('express');
const shieldwall = require('shieldwall');

const app = express();
app.use(express.json());

app.use(shieldwall({
  mode: 'block',        // 'block' or 'detect' (log only)
  dashboard: { port: 9090 },
  rateLimit: { max: 100 },
  bruteForce: { maxAttempts: 5 },
}));

app.get('/', (req, res) => {
  res.json({ message: 'Protected by ShieldWall 🛡️' });
});

app.listen(3000);
```

---

## .shield Rule Syntax

Write custom detection rules in a YARA-inspired DSL:

```
rule my_detection : tag {
    meta:
        author      = "You"
        description = "What this catches and why"
        severity    = "critical"

    target:
        $url  = request.url
        $body = request.body

    strings:
        $pattern = /suspicious_regex/i

    condition:
        $pattern in $url or $pattern in $body
}
```

### Targets

| Target | Description |
|--------|-------------|
| `request.url` | Full decoded URL |
| `request.body` | Request body |
| `request.query` | Query string parameters |
| `request.headers` | All headers |
| `request.cookies` | Cookie values |
| `request.useragent` | User-Agent string |
| `request.raw_url` | URL before decoding (for evasion detection) |
| `request.session` / `request.sessionid` | Session identifier |
| `request.timestamp` / `request.time` | Request timestamp |
| `request.geoip` / `request.geo` | GeoIP data (country, city, ASN) |
| `request.fingerprint` / `request.fp` | Browser/device fingerprint |
| `request.rate` | Rate limit counter data |

### Condition Operators

`and`, `or`, `not`, `in` (target-scoped match), `any of them`, `all of them`, `( )` grouping.

Rules can be loaded from files, directories, or inline strings — see examples.

### Built-in Rule Files

| File | Protection |
|------|------------|
| `sqli.shield` | SQL and NoSQL injection patterns |
| `xss.shield` | Cross-site scripting attacks |
| `traversal.shield` | Path traversal and LFI/RFI |
| `cmdi.shield` | Command injection attacks |
| `protocol.shield` | HTTP smuggling, SSRF, CRLF injection |
| `scanner.shield` | Known security scanner detection |
| `graphql.shield` | GraphQL query depth bombing and introspection |
| `jwt.shield` | JWT algorithm confusion and key injection |
| `deserialization.shield` | Java/PHP/Node.js/Python deserialization |
| `cors.shield` | CORS misconfiguration abuse |
| `file_upload.shield` | Dangerous file upload patterns |
| `dos_protection.shield` | L7 DDoS - Slowloris, header swelling, parameter floods |
| `api_security.shield` | IDOR/BOLA, mass assignment, anomalous Content-Type |
| `proto_pollution.shield` | Node.js prototype pollution attacks |
| `obfuscation_evasion.shield` | Double Base64, hex encoding, Unicode homoglyphs |
| `business_logic.shield` | Form speed, cart manipulation, scraping patterns |
| `security_misconfig.shield` | Debug endpoints, config files, backup access |

---

## Modules

| Module | Approach |
|--------|----------|
| **Anomaly Scoring** | Behavioral heuristics — encoding layers, char density, nesting depth, mixed schemes, entropy analysis, parameter pollution, raw byte injection, payload inflation, header integrity |
| **Honeypot** | Invisible HTML traps, fake admin panels, fake APIs — flags anything that interacts |
| **Injection** | Structural patterns (context breaks + keywords) — database-agnostic |
| **XSS** | HTML execution shapes (tags, handlers, protocol, DOM sinks) |
| **Path Traversal** | Decoded traversal + encoding evasion detection on raw URL |
| **Command Injection** | Shell metacharacter + command name structural pair |
| **Scanner Detection** | User-Agent fingerprints and out-of-band callback domains |
| **Protocol Abuse** | HTTP smuggling, SSRF, CRLF, host header poisoning |
| **Rate Limiter** | Sliding window per-IP with auto-blocking |
| **Brute-Force Guard** | Progressive backoff on sensitive endpoints |
| **Security Headers** | CSP, HSTS, Permissions-Policy, etc. (helmet.js alternative) |
| **Bot Detection** | Headless browser detection, automation tools, behavioral analysis |
| **Session Anomaly** | 
// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                ShieldWall Session EDR (Stateful)                         ║
// ║                                                                         ║
// ║  Provides high-level context awareness similar to Endpoint Detection     ║
// ║  and Response (EDR) systems. Tracks sessions across requests to detect  ║
// ║  logical bypasses, lateral movement, and identity theft.                ║
// ║                                                                         ║
// ║  Core Capabilities:                                                     ║
// ║  ├─ Request Lineage: Validates logical navigation flow graphs.           ║
// ║  ├─ BOLA/IDOR Detection: Tracks resource ID access patterns.             ║
// ║  ├─ Context Drift: Monitors IP/TLS identity shifts mid-session.          ║
// ║  └─ Velocity Control: Detects "Impossible Human" interaction speeds.     ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
| **API Abuse** | GraphQL complexity analysis, REST enumeration, batch attack detection |
| **DDoS Protection** | L7 flood detection - Slowloris, oversized headers, connection floods |

---

## Anomaly Threshold Calibration

All thresholds are empirically tuned against a mix of legitimate web traffic and
known attack corpora (SQLi, XSS, encoded payloads, PE/ELF uploads).  Reference
scores for common payloads:

| Payload type | Typical score | Level |
|---|---|---|
| Normal `GET /api/users` | 0 – 3 | none |
| GraphQL introspection | 4 – 8 | none/low |
| JWT in Authorization | 2 – 5 | none |
| `' OR 1=1 --` | 12 – 18 | medium/high |
| UNION SELECT (encoded) | 22 – 35 | high/critical |
| `<script>alert(1)</script>` | 14 – 20 | high |
| Multi-layer encoded payload | 20 – 40+ | critical |

**Score threshold (15)** — lowest score at which known attacks reliably trigger.<br>
**Critical threshold (30)** — requires ≥3 independent high-weight signals; extremely unlikely for legitimate traffic.<br>
**Entropy 5.5** — sits above normal URL-encoded values (≈4.5–5.2) but below pure base64/encrypted data (≈5.8–6.0).

Known false-positive sources (JWTs, GraphQL introspection, hex hashes, versioned
REST paths) are automatically suppressed.

---

## Honeypot

ShieldWall automatically injects invisible HTML traps into your pages:

- Hidden forms that humans can't see but bots auto-fill
- Fake links to `/admin-panel`, `/.env`, `/.git/config`
- Fake API endpoints like `/api/internal/debug`

Any interaction with these traps immediately flags the client as a bot.

---

## Dashboard

Real-time monitoring at `http://localhost:9090`:

- Live attack feed with severity indicators
- Why each request was blocked (human-readable explanations)
- Severity breakdown, top attack types, top attacker IPs
- WebSocket-powered — updates instantly

---

## Configuration

```javascript
shieldwall({
  mode: 'block',                    // 'block' | 'detect'
  logLevel: 'info',                 // 'error' | 'warn' | 'info' | 'debug'
  jsonLogs: false,                  // structured JSON output
  rulesDir: './rules',              // .shield files directory
  customRules: '...',               // inline .shield string
  customRulesFiles: [],             // additional .shield file paths
  blockStatusCode: 403,
  blockMessage: null,               // string or function(matches)
  trustProxy: false,
  excludePaths: ['/health'],
  excludeIPs: ['127.0.0.1'],
  modules: { anomaly: true, honeypot: true, sqli: true, xss: true, pathTraversal: true, commandInjection: true, botDetection: true, sessionAnomaly: true, apiAbuse: true },
  rateLimit: { windowMs: 60000, max: 100 },
  bruteForce: { maxAttempts: 5, sensitivePaths: ['/login'] },
  dashboard: { port: 9090 },
  headers: { hsts: { maxAge: 31536000 } },
  honeypot: true,                   // inject HTML traps into responses
  reporting: {
    enabled: true,
    reportsDir: './reports',
    maxStoredReports: 12,
  },
});
```

### Programmatic Access

```javascript
const waf = shieldwall({ ... });

waf.on('threat', (event) => {
  // event.matches — what triggered
  // event.request — IP, method, URL
  // send to Slack, Discord, webhook, SIEM...
});

waf.on('report', ({ type, report, filepath }) => {
  // type: '14d' | 'monthly'
  // report — full report object with trends, ROI, persistent attackers
  // filepath — path to saved JSON file
});

waf.getStats();              // request/block/threat counters
waf.getReport(14);           // generate report for last 14 days
waf.getStoredReports();      // get all stored reports
waf.reloadRules();           // hot-reload .shield files
```

### Automatic Reports

ShieldWall generates reports automatically:

- **Every 14 days** — summary report with key statistics
- **Monthly** — detailed report with trends, ROI metrics, vector shift analysis, and persistent attacker tracking

Reports are saved to `reports/` and include:
- Attack summary by severity and category
- Top attacked endpoints with protection recommendations
- Attack dynamics (comparison with previous period)
- New attack patterns detection
- Geographic distribution
- ROI metrics (traffic saved, CPU time saved, cost estimate)
- Vector shift analysis (e.g., cmdi → api-abuse migration)
- Persistent attacker identification (IP reconnaissance tracking)
- SVG timeline charts

---

## Logging

Every blocked request produces a structured log explaining:

```
[SHIELDWALL] 🔴 BLOCKED | anomaly_detection [critical] | 192.168.1.50 POST /api/data
  ├─ Why: Anomaly score 28/30: multi_layer_encoding, unusual_char_density, comment_syntax
  └─ Evidence: [multi_layer_encoding] 3 layers of URL encoding — likely evasion attempt
```

JSON mode (`jsonLogs: true`) outputs machine-parseable entries for SIEM integration.

---

## License

MIT — see [LICENSE](./LICENSE)

---

<p align="center">
  <i>Built for the security research community.<br>
  This is a tool, not a product — tune it for your environment.</i>
</p>
