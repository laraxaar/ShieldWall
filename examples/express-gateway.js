/*
 * Gateway integration example.
 *
 * Architecture:
 *   [Client] ──TLS──▶ [Go Gateway :8443] ──HTTP──▶ [Node.js :3000]
 *
 * Start:
 *   1. cd gateway && go run .                     # Start the Go TLS proxy
 *   2. node examples/express-gateway.js           # Start the Node.js backend
 *
 * Test:
 *   curl -k "https://localhost:8443/search?q=hello"
 *   curl -k "https://localhost:8443/fingerprint"
 *   curl -k "https://localhost:8443/search?q=' OR 1=1--"
 */

const express = require('express');
const shieldwall = require('../src/index');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Enable trustProxy so ShieldWall reads X-Forwarded-For from the Go gateway
app.use(shieldwall({
  mode: 'block',
  logLevel: 'info',
  trustProxy: true,
  rateLimit: { windowMs: 60_000, max: 100 },
  bruteForce: { maxAttempts: 5, sensitivePaths: ['/login'] },
  excludePaths: ['/health'],
  modules: {
    fingerprinter: true,
    botDetection: true,
  },
}));

// ── Fingerprint inspection endpoint ─────────────────────────────────────
// Returns all TLS fingerprint data injected by the Go gateway.
app.get('/fingerprint', (req, res) => {
  const tlsHeaders = {};
  const prefixes = ['x-ja3', 'x-ja4', 'x-tls', 'x-alpn', 'x-h2', 'x-real-ip', 'x-forwarded'];
  
  for (const [key, value] of Object.entries(req.headers)) {
    if (prefixes.some(p => key.startsWith(p))) {
      tlsHeaders[key] = value;
    }
  }

  // Run the fingerprinter module directly for analysis
  let fingerprinterResult = null;
  try {
    const { analyzeRequest } = require('../src/modules/fingerprinter');
    fingerprinterResult = analyzeRequest(req);
  } catch (err) {
    fingerprinterResult = { error: err.message };
  }

  res.json({
    message: '🔍 TLS Fingerprint Analysis',
    gateway_headers: tlsHeaders,
    fingerprinter_analysis: fingerprinterResult,
    shieldwall: req.shieldwall || null,
    raw_user_agent: req.headers['user-agent'],
  });
});

// ── Standard endpoints ──────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    message: '🛡️ ShieldWall + TLS Gateway Protected API',
    architecture: '[Client] ──TLS──▶ [Go Gateway :8443] ──HTTP──▶ [Node.js :3000]',
    endpoints: {
      '/fingerprint':  'View your TLS fingerprint analysis',
      '/search?q=...': 'Search (try injection here)',
      '/login':        'POST login (brute-force protected)',
      '/health':       'Health check (excluded from WAF)',
    },
    tls_headers_available: [
      'x-ja3-fingerprint', 'x-ja3-hash', 'x-ja4-fingerprint',
      'x-tls-version', 'x-tls-random-entropy', 'x-tls-has-grease',
      'x-tls-cipher-count', 'x-tls-extension-count', 'x-alpn',
    ],
  });
});

app.get('/search', (req, res) => res.json({ results: [], query: req.query.q }));
app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === 'admin' && password === 'admin') {
    return res.json({ status: 'ok', token: 'demo-token' });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 Node.js backend at http://localhost:${PORT}`);
  console.log('🛡️  ShieldWall active (block mode + TLS fingerprinting)\n');
  console.log('Architecture:');
  console.log('  [Client] ──TLS──▶ [Go Gateway :8443] ──HTTP──▶ [Node.js :3000]\n');
  console.log('Test via the Go gateway:');
  console.log(`  curl -k "https://localhost:8443/fingerprint"     # View TLS fingerprint`);
  console.log(`  curl -k "https://localhost:8443/search?q=hello"  # Normal request`);
  console.log(`  curl -k "https://localhost:8443/search?q=' OR 1=1--"  # Attack (blocked)\n`);
});
