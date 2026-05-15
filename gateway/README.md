# ShieldWall TLS Fingerprint Gateway

Transparent Go reverse-proxy that intercepts raw TLS `ClientHello` messages, computes **JA3/JA4 fingerprints** and **Shannon entropy**, then injects them as HTTP headers before proxying to the Node.js ShieldWall engine.

## Architecture

```
[Client] ──TLS──▶ [Go Gateway :8443] ──HTTP──▶ [Node.js :3000]
                        │
                        ├─ Parse ClientHello (binary)
                        ├─ Compute JA3 hash (MD5)
                        ├─ Compute JA4 fingerprint (SHA256)
                        ├─ Calculate Client Random entropy
                        ├─ Detect GREASE values
                        └─ Inject X-JA3-*, X-TLS-* headers
```

## Quick Start

```bash
# 1. Start the Go gateway (auto-generates self-signed cert)
cd gateway
go run .

# 2. Start the Node.js backend (in another terminal)
node examples/express-gateway.js

# 3. Test
curl -k "https://localhost:8443/fingerprint"
```

## Build

```bash
cd gateway
go build -o shieldwall-gateway .
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:8443` | TLS listen address |
| `-backend` | `http://127.0.0.1:3000` | Node.js backend URL |
| `-cert` | (empty) | TLS certificate path |
| `-key` | (empty) | TLS private key path |
| `-auto-cert` | `true` | Auto-generate self-signed cert |
| `-log-level` | `info` | Logging verbosity |

## Injected Headers

| Header | Description |
|--------|-------------|
| `X-JA3-Fingerprint` | Raw JA3 string |
| `X-JA3-Hash` | MD5 of JA3 string |
| `X-JA4-Fingerprint` | JA4-style fingerprint |
| `X-ALPN` | Negotiated protocol (h2/http1.1) |
| `X-TLS-Version` | Highest TLS version |
| `X-TLS-Random-Entropy` | Shannon entropy (0-8) |
| `X-TLS-Has-GREASE` | GREASE value presence |
| `X-TLS-Cipher-Count` | Offered cipher count |
| `X-TLS-Extension-Count` | Extension count |
| `X-TLS-SNI` | Server Name Indication |
| `X-Forwarded-For` | Real client IP |

## Tests

```bash
cd gateway
go test -v ./...
go test -bench=. ./...
```

## Requirements

- Go 1.22+
- No external dependencies (pure stdlib)

## License

MIT — Same as ShieldWall
