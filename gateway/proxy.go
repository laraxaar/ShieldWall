package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── prefixConn: replays buffered bytes then reads from real conn ────────────

// prefixConn wraps a net.Conn and prepends previously-read bytes.
// This allows us to read the raw ClientHello for parsing, then replay
// those same bytes to crypto/tls for the actual handshake.
type prefixConn struct {
	net.Conn
	reader io.Reader
}

func (c *prefixConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func newPrefixConn(conn net.Conn, prefix []byte) *prefixConn {
	return &prefixConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(prefix), conn),
	}
}

// ── FingerprintStore: thread-safe per-connection fingerprint cache ──────────

// FingerprintStore maps remote addresses to their computed TLS fingerprints.
type FingerprintStore struct {
	mu    sync.RWMutex
	store map[string]*Fingerprint
}

func NewFingerprintStore() *FingerprintStore {
	return &FingerprintStore{store: make(map[string]*Fingerprint)}
}

func (s *FingerprintStore) Set(addr string, fp *Fingerprint) {
	s.mu.Lock()
	s.store[addr] = fp
	s.mu.Unlock()
}

func (s *FingerprintStore) Get(addr string) *Fingerprint {
	s.mu.RLock()
	fp := s.store[addr]
	s.mu.RUnlock()
	return fp
}

func (s *FingerprintStore) Delete(addr string) {
	s.mu.Lock()
	delete(s.store, addr)
	s.mu.Unlock()
}

// ── TLS Intercepting Listener ──────────────────────────────────────────────

// TLSInterceptor wraps a TCP listener. For each connection it:
// 1. Reads the raw ClientHello bytes
// 2. Parses them for fingerprinting
// 3. Stores the fingerprint keyed by remote address
// 4. Replays the bytes into crypto/tls for the real handshake
type TLSInterceptor struct {
	tcpListener net.Listener
	tlsConfig   *tls.Config
	fpStore     *FingerprintStore
	logger      *log.Logger
}

func NewTLSInterceptor(ln net.Listener, cfg *tls.Config, store *FingerprintStore, logger *log.Logger) *TLSInterceptor {
	return &TLSInterceptor{
		tcpListener: ln,
		tlsConfig:   cfg,
		fpStore:     store,
		logger:      logger,
	}
}

func (t *TLSInterceptor) Accept() (net.Conn, error) {
	for {
		tcpConn, err := t.tcpListener.Accept()
		if err != nil {
			return nil, err
		}

		// Set a deadline for the ClientHello read to prevent slow-loris
		tcpConn.SetReadDeadline(time.Now().Add(10 * time.Second))

		// Read and parse the raw ClientHello
		rawBytes, ch, parseErr := ReadClientHello(tcpConn)

		// Reset deadline
		tcpConn.SetReadDeadline(time.Time{})

		if parseErr != nil {
			t.logger.Printf("⚠ ClientHello parse failed from %s: %v", tcpConn.RemoteAddr(), parseErr)
			// Still try to complete the connection — just without fingerprint data
		}

		if ch != nil {
			fp := ComputeFingerprint(ch)
			t.fpStore.Set(tcpConn.RemoteAddr().String(), fp)
			t.logger.Printf("🔍 TLS Fingerprint [%s] JA3=%s JA4=%s GREASE=%v entropy=%.3f",
				tcpConn.RemoteAddr(), fp.JA3Hash, fp.JA4, fp.HasGREASE, fp.RandomEntropy)
		}

		// Create a prefixConn that replays the raw bytes we already consumed
		var replayConn net.Conn
		if rawBytes != nil {
			replayConn = newPrefixConn(tcpConn, rawBytes)
		} else {
			replayConn = tcpConn
		}

		// Wrap with TLS for the actual handshake
		tlsConn := tls.Server(replayConn, t.tlsConfig)
		return tlsConn, nil
	}
}

func (t *TLSInterceptor) Close() error {
	return t.tcpListener.Close()
}

func (t *TLSInterceptor) Addr() net.Addr {
	return t.tcpListener.Addr()
}

// ── Reverse Proxy with Header Injection ─────────────────────────────────────

// CreateReverseProxy builds an HTTP handler that:
// 1. Looks up the TLS fingerprint for the current connection
// 2. Injects fingerprint data as X-* headers
// 3. Forwards the request to the Node.js backend
func CreateReverseProxy(backendURL *url.URL, fpStore *FingerprintStore, logger *log.Logger) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(backendURL)

	// Custom transport with sensible timeouts
	proxy.Transport = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	// Error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Printf("❌ Proxy error [%s %s]: %v", r.Method, r.URL.Path, err)
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"error":"Bad Gateway","message":"Backend unreachable"}`))
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteAddr := r.RemoteAddr

		// Support for reverse proxies / load balancers
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// X-Forwarded-For can contain multiple IPs, take the first one (client)
			remoteAddr = strings.TrimSpace(strings.Split(xff, ",")[0])
			// In a real LB scenario, we should also parse PROXY protocol at the TCP level
			// to store the fingerprint under the real client IP. For now, we fallback
			// to connection RemoteAddr if the FP is not found by XFF.
		}

		// Inject Gateway Authentication Secret to prevent Header Spoofing
		gatewaySecret := os.Getenv("GATEWAY_SECRET")
		if gatewaySecret != "" {
			r.Header.Set("X-Gateway-Auth", gatewaySecret)
		}

		// Look up fingerprint for this connection (Try XFF first, fallback to TCP RemoteAddr)
		fp := fpStore.Get(remoteAddr)
		if fp == nil {
			fp = fpStore.Get(r.RemoteAddr)
		}

		if fp != nil {
			// ── Inject TLS fingerprint headers ──────────────────────────

			// Core fingerprints (consumed by Node.js fingerprinter.js)
			r.Header.Set("X-JA3-Fingerprint", fp.JA3String)
			r.Header.Set("X-JA3-Hash", fp.JA3Hash)
			r.Header.Set("X-JA4-Fingerprint", fp.JA4)

			// Protocol info (consumed by decoder.js getAlpn/extractH2Fingerprint)
			if fp.ALPN != "" {
				r.Header.Set("X-ALPN", fp.ALPN)
			}
			r.Header.Set("X-TLS-Version", fp.TLSVersion)

			// Enrichment data for deep heuristic analysis
			r.Header.Set("X-TLS-Cipher-Count", strconv.Itoa(fp.CipherCount))
			r.Header.Set("X-TLS-Extension-Count", strconv.Itoa(fp.ExtensionCount))
			r.Header.Set("X-TLS-Random-Entropy", fmt.Sprintf("%.3f", fp.RandomEntropy))
			r.Header.Set("X-TLS-Session-ID-Length", strconv.Itoa(fp.SessionIDLength))
			r.Header.Set("X-TLS-Has-GREASE", strconv.FormatBool(fp.HasGREASE))
			r.Header.Set("X-TLS-GREASE-Count", strconv.Itoa(fp.GREASECount))
			r.Header.Set("X-TLS-Compression-Count", strconv.Itoa(fp.CompressionCount))
			r.Header.Set("X-TLS-Has-Status-Request", strconv.FormatBool(fp.HasStatusRequest))
			r.Header.Set("X-TLS-Has-Renegotiation", strconv.FormatBool(fp.HasRenegotiation))
			r.Header.Set("X-TLS-Padding-Length", strconv.Itoa(fp.PaddingLength))

			if fp.SupportedVersions != "" {
				r.Header.Set("X-TLS-Supported-Versions", fp.SupportedVersions)
			}
			if fp.ServerName != "" {
				r.Header.Set("X-TLS-SNI", fp.ServerName)
			}

			// Detect H2 and set fingerprint placeholder
			if strings.Contains(fp.ALPN, "h2") || r.ProtoMajor == 2 {
				r.Header.Set("X-H2-Fingerprint", fmt.Sprintf("gw:%s", fp.JA4))
			}

			// Clean up after proxying
			defer fpStore.Delete(remoteAddr)
		}

		// Forward real client IP
		clientIP := remoteAddr
		if host, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = host
		}
		
		// Only set if not already provided by an upstream trusted proxy
		if r.Header.Get("X-Forwarded-For") == "" {
			r.Header.Set("X-Forwarded-For", clientIP)
		}
		r.Header.Set("X-Real-IP", clientIP)
		r.Header.Set("X-Forwarded-Proto", "https")

		logger.Printf("→ %s %s [%s] JA3=%s",
			r.Method, r.URL.Path, clientIP,
			r.Header.Get("X-JA3-Hash"))

		proxy.ServeHTTP(w, r)
	})
}
