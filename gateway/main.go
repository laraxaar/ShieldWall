package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║              ShieldWall Next-Gen TLS Gateway (Go)                       ║
// ║                                                                         ║
// ║  High-performance reverse proxy that performs deep ClientHello analysis. ║
// ║  Injects low-level cryptographic entropy and identity signals as        ║
// ║  upstream HTTP headers for the Node.js heuristic engine.                 ║
// ║                                                                         ║
// ║  Architecture Flow:                                                     ║
// ║  [Client] ──TLS──▶ [Go Gateway :8443] ──HTTP──▶ [Node.js :3000]         ║
// ║                       │                                                 ║
// ║                       ├─ Shannon Entropy Analysis (Randomness)          ║
// ║                       ├─ JA3 & JA4 Fingerprinting                       ║
// ║                       ├─ ALPN/H2 Feature Extraction                     ║
// ║                       └─ Real IP Propagation (X-Forwarded-For)          ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

func main() {
	// ── CLI flags ───────────────────────────────────────────────────────
	listenAddr := flag.String("listen", ":8443", "TLS listen address")
	backendAddr := flag.String("backend", "http://127.0.0.1:3000", "Node.js backend URL")
	certFile := flag.String("cert", "", "TLS certificate file (auto-generated if empty)")
	keyFile := flag.String("key", "", "TLS private key file (auto-generated if empty)")
	autoCert := flag.Bool("auto-cert", true, "Auto-generate self-signed cert for development")


	logLevel := flag.String("log-level", "info", "Log level: debug, info, warn, error, fatal")
	flag.Parse()

	logger := setupLogger(*logLevel)

	// ── Banner ──────────────────────────────────────────────────────────
	fmt.Println(`
  ╔══════════════════════════════════════════════╗
  ║  🛡️  ShieldWall TLS Fingerprint Gateway     ║
  ║     Deep ClientHello Analysis + JA3/JA4     ║
  ╚══════════════════════════════════════════════╝`)


	// ── Parse backend URL ───────────────────────────────────────────────
	backendURL, err := url.Parse(*backendAddr)
	if err != nil {
		logger.Fatal("Invalid backend URL %q: %v", *backendAddr, err)
	}

	// ── Load or generate TLS certificate ────────────────────────────────
	var tlsCert tls.Certificate

	if *certFile != "" && *keyFile != "" {
		tlsCert, err = tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			logger.Fatal("Failed to load TLS certificate: %v", err)
		}
		logger.Infof("📜 Loaded TLS certificate from %s", *certFile)
	} else if *autoCert {
		// In development, auto-generate self-signed certificate
		tlsCert, err = generateSelfSignedCert(logger)
		if err != nil {
			logger.Fatal("Failed to generate self-signed cert: %v", err)
		}
		logger.Info("📜 Generated self-signed certificate for development")
	} else {
		logger.Fatal("No TLS certificate specified. Use -cert/-key or -auto-cert")
	}

	// ── Initialize fingerprint store ────────────────────────────────────
	fpStore := NewFingerprintStore()

	// ── TLS configuration ───────────────────────────────────────────────
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
		// Prefer TLS 1.3 cipher suites if available
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		PreferServerCipherSuites: true,
		CurvePreferences:         []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
	}

	// ── Start TCP listener ──────────────────────────────────────────────
	tcpListener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		logger.Fatal("Failed to listen on %s: %v", *listenAddr, err)
	}

	// ── Create intercepting listener + reverse proxy ────────────────────
	interceptor := NewTLSInterceptor(tcpListener, tlsConfig, fpStore, logger)
	proxy := CreateReverseProxy(backendURL, fpStore, logger)

	server := &http.Server{
		Handler:           proxy,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.New(logger.out, "HTTP_SERVER_ERROR: ", log.LstdFlags|log.Lmicroseconds),
	}

	// ── Graceful shutdown ───────────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Warnf("Received %v, shutting down...", sig)
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Errorf("Server shutdown error: %v", err)
		}
	}()

	// ── Print startup info ──────────────────────────────────────────────
	logger.Infof("🔒 Listening on https://localhost%s", *listenAddr)
	logger.Infof("🔗 Proxying to backend: %s", *backendAddr)
	logger.Infof("📊 Log level: %s", *logLevel)
	fmt.Println()
	logger.Info("Headers injected into every proxied request:")
	fmt.Println("   ├─ X-JA3-Fingerprint    (raw JA3 string)")
	fmt.Println("   ├─ X-JA3-Hash           (MD5 digest)")
	fmt.Println("   ├─ X-JA4-Fingerprint    (JA4-style hash)")
	fmt.Println("   ├─ X-ALPN               (negotiated protocol)")
	fmt.Println("   ├─ X-TLS-Version        (highest TLS version)")
	fmt.Println("   ├─ X-TLS-Random-Entropy (Shannon entropy 0-8)")
	fmt.Println("   ├─ X-TLS-Has-GREASE     (GREASE value presence)")
	fmt.Println("   ├─ X-TLS-Cipher-Count   (offered cipher count)")
	fmt.Println("   ├─ X-TLS-Extension-Count")
	fmt.Println("   ├─ X-TLS-SNI            (Server Name Indication)")
	fmt.Println("   └─ X-Forwarded-For      (real client IP)")
	fmt.Println()

	// ── Serve ───────────────────────────────────────────────────────────
	logger.Infof("🚀 Gateway started, press Ctrl+C to stop...")
	if err := server.Serve(interceptor); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Fatal("Server error: %v", err)
	}

	logger.Info("Gateway stopped")


	// ── Banner ──────────────────────────────────────────────────────────
	fmt.Println(`
  ╔══════════════════════════════════════════════╗
  ║  🛡️  ShieldWall TLS Fingerprint Gateway     ║
  ║     Deep ClientHello Analysis + JA3/JA4     ║
  ╚══════════════════════════════════════════════╝`)

	// ── Parse backend URL ───────────────────────────────────────────────
	backendURL, err := url.Parse(*backendAddr)
	if err != nil {
		logger.Fatalf("Invalid backend URL %q: %v", *backendAddr, err)
	}

	// ── Load or generate TLS certificate ────────────────────────────────
	var tlsCert tls.Certificate

	if *certFile != "" && *keyFile != "" {
		tlsCert, err = tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			logger.Fatalf("Failed to load TLS certificate: %v", err)
		}
		logger.Printf("📜 Loaded TLS certificate from %s", *certFile)
	} else if *autoCert {
		tlsCert, err = generateSelfSignedCert(logger)
		if err != nil {
			logger.Fatalf("Failed to generate self-signed cert: %v", err)
		}
		logger.Println("📜 Generated self-signed certificate for development")
	} else {
		logger.Fatal("No TLS certificate specified. Use -cert/-key or -auto-cert")
	}

	// ── Initialize fingerprint store ────────────────────────────────────
	fpStore := NewFingerprintStore()

	// ── TLS configuration ───────────────────────────────────────────────
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	// ── Start TCP listener ──────────────────────────────────────────────
	tcpListener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		logger.Fatalf("Failed to listen on %s: %v", *listenAddr, err)
	}

	// ── Create intercepting listener + reverse proxy ────────────────────
	interceptor := NewTLSInterceptor(tcpListener, tlsConfig, fpStore, logger)
	proxy := CreateReverseProxy(backendURL, fpStore, logger)

	server := &http.Server{
		Handler:           proxy,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// ── Graceful shutdown ───────────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Printf("Received %v, shutting down...", sig)
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
	}()

	// ── Print startup info ──────────────────────────────────────────────
	logger.Printf("🔒 Listening on https://localhost%s", *listenAddr)
	logger.Printf("🔗 Proxying to backend: %s", *backendAddr)
	logger.Printf("📊 Log level: %s", *logLevel)
	fmt.Println()
	logger.Println("Headers injected into every proxied request:")
	fmt.Println("   ├─ X-JA3-Fingerprint    (raw JA3 string)")
	fmt.Println("   ├─ X-JA3-Hash           (MD5 digest)")
	fmt.Println("   ├─ X-JA4-Fingerprint    (JA4-style hash)")
	fmt.Println("   ├─ X-ALPN               (negotiated protocol)")
	fmt.Println("   ├─ X-TLS-Version        (highest TLS version)")
	fmt.Println("   ├─ X-TLS-Random-Entropy (Shannon entropy 0-8)")
	fmt.Println("   ├─ X-TLS-Has-GREASE     (GREASE value presence)")
	fmt.Println("   ├─ X-TLS-Cipher-Count   (offered cipher count)")
	fmt.Println("   ├─ X-TLS-Extension-Count")
	fmt.Println("   ├─ X-TLS-SNI            (Server Name Indication)")
	fmt.Println("   └─ X-Forwarded-For      (real client IP)")
	fmt.Println()



	// ── Serve ───────────────────────────────────────────────────────────
	if err := server.Serve(interceptor); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("Server error: %v", err)
	}

	logger.Println("Gateway stopped")

	// ── Banner ──────────────────────────────────────────────────────────
	fmt.Println(`
  ╔══════════════════════════════════════════════╗
  ║  🛡️  ShieldWall TLS Fingerprint Gateway     ║
  ║     Deep ClientHello Analysis + JA3/JA4     ║
  ╚══════════════════════════════════════════════╝`)

	// ── Parse backend URL ───────────────────────────────────────────────
	backendURL, err := url.Parse(*backendAddr)
	if err != nil {
		logger.Fatalf("Invalid backend URL %q: %v", *backendAddr, err)
	}

	// ── Load or generate TLS certificate ────────────────────────────────
	var tlsCert tls.Certificate

	if *certFile != "" && *keyFile != "" {
		tlsCert, err = tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			logger.Fatalf("Failed to load TLS certificate: %v", err)
		}
		logger.Printf("📜 Loaded TLS certificate from %s", *certFile)
	} else if *autoCert {
		tlsCert, err = generateSelfSignedCert(logger)
		if err != nil {
			logger.Fatalf("Failed to generate self-signed cert: %v", err)
		}
		logger.Println("📜 Generated self-signed certificate for development")
	} else {
		logger.Fatal("No TLS certificate specified. Use -cert/-key or -auto-cert")
	}

	// ── Initialize fingerprint store ────────────────────────────────────
	fpStore := NewFingerprintStore()

	// ── TLS configuration ───────────────────────────────────────────────
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	// ── Start TCP listener ──────────────────────────────────────────────
	tcpListener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		logger.Fatalf("Failed to listen on %s: %v", *listenAddr, err)
	}

	// ── Create intercepting listener + reverse proxy ────────────────────
	interceptor := NewTLSInterceptor(tcpListener, tlsConfig, fpStore, logger)
	proxy := CreateReverseProxy(backendURL, fpStore, logger)

	server := &http.Server{
		Handler:           proxy,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// ── Graceful shutdown ───────────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Printf("Received %v, shutting down...", sig)
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
	}()

	// ── Print startup info ──────────────────────────────────────────────
	logger.Printf("🔒 Listening on https://localhost%s", *listenAddr)
	logger.Printf("🔗 Proxying to backend: %s", *backendAddr)
	logger.Printf("📊 Log level: %s", *logLevel)
	fmt.Println()
	logger.Println("Headers injected into every proxied request:")
	fmt.Println("   ├─ X-JA3-Fingerprint    (raw JA3 string)")
	fmt.Println("   ├─ X-JA3-Hash           (MD5 digest)")
	fmt.Println("   ├─ X-JA4-Fingerprint    (JA4-style hash)")
	fmt.Println("   ├─ X-ALPN               (negotiated protocol)")
	fmt.Println("   ├─ X-TLS-Version        (highest TLS version)")
	fmt.Println("   ├─ X-TLS-Random-Entropy (Shannon entropy 0-8)")
	fmt.Println("   ├─ X-TLS-Has-GREASE     (GREASE value presence)")
	fmt.Println("   ├─ X-TLS-Cipher-Count   (offered cipher count)")
	fmt.Println("   ├─ X-TLS-Extension-Count")
	fmt.Println("   ├─ X-TLS-SNI            (Server Name Indication)")
	fmt.Println("   └─ X-Forwarded-For      (real client IP)")
	fmt.Println()

	_ = ctx // used by shutdown goroutine

	// ── Serve ───────────────────────────────────────────────────────────
	if err := server.Serve(interceptor); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("Server error: %v", err)
	}

	logger.Println("Gateway stopped")
}

// ── Self-signed certificate generator ───────────────────────────────────────

func generateSelfSignedCert(logger *log.Logger) (tls.Certificate, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ShieldWall Gateway (dev)"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "*.localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}

	privKeyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyDER})

	// Optionally save to disk
	certsDir := filepath.Join("gateway", "certs")
	os.MkdirAll(certsDir, 0755)
	os.WriteFile(filepath.Join(certsDir, "dev.crt"), certPEM, 0644)
	os.WriteFile(filepath.Join(certsDir, "dev.key"), keyPEM, 0600)
	logger.Printf("📁 Dev certificates saved to %s/", certsDir)

	return tls.X509KeyPair(certPEM, keyPEM)
}
