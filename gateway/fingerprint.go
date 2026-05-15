package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)
// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                ShieldWall Identity Synthesis Engine                      ║
// ║                                                                         ║
// ║  Computes unique identity fingerprints (JA3, JA4) and measures          ║
// ║  cryptographic randomness (Shannon Entropy). These signals allow        ║
// ║  ShieldWall to detect botnets and automated scrapers based on           ║
// ║  their unique TLS stack signatures.                                     ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
// ── Fingerprint results ─────────────────────────────────────────────────────

// Fingerprint holds all computed fingerprint data for a single connection.
type Fingerprint struct {
	// JA3
	JA3String string // raw JA3 string (Version,Ciphers,Extensions,Groups,Formats)
	JA3Hash   string // MD5 hex digest of JA3String

	// JA4 (FoxIO-inspired)
	JA4 string // t13d1207h2_<cipher_hash>_<ext_hash>

	// Enrichment data
	TLSVersion        string // "1.2", "1.3", etc.
	CipherCount       int
	ExtensionCount    int
	ALPN              string // first negotiated ALPN protocol
	HasGREASE         bool
	GREASECount       int
	SupportedVersions string // comma-separated list
	ServerName        string
	RandomEntropy     float64 // Shannon entropy of Client Random (0.0–8.0)
	SessionIDLength   int
	PaddingLength     int
	HasStatusRequest  bool
	HasRenegotiation  bool
	CompressionCount  int
}

// ── JA3 computation ─────────────────────────────────────────────────────────

// ComputeJA3 builds the JA3 string and hash from a parsed ClientHello.
// JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
// All values are decimal. GREASE values are stripped.
func ComputeJA3(ch *ClientHello) (ja3str, ja3hash string) {
	version := strconv.FormatUint(uint64(ch.HandshakeVersion), 10)

	ciphers := filterGREASE16(ch.CipherSuites)
	extensions := filterGREASE16(ch.ExtensionIDs)
	groups := filterGREASE16(ch.SupportedGroups)
	formats := uint8ToStrings(ch.ECPointFormats)

	ja3str = fmt.Sprintf("%s,%s,%s,%s,%s",
		version,
		strings.Join(uint16ToStrings(ciphers), "-"),
		strings.Join(uint16ToStrings(extensions), "-"),
		strings.Join(uint16ToStrings(groups), "-"),
		strings.Join(formats, "-"),
	)

	sum := md5.Sum([]byte(ja3str))
	ja3hash = hex.EncodeToString(sum[:])
	return
}

// ── JA4 computation ─────────────────────────────────────────────────────────

// ComputeJA4 builds a JA4-style fingerprint (inspired by FoxIO JA4 spec).
// Format: [proto][ver][sni][ciphers][exts][alpn]_[cipher_hash12]_[ext_hash12]
//
// Example: t13d1207h2_a0b1c2d3e4f5_f5e4d3c2b1a0
func ComputeJA4(ch *ClientHello) string {
	// Protocol: always "t" for TCP (we don't handle QUIC)
	proto := "t"

	// TLS version: use highest supported version (from supported_versions ext)
	ver := resolveVersion(ch)

	// SNI: "d" if domain present, "i" if IP or empty
	sni := "i"
	if ch.ServerName != "" && !isIPAddress(ch.ServerName) {
		sni = "d"
	}

	// Cipher and extension counts (no GREASE), 2-digit zero-padded
	ciphers := filterGREASE16(ch.CipherSuites)
	extensions := filterGREASE16(ch.ExtensionIDs)
	cc := fmt.Sprintf("%02d", clamp(len(ciphers), 99))
	ec := fmt.Sprintf("%02d", clamp(len(extensions), 99))

	// First ALPN protocol
	alpn := "00"
	if len(ch.ALPNProtocols) > 0 {
		first := ch.ALPNProtocols[0]
		if len(first) >= 2 {
			alpn = first[:2] // "h2", "h1", etc.
		}
	}

	// Section A
	sectionA := fmt.Sprintf("%s%s%s%s%s%s", proto, ver, sni, cc, ec, alpn)

	// Section B: SHA256 of sorted cipher suites (first 12 hex chars)
	sortedCiphers := make([]uint16, len(ciphers))
	copy(sortedCiphers, ciphers)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	cipherStr := strings.Join(uint16ToHexStrings(sortedCiphers), ",")
	sectionB := sha256First12(cipherStr)

	// Section C: SHA256 of sorted extensions + sorted signature algos (first 12 hex chars)
	sortedExts := make([]uint16, len(extensions))
	copy(sortedExts, extensions)
	sort.Slice(sortedExts, func(i, j int) bool { return sortedExts[i] < sortedExts[j] })

	sigAlgos := filterGREASE16(ch.SignatureAlgos)
	sortedSigAlgos := make([]uint16, len(sigAlgos))
	copy(sortedSigAlgos, sigAlgos)
	sort.Slice(sortedSigAlgos, func(i, j int) bool { return sortedSigAlgos[i] < sortedSigAlgos[j] })

	extStr := strings.Join(uint16ToHexStrings(sortedExts), ",")
	sigStr := strings.Join(uint16ToHexStrings(sortedSigAlgos), ",")
	sectionC := sha256First12(extStr + "_" + sigStr)

	return fmt.Sprintf("%s_%s_%s", sectionA, sectionB, sectionC)
}

// ── Full fingerprint computation ────────────────────────────────────────────

// ComputeFingerprint builds the complete Fingerprint from a parsed ClientHello.
func ComputeFingerprint(ch *ClientHello) *Fingerprint {
	ja3str, ja3hash := ComputeJA3(ch)
	ja4 := ComputeJA4(ch)

	fp := &Fingerprint{
		JA3String:        ja3str,
		JA3Hash:          ja3hash,
		JA4:              ja4,
		TLSVersion:       resolveVersion(ch),
		CipherCount:      len(filterGREASE16(ch.CipherSuites)),
		ExtensionCount:   len(filterGREASE16(ch.ExtensionIDs)),
		HasGREASE:        ch.GREASECiphers+ch.GREASEExtensions+ch.GREASEGroups > 0,
		GREASECount:      ch.GREASECiphers + ch.GREASEExtensions + ch.GREASEGroups,
		ServerName:       ch.ServerName,
		RandomEntropy:    ShannonEntropy(ch.Random[:]),
		SessionIDLength:  len(ch.SessionID),
		PaddingLength:    ch.PaddingLength,
		HasStatusRequest: ch.HasStatusRequest,
		HasRenegotiation: ch.HasRenegotiation,
		CompressionCount: len(ch.CompressionMethods),
	}

	// ALPN
	if len(ch.ALPNProtocols) > 0 {
		fp.ALPN = ch.ALPNProtocols[0]
	}

	// Supported versions as comma-separated
	if len(ch.SupportedVersions) > 0 {
		parts := make([]string, len(ch.SupportedVersions))
		for i, v := range ch.SupportedVersions {
			parts[i] = versionToString(v)
		}
		fp.SupportedVersions = strings.Join(parts, ",")
	}

	return fp
}

// ── Shannon Entropy ─────────────────────────────────────────────────────────

// ShannonEntropy computes the Shannon entropy (bits per byte) of the data.
// For truly random data this approaches 8.0. For predictable/repeated
// patterns (e.g. LCG-based generators in bots) this will be significantly lower.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	entropy := 0.0
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return math.Round(entropy*1000) / 1000
}

// ── Helper functions ────────────────────────────────────────────────────────

func filterGREASE16(vals []uint16) []uint16 {
	result := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if !IsGREASE(v) {
			result = append(result, v)
		}
	}
	return result
}

func uint16ToStrings(vals []uint16) []string {
	result := make([]string, len(vals))
	for i, v := range vals {
		result[i] = strconv.FormatUint(uint64(v), 10)
	}
	return result
}

func uint16ToHexStrings(vals []uint16) []string {
	result := make([]string, len(vals))
	for i, v := range vals {
		result[i] = fmt.Sprintf("%04x", v)
	}
	return result
}

func uint8ToStrings(vals []uint8) []string {
	result := make([]string, len(vals))
	for i, v := range vals {
		result[i] = strconv.FormatUint(uint64(v), 10)
	}
	return result
}

func sha256First12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func resolveVersion(ch *ClientHello) string {
	// Prefer supported_versions extension (TLS 1.3 uses this)
	if len(ch.SupportedVersions) > 0 {
		highest := uint16(0)
		for _, v := range ch.SupportedVersions {
			if !IsGREASE(v) && v > highest {
				highest = v
			}
		}
		if highest > 0 {
			return versionToString(highest)
		}
	}
	return versionToString(ch.HandshakeVersion)
}

func versionToString(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	default:
		return fmt.Sprintf("%04x", v)
	}
}

func isIPAddress(s string) bool {
	for _, c := range s {
		if c != '.' && c != ':' && !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func clamp(v, max int) int {
	if v > max {
		return max
	}
	return v
}
