package main

import (
	"fmt"
	"strings"
	"testing"
)

// ── ClientHello parser tests ────────────────────────────────────────────────

// Craft a minimal valid ClientHello for testing
func buildTestClientHello() []byte {
	// TLS Record Header
	record := []byte{
		0x16,       // ContentType: Handshake
		0x03, 0x01, // ProtocolVersion: TLS 1.0 (record layer)
	}

	// Build the ClientHello handshake message
	hello := []byte{}

	// Legacy version: TLS 1.2 (0x0303)
	hello = append(hello, 0x03, 0x03)

	// Client Random (32 bytes of varied data for entropy testing)
	random := []byte{
		0x4a, 0x9c, 0x2b, 0x71, 0xf3, 0x08, 0xd5, 0xe7,
		0xa2, 0x56, 0xc1, 0x84, 0x6f, 0xbb, 0x3d, 0x19,
		0x82, 0xe4, 0x00, 0xcd, 0x5e, 0x97, 0xaf, 0x63,
		0xd8, 0x14, 0x7b, 0xf0, 0x25, 0x48, 0x9a, 0xdc,
	}
	hello = append(hello, random...)

	// Session ID (empty)
	hello = append(hello, 0x00)

	// Cipher Suites: GREASE(0x0a0a) + TLS_AES_128_GCM_SHA256(0x1301) + TLS_AES_256_GCM_SHA384(0x1302)
	ciphers := []byte{
		0x00, 0x06, // Length: 6 bytes (3 ciphers)
		0x0a, 0x0a, // GREASE
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x13, 0x02, // TLS_AES_256_GCM_SHA384
	}
	hello = append(hello, ciphers...)

	// Compression Methods: null only
	hello = append(hello, 0x01, 0x00)

	// Extensions
	extensions := []byte{}

	// SNI extension (0x0000)
	sni := buildSNIExtension("example.com")
	extensions = append(extensions, sni...)

	// Supported versions extension (0x002b): TLS 1.3 + TLS 1.2
	sv := buildSupportedVersionsExtension([]uint16{0x0304, 0x0303})
	extensions = append(extensions, sv...)

	// ALPN extension (0x0010): h2, http/1.1
	alpn := buildALPNExtension([]string{"h2", "http/1.1"})
	extensions = append(extensions, alpn...)

	// Supported Groups extension (0x000a): x25519(0x001d), secp256r1(0x0017)
	sg := buildUint16ListExtension(0x000a, []uint16{0x001d, 0x0017})
	extensions = append(extensions, sg...)

	// EC Point Formats extension (0x000b): uncompressed(0)
	ecpf := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}
	extensions = append(extensions, ecpf...)

	// Status Request (0x0005)
	statusReq := []byte{0x00, 0x05, 0x00, 0x00}
	extensions = append(extensions, statusReq...)

	// Extensions length prefix (2 bytes)
	extLen := len(extensions)
	hello = append(hello, byte(extLen>>8), byte(extLen))
	hello = append(hello, extensions...)

	// Handshake header: type(1) + length(3)
	hsLen := len(hello)
	handshake := []byte{0x01, byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)}
	handshake = append(handshake, hello...)

	// TLS record length
	recordLen := len(handshake)
	record = append(record, byte(recordLen>>8), byte(recordLen))
	record = append(record, handshake...)

	return record
}

func buildSNIExtension(hostname string) []byte {
	nameBytes := []byte(hostname)
	nameLen := len(nameBytes)
	// Extension header: type(2) + length(2) + SNI list length(2) + entry type(1) + name length(2) + name
	totalLen := 2 + 1 + 2 + nameLen
	ext := []byte{
		0x00, 0x00, // Extension type: SNI
		byte((totalLen + 2) >> 8), byte((totalLen + 2)), // Extension data length
		byte(totalLen >> 8), byte(totalLen), // SNI list length
		0x00,                                  // Type: hostname
		byte(nameLen >> 8), byte(nameLen),     // Name length
	}
	ext = append(ext, nameBytes...)
	return ext
}

func buildSupportedVersionsExtension(versions []uint16) []byte {
	listLen := len(versions) * 2
	ext := []byte{
		0x00, 0x2b, // Extension type: supported_versions
		byte((listLen + 1) >> 8), byte(listLen + 1), // Extension data length
		byte(listLen), // List length
	}
	for _, v := range versions {
		ext = append(ext, byte(v>>8), byte(v))
	}
	return ext
}

func buildALPNExtension(protocols []string) []byte {
	var alpnList []byte
	for _, p := range protocols {
		alpnList = append(alpnList, byte(len(p)))
		alpnList = append(alpnList, []byte(p)...)
	}
	listLen := len(alpnList)
	ext := []byte{
		0x00, 0x10, // Extension type: ALPN
		byte((listLen + 2) >> 8), byte(listLen + 2), // Extension data length
		byte(listLen >> 8), byte(listLen), // ALPN list length
	}
	ext = append(ext, alpnList...)
	return ext
}

func buildUint16ListExtension(extType uint16, values []uint16) []byte {
	listLen := len(values) * 2
	ext := []byte{
		byte(extType >> 8), byte(extType), // Extension type
		byte((listLen + 2) >> 8), byte(listLen + 2), // Extension data length
		byte(listLen >> 8), byte(listLen), // List length
	}
	for _, v := range values {
		ext = append(ext, byte(v>>8), byte(v))
	}
	return ext
}

// ── Tests ───────────────────────────────────────────────────────────────────

func TestParseClientHello(t *testing.T) {
	raw := buildTestClientHello()

	header := raw[:5]
	payload := raw[5:]
	ch, err := ParseClientHello(header, payload)
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}

	// Verify version
	if ch.HandshakeVersion != 0x0303 {
		t.Errorf("HandshakeVersion = 0x%04x, want 0x0303", ch.HandshakeVersion)
	}

	// Verify cipher suites (3 including GREASE)
	if len(ch.CipherSuites) != 3 {
		t.Errorf("CipherSuites count = %d, want 3", len(ch.CipherSuites))
	}
	if ch.GREASECiphers != 1 {
		t.Errorf("GREASECiphers = %d, want 1", ch.GREASECiphers)
	}

	// Verify SNI
	if ch.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want %q", ch.ServerName, "example.com")
	}

	// Verify ALPN
	if len(ch.ALPNProtocols) != 2 || ch.ALPNProtocols[0] != "h2" {
		t.Errorf("ALPNProtocols = %v, want [h2, http/1.1]", ch.ALPNProtocols)
	}

	// Verify supported versions
	if len(ch.SupportedVersions) != 2 || ch.SupportedVersions[0] != 0x0304 {
		t.Errorf("SupportedVersions = %v, want [0x0304, 0x0303]", ch.SupportedVersions)
	}

	// Verify supported groups
	if len(ch.SupportedGroups) != 2 {
		t.Errorf("SupportedGroups count = %d, want 2", len(ch.SupportedGroups))
	}

	// Verify status request
	if !ch.HasStatusRequest {
		t.Error("HasStatusRequest = false, want true")
	}
}

func TestGREASEDetection(t *testing.T) {
	greaseValues := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}
	for _, v := range greaseValues {
		if !IsGREASE(v) {
			t.Errorf("IsGREASE(0x%04x) = false, want true", v)
		}
	}

	nonGrease := []uint16{0x0301, 0x1301, 0x0a0b, 0x1234, 0xc02b}
	for _, v := range nonGrease {
		if IsGREASE(v) {
			t.Errorf("IsGREASE(0x%04x) = true, want false", v)
		}
	}
}

func TestComputeJA3(t *testing.T) {
	raw := buildTestClientHello()
	ch, err := ParseClientHello(raw[:5], raw[5:])
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	ja3str, ja3hash := ComputeJA3(ch)

	// JA3 string should NOT contain GREASE values
	if strings.Contains(ja3str, "2570") { // 0x0a0a = 2570 decimal
		t.Error("JA3 string contains GREASE value 2570")
	}

	// Should start with version 771 (0x0303)
	if !strings.HasPrefix(ja3str, "771,") {
		t.Errorf("JA3 string starts with %q, expected '771,'", ja3str[:4])
	}

	// Hash should be 32 hex chars
	if len(ja3hash) != 32 {
		t.Errorf("JA3 hash length = %d, want 32", len(ja3hash))
	}

	t.Logf("JA3 String: %s", ja3str)
	t.Logf("JA3 Hash:   %s", ja3hash)
}

func TestComputeJA4(t *testing.T) {
	raw := buildTestClientHello()
	ch, err := ParseClientHello(raw[:5], raw[5:])
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	ja4 := ComputeJA4(ch)

	// JA4 should have 3 sections separated by underscores
	parts := strings.Split(ja4, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 has %d sections, want 3: %s", len(parts), ja4)
	}

	// Section A should start with "t13d" (TCP, TLS 1.3, domain SNI)
	if !strings.HasPrefix(parts[0], "t13d") {
		t.Errorf("JA4 section A = %q, expected prefix 't13d'", parts[0])
	}

	// Section A should end with "h2" (ALPN)
	if !strings.HasSuffix(parts[0], "h2") {
		t.Errorf("JA4 section A = %q, expected suffix 'h2'", parts[0])
	}

	// Sections B and C should be 12 hex chars each
	if len(parts[1]) != 12 {
		t.Errorf("JA4 section B length = %d, want 12", len(parts[1]))
	}
	if len(parts[2]) != 12 {
		t.Errorf("JA4 section C length = %d, want 12", len(parts[2]))
	}

	t.Logf("JA4: %s", ja4)
}

func TestShannonEntropy(t *testing.T) {
	// All zeros — entropy should be 0
	allZeros := make([]byte, 32)
	e0 := ShannonEntropy(allZeros)
	if e0 != 0 {
		t.Errorf("Entropy of all zeros = %f, want 0", e0)
	}

	// All different values (0-31) — high entropy
	varied := make([]byte, 32)
	for i := range varied {
		varied[i] = byte(i)
	}
	eVaried := ShannonEntropy(varied)
	if eVaried < 4.0 {
		t.Errorf("Entropy of varied data = %f, expected > 4.0", eVaried)
	}

	// Repeated pattern (bot-like) — lower entropy
	repeated := make([]byte, 32)
	for i := range repeated {
		repeated[i] = byte(i % 4) // only 4 unique values
	}
	eRepeated := ShannonEntropy(repeated)
	if eRepeated >= eVaried {
		t.Errorf("Repeated pattern entropy (%f) >= varied data entropy (%f)", eRepeated, eVaried)
	}

	t.Logf("Entropy: zeros=%.3f varied=%.3f repeated=%.3f", e0, eVaried, eRepeated)
}

func TestComputeFingerprint(t *testing.T) {
	raw := buildTestClientHello()
	ch, err := ParseClientHello(raw[:5], raw[5:])
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	fp := ComputeFingerprint(ch)

	if fp.JA3Hash == "" {
		t.Error("JA3Hash is empty")
	}
	if fp.JA4 == "" {
		t.Error("JA4 is empty")
	}
	if fp.TLSVersion != "13" {
		t.Errorf("TLSVersion = %q, want '13'", fp.TLSVersion)
	}
	if fp.CipherCount != 2 { // 3 total - 1 GREASE = 2
		t.Errorf("CipherCount = %d, want 2", fp.CipherCount)
	}
	if !fp.HasGREASE {
		t.Error("HasGREASE = false, want true")
	}
	if fp.ALPN != "h2" {
		t.Errorf("ALPN = %q, want 'h2'", fp.ALPN)
	}
	if fp.RandomEntropy < 3.0 {
		t.Errorf("RandomEntropy = %f, expected > 3.0 for varied random", fp.RandomEntropy)
	}

	t.Logf("Full fingerprint: JA3=%s JA4=%s TLS=%s ALPN=%s entropy=%.3f GREASE=%v",
		fp.JA3Hash, fp.JA4, fp.TLSVersion, fp.ALPN, fp.RandomEntropy, fp.HasGREASE)
}

func TestVersionResolving(t *testing.T) {
	tests := []struct {
		name    string
		hello   uint16
		supVers []uint16
		want    string
	}{
		{"TLS 1.3 via supported_versions", 0x0303, []uint16{0x0304, 0x0303}, "13"},
		{"TLS 1.2 legacy only", 0x0303, nil, "12"},
		{"TLS 1.3 with GREASE", 0x0303, []uint16{0x3a3a, 0x0304}, "13"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := &ClientHello{
				HandshakeVersion:  tt.hello,
				SupportedVersions: tt.supVers,
			}
			got := resolveVersion(ch)
			if got != tt.want {
				t.Errorf("resolveVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFilterGREASE(t *testing.T) {
	input := []uint16{0x0a0a, 0x1301, 0x2a2a, 0x1302, 0xfafa}
	filtered := filterGREASE16(input)
	if len(filtered) != 2 {
		t.Fatalf("filterGREASE16 returned %d items, want 2", len(filtered))
	}
	if filtered[0] != 0x1301 || filtered[1] != 0x1302 {
		t.Errorf("Filtered = %v, want [0x1301, 0x1302]", filtered)
	}
}

// ── Benchmark ───────────────────────────────────────────────────────────────

func BenchmarkParseClientHello(b *testing.B) {
	raw := buildTestClientHello()
	header := raw[:5]
	payload := raw[5:]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseClientHello(header, payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkComputeFingerprint(b *testing.B) {
	raw := buildTestClientHello()
	ch, _ := ParseClientHello(raw[:5], raw[5:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeFingerprint(ch)
	}
}

func BenchmarkShannonEntropy(b *testing.B) {
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i * 7)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ShannonEntropy(data)
	}
}

// Satisfy the import
var _ = fmt.Sprintf
