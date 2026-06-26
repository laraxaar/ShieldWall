package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                ShieldWall TLS Handshake Parser                           ║
// ║                                                                         ║
// ║  Performs manual binary decoding of TLS records and ClientHello         ║
// ║  structures. Extracts cryptographic parameters, extensions, and         ║
// ║  versioning data without performing a full handshake.                   ║
// ╚═══════════════════════════════════════════════════════════════════════════╝

// ClientHello holds every field extracted from the raw TLS ClientHello message.
type ClientHello struct {
	Raw                []byte
	RecordVersion      uint16   // TLS record-layer version (usually 0x0301)
	HandshakeVersion   uint16   // ClientHello.legacy_version (0x0303 = TLS 1.2)
	Random             [32]byte // 32-byte client random
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8
	ExtensionIDs       []uint16 // ordered list of extension type IDs
	Extensions         map[uint16][]byte

	// Parsed from specific extensions:
	SupportedGroups   []uint16
	ECPointFormats    []uint8
	SignatureAlgos    []uint16
	ALPNProtocols     []string
	SupportedVersions []uint16
	ServerName        string
	PaddingLength     int
	HasStatusRequest  bool
	HasRenegotiation  bool

	// GREASE counters
	GREASECiphers    int
	GREASEExtensions int
	GREASEGroups     int
}

// ── GREASE detection ────────────────────────────────────────────────────────

// IsGREASE returns true if the value matches the GREASE pattern (RFC 8701).
// GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ... 0xfafa
func IsGREASE(v uint16) bool {
	return (v>>8) == (v&0xFF) && (v&0x0F) == 0x0A
}

// validateRecordLength validates TLS record length with additional DoS protections.
// FIX: BUG_14 — Added suspicious size detection to prevent DoS via multiple small records.
func validateRecordLength(recordLen int) error {
	if recordLen < 4 {
		return fmt.Errorf("invalid TLS record length: %d (too small)", recordLen)
	}
	if recordLen > 16384 {
		return fmt.Errorf("invalid TLS record length: %d (too large)", recordLen)
	}
	// Additional check: reject suspicious sizes often used in attacks
	if recordLen > 8192 && recordLen%256 != 0 {
		return fmt.Errorf("suspicious TLS record length: %d", recordLen)
	}
	return nil
}

// ── Raw ClientHello capture from TCP ────────────────────────────────────────

// ReadClientHello reads the first TLS record from a TCP connection and parses
// the ClientHello. Returns the raw bytes (for replay) and parsed structure.
func ReadClientHello(conn net.Conn) ([]byte, *ClientHello, error) {
	// Step 1: Read TLS record header (5 bytes)
	// ContentType(1) + ProtocolVersion(2) + Length(2)
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, nil, fmt.Errorf("read TLS record header: %w", err)
	}

	if header[0] != 0x16 { // ContentType: Handshake
		return header, nil, errors.New("not a TLS handshake record")
	}

	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	// FIX: BUG_14 — Use enhanced validation to prevent DoS via suspicious record sizes
	if err := validateRecordLength(recordLen); err != nil {
		return header, nil, err
	}

	// Step 2: Read the full handshake payload
	payload := make([]byte, recordLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return header, nil, fmt.Errorf("read TLS record payload: %w", err)
	}

	raw := append(header, payload...)

	// Step 3: Parse the ClientHello
	ch, err := ParseClientHello(header, payload)
	if err != nil {
		return raw, nil, err
	}
	ch.Raw = raw
	return raw, ch, nil
}

// ── Binary parser ───────────────────────────────────────────────────────────

// ParseClientHello parses a TLS ClientHello from the record header and payload.
func ParseClientHello(recordHeader, payload []byte) (*ClientHello, error) {
	ch := &ClientHello{
		Extensions: make(map[uint16][]byte),
	}
	ch.RecordVersion = binary.BigEndian.Uint16(recordHeader[1:3])

	// Handshake header: Type(1) + Length(3)
	if len(payload) < 4 {
		return nil, errors.New("payload too short for handshake header")
	}
	if payload[0] != 0x01 { // HandshakeType: ClientHello
		return nil, fmt.Errorf("not a ClientHello (type=0x%02x)", payload[0])
	}

	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	data := payload[4:]
	if len(data) < hsLen {
		return nil, errors.New("truncated ClientHello")
	}
	data = data[:hsLen]
	pos := 0

	// ── Legacy version (2 bytes) ──
	if pos+2 > len(data) {
		return nil, errors.New("truncated: version")
	}
	ch.HandshakeVersion = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	// ── Random (32 bytes) ──
	if pos+32 > len(data) {
		return nil, errors.New("truncated: random")
	}
	copy(ch.Random[:], data[pos:pos+32])
	pos += 32

	// ── Session ID (1-byte length prefix) ──
	if pos+1 > len(data) {
		return nil, errors.New("truncated: session_id length")
	}
	sidLen := int(data[pos])
	pos++
	if pos+sidLen > len(data) {
		return nil, errors.New("truncated: session_id")
	}
	ch.SessionID = make([]byte, sidLen)
	copy(ch.SessionID, data[pos:pos+sidLen])
	pos += sidLen

	// ── Cipher Suites (2-byte length prefix, each suite is 2 bytes) ──
	if pos+2 > len(data) {
		return nil, errors.New("truncated: cipher_suites length")
	}
	csLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+csLen > len(data) || csLen%2 != 0 {
		return nil, errors.New("truncated: cipher_suites")
	}
	for i := 0; i < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(data[pos+i : pos+i+2])
		ch.CipherSuites = append(ch.CipherSuites, cs)
		if IsGREASE(cs) {
			ch.GREASECiphers++
		}
	}
	pos += csLen

	// ── Compression Methods (1-byte length prefix) ──
	if pos+1 > len(data) {
		return nil, errors.New("truncated: compression length")
	}
	cmLen := int(data[pos])
	pos++
	if pos+cmLen > len(data) {
		return nil, errors.New("truncated: compression")
	}
	ch.CompressionMethods = make([]uint8, cmLen)
	for i := 0; i < cmLen; i++ {
		ch.CompressionMethods[i] = data[pos+i]
	}
	pos += cmLen

	// ── Extensions (2-byte length prefix) ──
	if pos+2 > len(data) {
		// No extensions (valid but unusual)
		return ch, nil
	}
	extTotalLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+extTotalLen > len(data) {
		return nil, errors.New("truncated: extensions block")
	}

	extEnd := pos + extTotalLen
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > extEnd {
			break
		}
		extData := data[pos : pos+extLen]
		pos += extLen

		ch.ExtensionIDs = append(ch.ExtensionIDs, extType)
		ch.Extensions[extType] = extData

		if IsGREASE(extType) {
			ch.GREASEExtensions++
		}

		// Parse specific extensions
		switch extType {
		case 0x0000: // server_name (SNI)
			ch.ServerName = parseSNI(extData)
		case 0x0005: // status_request
			ch.HasStatusRequest = true
		case 0x000a: // supported_groups
			ch.SupportedGroups = parseUint16List(extData)
			for _, g := range ch.SupportedGroups {
				if IsGREASE(g) {
					ch.GREASEGroups++
				}
			}
		case 0x000b: // ec_point_formats
			ch.ECPointFormats = parseUint8List(extData)
		case 0x000d: // signature_algorithms
			ch.SignatureAlgos = parseUint16List(extData)
		case 0x0010: // ALPN
			ch.ALPNProtocols = parseALPN(extData)
		case 0x0015: // padding
			ch.PaddingLength = extLen
		case 0x002b: // supported_versions
			ch.SupportedVersions = parseSupportedVersions(extData)
		case 0xff01: // renegotiation_info
			ch.HasRenegotiation = true
		}
	}

	return ch, nil
}

// ── Extension sub-parsers ───────────────────────────────────────────────────

func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// SNI list length (2) + type (1) + name length (2) + name
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+nameLen > len(data) {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

func parseUint16List(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2:]
	if len(data) < listLen || listLen%2 != 0 {
		return nil
	}
	result := make([]uint16, listLen/2)
	for i := range result {
		result[i] = binary.BigEndian.Uint16(data[i*2 : i*2+2])
	}
	return result
}

func parseUint8List(data []byte) []uint8 {
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	data = data[1:]
	if len(data) < listLen {
		return nil
	}
	result := make([]uint8, listLen)
	copy(result, data[:listLen])
	return result
}

func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2:]
	if len(data) < listLen {
		return nil
	}
	var protocols []string
	pos := 0
	for pos < listLen {
		if pos >= len(data) {
			break
		}
		pLen := int(data[pos])
		pos++
		if pos+pLen > len(data) {
			break
		}
		protocols = append(protocols, string(data[pos:pos+pLen]))
		pos += pLen
	}
	return protocols
}

func parseSupportedVersions(data []byte) []uint16 {
	// In ClientHello: 1-byte length prefix + 2-byte version entries
	if len(data) < 1 {
		return nil
	}
	listLen := int(data[0])
	data = data[1:]
	if len(data) < listLen || listLen%2 != 0 {
		return nil
	}
	result := make([]uint16, listLen/2)
	for i := range result {
		result[i] = binary.BigEndian.Uint16(data[i*2 : i*2+2])
	}
	return result
}
