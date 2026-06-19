// tls.go — TLS handshake record parser.
//
// This file is pure Go (no CGO dependency). It parses raw TLS record streams
// produced by the TCP assembler in capture.go and converts handshake messages
// into DiscoveredAssets.
//
// Parsed messages:
//
//   - ClientHello  (type  1) — extracts SNI hostname and offered cipher suites.
//     Each non-GREASE offered suite is emitted as a type="crypto_library" asset
//     with labels=["network_capture","cipher_suite","client_offered"] so analysts
//     can see which QV suites clients are willing to negotiate.
//
//   - ServerHello  (type  2) — extracts the chosen cipher suite and the
//     supported_versions extension (to detect TLS 1.3 sessions for cert parsing).
//     The chosen suite is emitted as a separate type="crypto_library" asset with
//     labels=["network_capture","cipher_suite"].
//
//   - Certificate  (type 11) — extracts the DER certificate chain.  Handles both
//     TLS 1.2 (no context, no per-cert extensions) and TLS 1.3 (1-byte
//     certificate_request_context + 2-byte per-cert extensions).
package sniffer

import (
        "bytes"
        "crypto/dsa"
        "crypto/ecdsa"
        "crypto/ed25519"
        "crypto/rsa"
        "crypto/sha256"
        "crypto/tls"
        "crypto/x509"
        "encoding/binary"
        "encoding/hex"
        "fmt"
        "math/big"
        "strings"
        "sync"

        "github.com/cryptosight/probe/types"
)

// tlsSession holds state shared between the two TCP stream directions of a
// single TLS connection.
type tlsSession struct {
        mu       sync.RWMutex
        sni      string  // SNI hostname from ClientHello server_name extension
        serverIP string  // IP of the TLS server endpoint
        isTLS13  bool    // set when ServerHello supported_versions = 0x0304
}

func (s *tlsSession) setSNI(sni string) {
        s.mu.Lock()
        s.sni = sni
        s.mu.Unlock()
}

func (s *tlsSession) setTLS13() {
        s.mu.Lock()
        s.isTLS13 = true
        s.mu.Unlock()
}

func (s *tlsSession) getTLS13() bool {
        s.mu.RLock()
        defer s.mu.RUnlock()
        return s.isTLS13
}

// hostLabel returns a combined "serverIP (sni)" string when the SNI is
// available, or just the bare serverIP otherwise.
func (s *tlsSession) hostLabel() string {
        s.mu.RLock()
        defer s.mu.RUnlock()
        if s.sni != "" {
                return s.serverIP + " (" + s.sni + ")"
        }
        return s.serverIP
}

// TLS content type for Handshake records.
const tlsHandshakeContentType = 22

// TLS handshake message type constants.
const (
        hsClientHello = 1
        hsServerHello = 2
        hsCertificate = 11
)

// parseTLSStream consumes complete TLS records from data, dispatching each
// Handshake record to parseHandshakeMessages. It returns discovered assets and
// the unconsumed tail (an incomplete record waiting for more bytes).
func parseTLSStream(data []byte, session *tlsSession, probeName string, serverToClient bool) ([]types.DiscoveredAsset, []byte) {
        var assets []types.DiscoveredAsset

        for len(data) >= 5 {
                contentType := data[0]
                recLen := int(binary.BigEndian.Uint16(data[3:5]))

                // TLS max record body = 2^14 + 2048 expansion.
                if recLen > 18432 {
                        // Corrupt data or non-TLS stream — stop parsing.
                        return assets, nil
                }
                if len(data) < 5+recLen {
                        break // incomplete record
                }

                if contentType == tlsHandshakeContentType {
                        fragment := data[5 : 5+recLen]
                        found := parseHandshakeMessages(fragment, session, probeName, serverToClient)
                        assets = append(assets, found...)
                }
                data = data[5+recLen:]
        }
        return assets, data
}

func parseHandshakeMessages(data []byte, session *tlsSession, probeName string, serverToClient bool) []types.DiscoveredAsset {
        var assets []types.DiscoveredAsset

        for len(data) >= 4 {
                msgType := data[0]
                msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
                if len(data) < 4+msgLen {
                        break
                }
                body := data[4 : 4+msgLen]
                data = data[4+msgLen:]

                switch msgType {
                case hsClientHello:
                        if !serverToClient {
                                // ClientHello: extract SNI into session + emit offered-suite assets.
                                found := parseClientHello(body, session, probeName)
                                assets = append(assets, found...)
                        }
                case hsServerHello:
                        if serverToClient {
                                if a := parseServerHello(body, session, probeName); a != nil {
                                        assets = append(assets, *a)
                                }
                        }
                case hsCertificate:
                        if serverToClient {
                                assets = append(assets, parseCertificateMessage(body, session, probeName)...)
                        }
                }
        }
        return assets
}

// parseClientHello extracts the SNI hostname (stored in session) and the list
// of client-offered cipher suites. It emits one type="crypto_library" asset
// per non-GREASE suite so the inventory shows which QV algorithms clients are
// willing to negotiate.
func parseClientHello(body []byte, session *tlsSession, probeName string) []types.DiscoveredAsset {
        // legacy_version(2) + random(32) = 34 bytes before session_id_length
        if len(body) < 34 {
                return nil
        }
        pos := 34

        // Session ID
        if pos >= len(body) {
                return nil
        }
        pos += 1 + int(body[pos])

        // Cipher suites
        if pos+2 > len(body) {
                return nil
        }
        csLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
        pos += 2
        if pos+csLen > len(body) {
                return nil
        }
        cipherSuiteBytes := body[pos : pos+csLen]
        pos += csLen

        // Compression methods
        if pos >= len(body) {
                return nil
        }
        pos += 1 + int(body[pos])

        // Extensions — scan for SNI (type 0x0000)
        if pos+2 <= len(body) {
                extsLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
                pos += 2
                end := pos + extsLen
                for pos+4 <= end && pos+4 <= len(body) {
                        extType := binary.BigEndian.Uint16(body[pos : pos+2])
                        extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
                        pos += 4
                        if extType == 0 && extLen >= 5 { // server_name extension
                                ext := body[pos : pos+extLen]
                                if len(ext) >= 5 && ext[2] == 0 { // name_type 0 = host_name
                                        nameLen := int(binary.BigEndian.Uint16(ext[3:5]))
                                        if len(ext) >= 5+nameLen {
                                                session.setSNI(string(ext[5 : 5+nameLen]))
                                        }
                                }
                        }
                        pos += extLen
                }
        }

        // Emit assets for offered cipher suites (SNI is now in session).
        host := session.hostLabel()
        var assets []types.DiscoveredAsset
        for i := 0; i+1 < len(cipherSuiteBytes); i += 2 {
                id := binary.BigEndian.Uint16(cipherSuiteBytes[i : i+2])
                if isGREASE(id) {
                        continue // skip RFC 8701 GREASE values
                }
                name := tlsCipherSuiteName(id)
                algo := cipherSuiteAuthAlgo(name)
                isQV := types.IsQuantumVulnerableAlgo(algo)
                uid := fmt.Sprintf("probe:%s:capture:offered:%s:%04x", probeName, session.serverIP, id)

                assets = append(assets, types.DiscoveredAsset{
                        UID:                 uid,
                        Name:                fmt.Sprintf("%s (client offered)", name),
                        Type:                "crypto_library",
                        Algorithm:           algo,
                        Host:                strPtr(host),
                        IsQuantumVulnerable: isQV,
                        Labels:              []string{"network_capture", "cipher_suite", "client_offered"},
                        CustomMetadata: map[string]any{
                                "cipherSuite":     fmt.Sprintf("0x%04x", id),
                                "cipherSuiteName": name,
                                "source":          "network_capture",
                                "sourceType":      "network",
                        },
                })
        }
        return assets
}

// parseServerHello extracts the chosen cipher suite, detects TLS 1.3 via the
// supported_versions extension, and emits a type="crypto_library" asset.
func parseServerHello(body []byte, session *tlsSession, probeName string) *types.DiscoveredAsset {
        // legacy_version(2) + random(32) = 34 before session_id_length
        if len(body) < 34 {
                return nil
        }
        pos := 34

        // Session ID
        if pos >= len(body) {
                return nil
        }
        pos += 1 + int(body[pos])

        if pos+2 > len(body) {
                return nil
        }
        cipherID := binary.BigEndian.Uint16(body[pos : pos+2])
        pos += 2

        // Compression method (1 byte)
        if pos >= len(body) {
                return nil
        }
        pos++

        // Extensions — check for supported_versions (type 0x002b) to detect TLS 1.3.
        if pos+2 <= len(body) {
                extsLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
                pos += 2
                end := pos + extsLen
                for pos+4 <= end && pos+4 <= len(body) {
                        extType := binary.BigEndian.Uint16(body[pos : pos+2])
                        extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
                        pos += 4
                        // supported_versions (0x002b) in ServerHello is a single 2-byte version.
                        if extType == 0x002b && extLen >= 2 {
                                selectedVersion := binary.BigEndian.Uint16(body[pos : pos+2])
                                if selectedVersion == 0x0304 {
                                        session.setTLS13()
                                }
                        }
                        pos += extLen
                }
        }

        name := tlsCipherSuiteName(cipherID)
        algo := cipherSuiteAuthAlgo(name)
        isQV := types.IsQuantumVulnerableAlgo(algo)
        host := session.hostLabel()
        uid := fmt.Sprintf("probe:%s:capture:cs:%s:%04x", probeName, session.serverIP, cipherID)

        return &types.DiscoveredAsset{
                UID:                 uid,
                Name:                fmt.Sprintf("%s (negotiated)", name),
                Type:                "crypto_library",
                Algorithm:           algo,
                Host:                strPtr(host),
                IsQuantumVulnerable: isQV,
                Labels:              []string{"network_capture", "cipher_suite"},
                CustomMetadata: map[string]any{
                        "cipherSuite":     fmt.Sprintf("0x%04x", cipherID),
                        "cipherSuiteName": name,
                        "source":          "network_capture",
                        "sourceType":      "network",
                },
        }
}

// parseCertificateMessage decodes a Certificate handshake message (type 11)
// and converts each DER-encoded cert in the chain to a DiscoveredAsset.
//
// Handles both:
//   - TLS 1.2: certificate_list_length(3) followed by cert entries
//   - TLS 1.3: certificate_request_context_length(1) + context + certificate_list_length(3)
//     + cert entries each followed by extensions_length(2) + extensions
func parseCertificateMessage(body []byte, session *tlsSession, probeName string) []types.DiscoveredAsset {
        if len(body) < 3 {
                return nil
        }

        pos := 0
        isTLS13 := session.getTLS13()

        if isTLS13 {
                // Skip certificate_request_context (1-byte length + context bytes).
                if len(body) < 1 {
                        return nil
                }
                contextLen := int(body[0])
                pos = 1 + contextLen
                if pos+3 > len(body) {
                        return nil
                }
        }

        totalLen := int(body[pos])<<16 | int(body[pos+1])<<8 | int(body[pos+2])
        pos += 3
        if pos+totalLen > len(body) {
                return nil
        }

        var assets []types.DiscoveredAsset
        end := pos + totalLen

        for pos+3 <= end {
                certLen := int(body[pos])<<16 | int(body[pos+1])<<8 | int(body[pos+2])
                pos += 3
                if pos+certLen > end {
                        break
                }
                certDER := body[pos : pos+certLen]
                pos += certLen

                // TLS 1.3 adds per-cert extensions after each DER blob.
                if isTLS13 && pos+2 <= end {
                        extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
                        pos += 2 + extLen
                }

                cert, err := x509.ParseCertificate(certDER)
                if err != nil {
                        continue
                }
                assets = append(assets, capturedCertToAsset(cert, session, probeName))
        }
        return assets
}

// capturedCertToAsset maps an x509.Certificate intercepted on the wire to a
// DiscoveredAsset with source="network_capture" / sourceType="network".
func capturedCertToAsset(cert *x509.Certificate, session *tlsSession, probeName string) types.DiscoveredAsset {
        sum := sha256.Sum256(cert.Raw)
        fp := hex.EncodeToString(sum[:])
        algo, keySize := certPubKeyInfo(cert)
        isQV := types.IsQuantumVulnerableAlgo(algo)
        selfSigned := bytes.Equal(cert.RawIssuer, cert.RawSubject)
        host := session.hostLabel()

        sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
        sans = append(sans, cert.DNSNames...)
        for _, ip := range cert.IPAddresses {
                sans = append(sans, ip.String())
        }

        name := cert.Subject.CommonName
        if name == "" && len(cert.DNSNames) > 0 {
                name = cert.DNSNames[0]
        }
        if name == "" {
                name = fmt.Sprintf("cert:%s", fp[:16])
        }

        subject := cert.Subject.String()
        issuer := cert.Issuer.String()
        serial := bigHex(cert.SerialNumber)
        notBefore := cert.NotBefore
        notAfter := cert.NotAfter

        return types.DiscoveredAsset{
                UID:                     fmt.Sprintf("probe:%s:capture:cert:%s", probeName, fp),
                Name:                    name,
                Type:                    "certificate",
                Algorithm:               algo,
                KeySize:                 &keySize,
                SelfSigned:              selfSigned,
                IsQuantumVulnerable:     isQV,
                ExtendedKeyUsage:        ekuNames(cert.ExtKeyUsage),
                SubjectAlternativeNames: sans,
                Host:                    strPtr(host),
                Subject:                 &subject,
                Issuer:                  &issuer,
                SerialNumber:            &serial,
                Fingerprint:             &fp,
                ValidFrom:               &notBefore,
                ValidTo:                 &notAfter,
                Labels:                  []string{"network_capture"},
                CustomMetadata: map[string]any{
                        "capturedFrom": session.serverIP,
                        "source":       "network_capture",
                        "sourceType":   "network",
                },
        }
}

// ── Cipher suite helpers ──────────────────────────────────────────────────────

// isGREASE reports whether id is an RFC 8701 GREASE value.
// GREASE values follow the pattern 0x?A?A where both bytes are identical and
// their low nibble is 0xA (e.g. 0x0A0A, 0x1A1A, 0x2A2A, …, 0xFAFA).
func isGREASE(id uint16) bool {
        lo := uint8(id & 0x00FF)
        hi := uint8(id >> 8)
        return lo == hi && (lo&0x0F) == 0x0A
}

var cipherNames = buildCipherNameMap()

func buildCipherNameMap() map[uint16]string {
        m := make(map[uint16]string)
        for _, s := range tls.CipherSuites() {
                m[s.ID] = s.Name
        }
        for _, s := range tls.InsecureCipherSuites() {
                m[s.ID] = s.Name
        }
        // TLS 1.3 suites (RFC 8446 §B.4) — some Go versions omit these from the
        // lists above.
        m[0x1301] = "TLS_AES_128_GCM_SHA256"
        m[0x1302] = "TLS_AES_256_GCM_SHA384"
        m[0x1303] = "TLS_CHACHA20_POLY1305_SHA256"
        return m
}

func tlsCipherSuiteName(id uint16) string {
        if name, ok := cipherNames[id]; ok {
                return name
        }
        return fmt.Sprintf("UNKNOWN_0x%04x", id)
}

// cipherSuiteAuthAlgo extracts the authentication algorithm from a TLS cipher
// suite name so the quantum-vulnerability flag can be set.
// e.g. "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" → "RSA"
func cipherSuiteAuthAlgo(name string) string {
        n := strings.ToUpper(name)
        switch {
        case strings.Contains(n, "ECDSA"):
                return "ECDSA"
        case strings.Contains(n, "RSA"):
                return "RSA"
        case strings.Contains(n, "_DSS_"):
                return "DSA"
        default:
                // TLS 1.3 AEAD-only suites use ECDH with ephemeral keys negotiated
                // separately; the algorithm field carries the full suite name.
                return name
        }
}

// ── Certificate public-key helpers ───────────────────────────────────────────

func certPubKeyInfo(cert *x509.Certificate) (string, int) {
        switch pub := cert.PublicKey.(type) {
        case *rsa.PublicKey:
                return "RSA", pub.N.BitLen()
        case *ecdsa.PublicKey:
                return "ECDSA", pub.Curve.Params().BitSize
        case ed25519.PublicKey:
                return "Ed25519", 256
        case *dsa.PublicKey:
                return "DSA", pub.P.BitLen()
        default:
                return cert.PublicKeyAlgorithm.String(), 0
        }
}

func bigHex(n *big.Int) string {
        if n == nil {
                return ""
        }
        return fmt.Sprintf("%x", n)
}

func strPtr(s string) *string { return &s }

func ekuNames(ekus []x509.ExtKeyUsage) []string {
        names := make([]string, 0, len(ekus))
        for _, eku := range ekus {
                switch eku {
                case x509.ExtKeyUsageServerAuth:
                        names = append(names, "serverAuth")
                case x509.ExtKeyUsageClientAuth:
                        names = append(names, "clientAuth")
                case x509.ExtKeyUsageCodeSigning:
                        names = append(names, "codeSigning")
                case x509.ExtKeyUsageEmailProtection:
                        names = append(names, "emailProtection")
                case x509.ExtKeyUsageTimeStamping:
                        names = append(names, "timeStamping")
                case x509.ExtKeyUsageOCSPSigning:
                        names = append(names, "OCSPSigning")
                default:
                        names = append(names, "any")
                }
        }
        return names
}
