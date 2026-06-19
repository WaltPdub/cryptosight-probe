// Package scanner implements the active TLS scanner.
//
// For each IP in the configured CIDR ranges the scanner attempts a TCP
// connection on each configured port.  If the port is open and speaks TLS the
// full certificate chain is extracted from the handshake and converted to
// DiscoveredAsset records.
//
// InsecureSkipVerify is used intentionally: the goal is cert extraction, NOT
// trust validation.  An untrusted cert is still a crypto asset that needs to
// appear in the inventory.
package scanner

import (
        "bytes"
        "crypto/dsa"
        "crypto/ecdsa"
        "crypto/ed25519"
        "crypto/rsa"
        "crypto/sha256"
        "crypto/tls"
        "crypto/x509"
        "encoding/hex"
        "fmt"
        "log"
        "math/big"
        "net"
        "sync"
        "time"

        "github.com/cryptosight/probe/config"
        "github.com/cryptosight/probe/types"
)

// target is a single host:port pair to attempt.
type target struct {
        host string
        port int
}

// Run scans all networks/ports in cfg and returns every discovered asset.
// Duplicate certificates (same fingerprint, different ports) are deduplicated
// so the inventory receives one canonical entry per certificate.
func Run(cfg *config.Config) ([]types.DiscoveredAsset, error) {
        timeout := time.Duration(cfg.Scan.TimeoutSeconds) * time.Second
        sem := make(chan struct{}, cfg.Scan.Concurrency)

        var (
                mu     sync.Mutex
                seen   = map[string]bool{}
                assets []types.DiscoveredAsset
                wg     sync.WaitGroup
        )

        addAsset := func(a types.DiscoveredAsset) {
                key := a.UID
                mu.Lock()
                defer mu.Unlock()
                if !seen[key] {
                        seen[key] = true
                        assets = append(assets, a)
                }
        }

        for _, cidr := range cfg.Scan.Networks {
                if err := iterCIDR(cidr, func(ip string) {
                        for _, port := range cfg.Scan.Ports {
                                t := target{ip, port}
                                wg.Add(1)
                                sem <- struct{}{}
                                go func(t target) {
                                        defer wg.Done()
                                        defer func() { <-sem }()
                                        found := scanTarget(t, cfg.Probe.Name, timeout)
                                        for _, a := range found {
                                                addAsset(a)
                                        }
                                }(t)
                        }
                }); err != nil {
                        log.Printf("WARN: skipping invalid CIDR %q: %v", cidr, err)
                }
        }

        wg.Wait()
        return assets, nil
}

// scanTarget dials host:port and returns DiscoveredAssets for each cert in the
// peer's chain.  Connection/handshake errors are silently ignored (the host may
// not be up or may not speak TLS on that port).
func scanTarget(t target, probeName string, timeout time.Duration) []types.DiscoveredAsset {
        certs, cipherSuite, err := tlsConnect(t.host, t.port, timeout)
        if err != nil {
                return nil
        }

        var assets []types.DiscoveredAsset
        for _, cert := range certs {
                a := certToAsset(cert, t.host, t.port, probeName, cipherSuite)
                assets = append(assets, a)
        }
        return assets
}

// tlsConnect opens a TLS connection and returns the peer certificate chain and
// the negotiated cipher suite id.
func tlsConnect(host string, port int, timeout time.Duration) ([]*x509.Certificate, uint16, error) {
        addr := fmt.Sprintf("%s:%d", host, port)
        dialer := &net.Dialer{Timeout: timeout}
        conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
                InsecureSkipVerify: true, //nolint:gosec // intentional — extracting certs, not trusting them
        })
        if err != nil {
                return nil, 0, err
        }
        defer conn.Close()
        state := conn.ConnectionState()
        return state.PeerCertificates, state.CipherSuite, nil
}

// certToAsset converts an x509 certificate to a DiscoveredAsset.
func certToAsset(cert *x509.Certificate, host string, port int, probeName string, cipherSuite uint16) types.DiscoveredAsset {
        fp := sha256hex(cert.Raw)
        algo, keySize := pubKeyInfo(cert)

        selfSigned := bytes.Equal(cert.RawIssuer, cert.RawSubject)

        sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses))
        sans = append(sans, cert.DNSNames...)
        for _, ip := range cert.IPAddresses {
                sans = append(sans, ip.String())
        }
        sans = append(sans, cert.EmailAddresses...)

        ekus := ekuStrings(cert.ExtKeyUsage)

        subject := cert.Subject.String()
        issuer := cert.Issuer.String()
        serial := serialHex(cert.SerialNumber)
        hostStr := host

        name := cert.Subject.CommonName
        if name == "" && len(cert.DNSNames) > 0 {
                name = cert.DNSNames[0]
        }
        if name == "" {
                name = fmt.Sprintf("cert:%s", fp[:16])
        }

        uid := fmt.Sprintf("probe:%s:tls:%s", probeName, fp)

        meta := map[string]any{
                "port":             port,
                "negotiatedCipher": cipherSuiteName(cipherSuite),
        }

        notBefore := cert.NotBefore
        notAfter := cert.NotAfter
        isQV := types.IsQuantumVulnerableAlgo(algo)

        return types.DiscoveredAsset{
                UID:                     uid,
                Name:                    name,
                Type:                    "certificate",
                Algorithm:               algo,
                KeySize:                 &keySize,
                SelfSigned:              selfSigned,
                IsQuantumVulnerable:     isQV,
                ExtendedKeyUsage:        ekus,
                SubjectAlternativeNames: sans,
                Host:                    &hostStr,
                Subject:                 &subject,
                Issuer:                  &issuer,
                SerialNumber:            &serial,
                Fingerprint:             &fp,
                ValidFrom:               &notBefore,
                ValidTo:                 &notAfter,
                Labels:                  []string{"tls", fmt.Sprintf("port:%d", port)},
                CustomMetadata:          meta,
        }
}

// pubKeyInfo returns the algorithm name and key size in bits for the
// certificate's public key.
func pubKeyInfo(cert *x509.Certificate) (string, int) {
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

// sha256hex returns the lowercase hex SHA-256 digest of data.
// This is the fingerprint format expected by the server's dedup logic:
// canonicalUid = "cert:fp:" + fingerprint (64 lowercase hex chars).
func sha256hex(data []byte) string {
        sum := sha256.Sum256(data)
        return hex.EncodeToString(sum[:])
}

// serialHex returns the certificate serial number as a lowercase hex string
// with no spaces — matching the server's dedupe normalisation.
func serialHex(n *big.Int) string {
        if n == nil {
                return ""
        }
        return fmt.Sprintf("%x", n)
}

// ekuStrings converts the x509 ExtKeyUsage slice to the string names that the
// server stores in the extendedKeyUsage JSON array.
func ekuStrings(ekus []x509.ExtKeyUsage) []string {
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
                case x509.ExtKeyUsageIPSECEndSystem:
                        names = append(names, "ipsecEndSystem")
                case x509.ExtKeyUsageIPSECTunnel:
                        names = append(names, "ipsecTunnel")
                case x509.ExtKeyUsageIPSECUser:
                        names = append(names, "ipsecUser")
                case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
                        names = append(names, "msServerGatedCrypto")
                case x509.ExtKeyUsageNetscapeServerGatedCrypto:
                        names = append(names, "netscapeServerGatedCrypto")
                default:
                        names = append(names, "any")
                }
        }
        return names
}

// cipherSuiteName maps a TLS cipher suite id to a human-readable name.
func cipherSuiteName(id uint16) string {
        for _, s := range tls.CipherSuites() {
                if s.ID == id {
                        return s.Name
                }
        }
        for _, s := range tls.InsecureCipherSuites() {
                if s.ID == id {
                        return s.Name
                }
        }
        return fmt.Sprintf("0x%04x", id)
}

// iterCIDR calls fn for every usable host address in the CIDR block.
// Uses a streaming iterator to avoid allocating a giant host slice for
// large ranges (e.g. /8 = 16 M hosts).
func iterCIDR(cidr string, fn func(ip string)) error {
        baseIP, ipnet, err := net.ParseCIDR(cidr)
        if err != nil {
                return err
        }

        // Start from the network address.
        ip := cloneIP(baseIP.To4())
        if ip == nil {
                ip = cloneIP(baseIP.To16())
        }
        ip = cloneIP(ip.Mask(ipnet.Mask))

        ones, bits := ipnet.Mask.Size()
        isHost := bits-ones <= 1 // /31 and /32 — no broadcast/network

        first := true
        for ipnet.Contains(ip) {
                last := isLastAddr(ip, ipnet)
                if !first && !last || isHost {
                        fn(ip.String())
                }
                first = false
                if !incIP(ip) {
                        break
                }
        }
        return nil
}

func cloneIP(ip net.IP) net.IP {
        clone := make(net.IP, len(ip))
        copy(clone, ip)
        return clone
}

func incIP(ip net.IP) bool {
        for i := len(ip) - 1; i >= 0; i-- {
                ip[i]++
                if ip[i] != 0 {
                        return true
                }
        }
        return false
}

func isLastAddr(ip net.IP, ipnet *net.IPNet) bool {
        mask := ipnet.Mask
        for i := range ip {
                idx := len(ip) - len(mask) + i
                if idx < 0 {
                        continue
                }
                if ip[idx]&^mask[i] != ^mask[i]&0xff {
                        return false
                }
        }
        return true
}
