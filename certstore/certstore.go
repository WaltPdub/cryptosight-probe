// Package certstore walks local certificate store directories and emits a
// DiscoveredAsset for every parseable certificate found.
//
// Supported file formats:
//   - PEM     — .pem, .crt, .cer  (may contain multiple CERTIFICATE blocks)
//   - DER     — .der              (single certificate per file)
//   - PKCS#12 — .p12, .pfx       (tries empty password then "changeit"/"password")
//   - JKS     — .jks             (via keytool subprocess when available)
//
// Files that cannot be parsed are skipped with a log warning; they do not cause
// the scan to fail.  This mirrors the honesty contract: the probe never
// fabricates assets, but transient read errors are non-fatal.
package certstore

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	goPkcs12 "golang.org/x/crypto/pkcs12"

	"github.com/cryptosight/probe/config"
	"github.com/cryptosight/probe/types"
)

// Read walks every path in cfg.CertStore.Paths and returns all parseable
// certificates as DiscoveredAssets.  Duplicate certificates (same fingerprint
// found under two paths) are suppressed.
func Read(cfg *config.Config) ([]types.DiscoveredAsset, error) {
	seen := map[string]bool{}
	var assets []types.DiscoveredAsset

	for _, dir := range cfg.CertStore.Paths {
		if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Printf("WARN: certstore walk error at %q: %v", path, err)
				return nil // continue walking
			}
			if info.IsDir() {
				return nil
			}
			found := parseCertFile(path, cfg.Probe.Name)
			for _, a := range found {
				if a.Fingerprint != nil && !seen[*a.Fingerprint] {
					seen[*a.Fingerprint] = true
					assets = append(assets, a)
				}
			}
			return nil
		}); err != nil {
			log.Printf("WARN: certstore path %q unreachable: %v", dir, err)
		}
	}

	return assets, nil
}

// parseCertFile dispatches to the appropriate parser based on file extension.
func parseCertFile(path, probeName string) []types.DiscoveredAsset {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".pem", ".crt", ".cer":
		return parsePEM(path, probeName)
	case ".der":
		return parseDER(path, probeName)
	case ".p12", ".pfx":
		return parsePKCS12(path, probeName)
	case ".jks":
		return parseJKS(path, probeName)
	}
	return nil
}

// parsePEM reads a PEM file and returns one DiscoveredAsset per CERTIFICATE block.
func parsePEM(path, probeName string) []types.DiscoveredAsset {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("WARN: cannot read %q: %v", path, err)
		return nil
	}

	var assets []types.DiscoveredAsset
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("WARN: cannot parse PEM cert in %q: %v", path, err)
			continue
		}
		assets = append(assets, certToAsset(cert, path, probeName))
	}
	return assets
}

// parseDER reads a DER-encoded certificate file (single cert per file).
func parseDER(path, probeName string) []types.DiscoveredAsset {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("WARN: cannot read %q: %v", path, err)
		return nil
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		log.Printf("WARN: cannot parse DER cert %q: %v", path, err)
		return nil
	}
	return []types.DiscoveredAsset{certToAsset(cert, path, probeName)}
}

// parsePKCS12 reads a PKCS#12 (.p12 / .pfx) file and returns all certificates
// found in it (leaf cert + CA chain).  It tries a set of common passwords;
// if all fail the file is skipped with a warning.
func parsePKCS12(path, probeName string) []types.DiscoveredAsset {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("WARN: cannot read %q: %v", path, err)
		return nil
	}

	// Common PKCS#12 passwords — covers the majority of dev/ops use cases.
	passwords := []string{"", "changeit", "password", "secret"}
	for _, pass := range passwords {
		blocks, err := goPkcs12.ToPEM(data, pass)
		if err != nil {
			continue
		}
		var assets []types.DiscoveredAsset
		for _, block := range blocks {
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Printf("WARN: cannot parse cert in PKCS#12 %q: %v", path, err)
				continue
			}
			assets = append(assets, certToAsset(cert, path, probeName))
		}
		if len(assets) > 0 {
			return assets
		}
	}
	log.Printf("WARN: could not decode PKCS#12 %q — check the password or format", path)
	return nil
}

// parseJKS extracts certificates from a Java KeyStore (.jks) file by invoking
// the system `keytool` command.  If keytool is not installed the file is
// skipped with an informational log.
func parseJKS(path, probeName string) []types.DiscoveredAsset {
	// Locate keytool; skip gracefully if not present.
	keytool, err := exec.LookPath("keytool")
	if err != nil {
		log.Printf("INFO: skipping JKS %q — keytool not found in PATH", path)
		return nil
	}

	// keytool -list -rfc exports all entries as PEM certificate blocks.
	// We try empty password first (common in dev environments), then "changeit".
	for _, storePass := range []string{"", "changeit"} {
		//nolint:gosec // keytool path is from LookPath; storePass is not user input
		out, err := exec.Command(
			keytool, "-list", "-rfc",
			"-keystore", path,
			"-storepass", storePass,
			"-noprompt",
		).Output()
		if err != nil {
			continue
		}

		var assets []types.DiscoveredAsset
		rest := out
		for len(rest) > 0 {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Printf("WARN: cannot parse cert from JKS %q: %v", path, err)
				continue
			}
			assets = append(assets, certToAsset(cert, path, probeName))
		}
		if len(assets) > 0 {
			return assets
		}
	}
	log.Printf("WARN: could not read JKS %q — check keytool version or store password", path)
	return nil
}

// certToAsset converts an x509.Certificate to a DiscoveredAsset with
// filePath set to the absolute path where the cert was found.
func certToAsset(cert *x509.Certificate, filePath, probeName string) types.DiscoveredAsset {
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

	abs, err := filepath.Abs(filePath)
	if err != nil {
		abs = filePath
	}

	name := cert.Subject.CommonName
	if name == "" && len(cert.DNSNames) > 0 {
		name = cert.DNSNames[0]
	}
	if name == "" {
		name = fmt.Sprintf("cert:%s", fp[:16])
	}

	uid := fmt.Sprintf("probe:%s:certstore:%s", probeName, fp)

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
		FilePath:                &abs,
		Subject:                 &subject,
		Issuer:                  &issuer,
		SerialNumber:            &serial,
		Fingerprint:             &fp,
		ValidFrom:               &notBefore,
		ValidTo:                 &notAfter,
		Labels:                  []string{"cert_store"},
		CustomMetadata:          map[string]any{"source": "cert_store"},
	}
}

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

func sha256hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func serialHex(n *big.Int) string {
	if n == nil {
		return ""
	}
	return fmt.Sprintf("%x", n)
}

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
