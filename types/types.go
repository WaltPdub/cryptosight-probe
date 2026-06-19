// Package types defines the shared data model exchanged between the scanner,
// cert-store reader, and ingest sender.  The DiscoveredAsset shape mirrors the
// TypeScript interface in artifacts/api-server/src/lib/sensors/types.ts so the
// server's post-processing pipeline (validate → dedupe → upsert) can accept it
// without modification.
package types

import "time"

// DiscoveredAsset is one cryptographic asset emitted by a scanner or cert-store
// reader.  All pointer fields are optional; omitempty suppresses nil values in
// the JSON payload so the server doesn't receive spurious nulls.
type DiscoveredAsset struct {
        UID                     string            `json:"uid"`
        Name                    string            `json:"name"`
        Type                    string            `json:"type"` // "certificate" | "key"
        Algorithm               string            `json:"algorithm"`
        KeySize                 *int              `json:"keySize,omitempty"`
        SelfSigned              bool              `json:"selfSigned,omitempty"`
        ExtendedKeyUsage        []string          `json:"extendedKeyUsage,omitempty"`
        SubjectAlternativeNames []string          `json:"subjectAlternativeNames,omitempty"`
        Host                    *string           `json:"host,omitempty"`
        FilePath                *string           `json:"filePath,omitempty"`
        Subject                 *string           `json:"subject,omitempty"`
        Issuer                  *string           `json:"issuer,omitempty"`
        SerialNumber            *string           `json:"serialNumber,omitempty"`
        Fingerprint             *string           `json:"fingerprint,omitempty"`
        ValidFrom               *time.Time        `json:"validFrom,omitempty"`
        ValidTo                 *time.Time        `json:"validTo,omitempty"`
        Status                  *string           `json:"status,omitempty"`
        Labels                  []string          `json:"labels,omitempty"`
        CustomMetadata          map[string]any    `json:"customMetadata,omitempty"`

        // IsQuantumVulnerable is a heuristic flag the probe computes locally so
        // operators can review it in the payload before ingest.  The server
        // re-derives it from Algorithm and ignores this field for storage.
        // RSA / ECDSA / DSA → true; Ed25519 / Kyber / Dilithium → false.
        IsQuantumVulnerable bool `json:"isQuantumVulnerable"`
}

// IsQuantumVulnerableAlgo returns the quantum-vulnerability heuristic for a
// given algorithm name.  This mirrors the server-side classify.ts logic.
func IsQuantumVulnerableAlgo(algorithm string) bool {
        switch algorithm {
        case "RSA", "ECDSA", "DSA":
                return true
        default:
                // Ed25519, Kyber, Dilithium, SPHINCS+, and unknowns are treated as safe.
                return false
        }
}

// SnifferStats contains live capture metrics reported by the passive sniffer
// on every ingest flush so the management UI can show sniffer health without
// a separate polling endpoint.
type SnifferStats struct {
        PacketsTotal   uint64   `json:"packetsTotal"`
        ActiveStreams   int64    `json:"activeStreams"`
        CipherSuites   []string `json:"cipherSuites"`  // unique suite names seen this flush window
        BufferDepth    int      `json:"bufferDepth"`   // assets in buffer at flush time
        CaptureStarted string   `json:"captureStarted"` // RFC 3339 time the sniffer started
}

// IngestRequest is the body POSTed to /api/probes/ingest.
type IngestRequest struct {
        Assets       []DiscoveredAsset `json:"assets"`
        ProbeVersion string            `json:"probeVersion"`
        Hostname     string            `json:"hostname"`
        // SnifferStats is optional; present only when the probe runs with passiveSniffer=true.
        SnifferStats *SnifferStats `json:"snifferStats,omitempty"`
}

// IngestResponse is the server's reply.
type IngestResponse struct {
        Accepted int `json:"accepted"`
        Rejected int `json:"rejected"`
}
