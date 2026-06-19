// Package config loads and validates the probe YAML configuration.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ProbeConfig identifies this probe instance to the CryptoSight server.
type ProbeConfig struct {
	Name     string `yaml:"name"`
	APIKey   string `yaml:"apiKey"`
	Endpoint string `yaml:"endpoint"`
}

// ScanConfig controls active TLS scanning behaviour.
type ScanConfig struct {
	// Networks is a list of CIDR ranges to scan.
	Networks       []string `yaml:"networks"`
	Ports          []int    `yaml:"ports"`
	Concurrency    int      `yaml:"concurrency"`
	TimeoutSeconds int      `yaml:"timeoutSeconds"`
	// Schedule is an optional cron expression (e.g. "0 2 * * *").
	// When empty the probe runs once and exits (unless passiveSniffer is also
	// enabled, in which case the probe keeps running for the sniffer).
	Schedule string `yaml:"schedule"`
}

// CertStoreConfig controls local certificate store reading.
type CertStoreConfig struct {
	Enabled bool     `yaml:"enabled"`
	Paths   []string `yaml:"paths"`
}

// ModeConfig selects which discovery methods are active.
// Both modes may be enabled simultaneously.
type ModeConfig struct {
	ActiveScan     bool `yaml:"activeScan"`
	PassiveSniffer bool `yaml:"passiveSniffer"`
}

// SnifferConfig tunes the passive pcap-based TLS traffic sniffer.
// Only used when mode.passiveSniffer is true.
type SnifferConfig struct {
	// Interface is the network interface to listen on (e.g. "eth0", "any").
	Interface string `yaml:"interface"`
	// BPFFilter is an optional libpcap BPF filter expression applied before
	// the TLS parser.  Defaults to "tcp port 443 or tcp port 8443".
	BPFFilter string `yaml:"bpfFilter"`
	// FlushIntervalSeconds controls how often accumulated assets are shipped
	// to the CryptoSight API.  Defaults to 60.
	FlushIntervalSeconds int `yaml:"flushIntervalSeconds"`
	// MaxBufferAssets triggers an early flush when the in-memory buffer
	// reaches this many unique assets.  Defaults to 500.
	MaxBufferAssets int `yaml:"maxBufferAssets"`
}

// Config is the root configuration struct.
type Config struct {
	Probe     ProbeConfig     `yaml:"probe"`
	Scan      ScanConfig      `yaml:"scan"`
	CertStore CertStoreConfig `yaml:"certStore"`
	Mode      ModeConfig      `yaml:"mode"`
	Sniffer   SnifferConfig   `yaml:"sniffer"`
}

// Load reads the YAML file at path and applies defaults and validation.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// ── Active scan defaults ──────────────────────────────────────────────
	if cfg.Scan.Concurrency <= 0 {
		cfg.Scan.Concurrency = 50
	}
	if cfg.Scan.TimeoutSeconds <= 0 {
		cfg.Scan.TimeoutSeconds = 5
	}
	if len(cfg.Scan.Ports) == 0 {
		cfg.Scan.Ports = []int{443, 8443, 636, 5671, 8080, 9200, 3269}
	}

	// ── Sniffer defaults ──────────────────────────────────────────────────
	if cfg.Sniffer.BPFFilter == "" {
		cfg.Sniffer.BPFFilter = "tcp port 443 or tcp port 8443"
	}
	if cfg.Sniffer.FlushIntervalSeconds <= 0 {
		cfg.Sniffer.FlushIntervalSeconds = 60
	}
	if cfg.Sniffer.MaxBufferAssets <= 0 {
		cfg.Sniffer.MaxBufferAssets = 500
	}

	// ── Required fields ───────────────────────────────────────────────────
	if cfg.Probe.Name == "" {
		return nil, fmt.Errorf("probe.name is required")
	}
	if cfg.Probe.APIKey == "" {
		return nil, fmt.Errorf("probe.apiKey is required")
	}
	if cfg.Probe.Endpoint == "" {
		return nil, fmt.Errorf("probe.endpoint is required")
	}

	// At least one discovery method must be configured.
	if len(cfg.Scan.Networks) == 0 && !cfg.CertStore.Enabled && !cfg.Mode.PassiveSniffer {
		return nil, fmt.Errorf(
			"configure at least one discovery method: scan.networks, certStore.enabled=true, or mode.passiveSniffer=true",
		)
	}

	// Sniffer requires an interface.
	if cfg.Mode.PassiveSniffer && cfg.Sniffer.Interface == "" {
		return nil, fmt.Errorf("sniffer.interface is required when mode.passiveSniffer=true (e.g. \"eth0\" or \"any\")")
	}

	return &cfg, nil
}
