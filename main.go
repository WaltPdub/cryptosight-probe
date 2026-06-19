// CryptoSight On-Prem Probe
//
// Actively scans IP ranges for TLS endpoints, reads local certificate stores,
// and passively sniffs live network traffic for TLS handshake data — then ships
// all findings to the CryptoSight ingest API so private-network assets appear
// in the cryptographic inventory alongside cloud-discovered assets.
//
// Usage:
//
//      cryptosight-probe [--config /path/to/config.yaml]
//
// The default config path is ./config.yaml (or /config/config.yaml inside the
// Docker image, mounted via docker-compose volume).
package main

import (
        "context"
        "flag"
        "log"
        "os"
        "os/signal"
        "sync"
        "syscall"

        "github.com/cryptosight/probe/certstore"
        "github.com/cryptosight/probe/config"
        "github.com/cryptosight/probe/scanner"
        "github.com/cryptosight/probe/sender"
        "github.com/cryptosight/probe/sniffer"
        "github.com/cryptosight/probe/types"
        "github.com/robfig/cron/v3"
)

// version is stamped at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

func main() {
        configPath := flag.String("config", defaultConfigPath(), "path to config.yaml")
        flag.Parse()

        cfg, err := config.Load(*configPath)
        if err != nil {
                log.Fatalf("ERROR: loading config: %v", err)
        }

        log.Printf("INFO: CryptoSight probe %q starting (version=%s)", cfg.Probe.Name, version)

        // Root context cancelled on SIGTERM or SIGINT.
        ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
        defer stop()

        var wg sync.WaitGroup

        // ── Passive sniffer (long-running goroutine) ───────────────────────────
        // Runs independently of the active scan — both modes can be enabled
        // simultaneously.  The sniffer sends directly to the API on its own flush
        // cadence; assets from both sources deduplicate in the server's ingest
        // pipeline via canonical uid.
        if cfg.Mode.PassiveSniffer {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        if err := sniffer.Run(ctx, cfg, version); err != nil {
                                log.Printf("ERROR: passive sniffer: %v", err)
                        }
                }()
        }

        // ── Scan cycle (active TLS scan and/or cert-store read) ──────────────
        // This block runs whenever active scan OR cert-store is configured,
        // independently of whether the passive sniffer is also running.
        needsCycle := (cfg.Mode.ActiveScan && len(cfg.Scan.Networks) > 0) || cfg.CertStore.Enabled
        if needsCycle {
                if cfg.Scan.Schedule != "" {
                        // Scheduled mode: run on the cron expression.
                        c := cron.New()
                        if _, err := c.AddFunc(cfg.Scan.Schedule, func() {
                                if err := runCycle(cfg); err != nil {
                                        log.Printf("ERROR: scheduled scan cycle failed: %v", err)
                                }
                        }); err != nil {
                                log.Fatalf("ERROR: invalid cron schedule %q: %v", cfg.Scan.Schedule, err)
                        }
                        c.Start()
                        log.Printf("INFO: scan cycle scheduled on %q — waiting for first tick", cfg.Scan.Schedule)

                        // Wait for shutdown, then drain the scheduler.
                        <-ctx.Done()
                        log.Println("INFO: stopping scan scheduler")
                        <-c.Stop().Done()
                        wg.Wait()
                        log.Println("INFO: probe stopped")
                        return
                }

                // One-shot mode: run once immediately.
                if err := runCycle(cfg); err != nil {
                        log.Printf("ERROR: scan cycle failed: %v", err)
                        if !cfg.Mode.PassiveSniffer {
                                wg.Wait()
                                os.Exit(1)
                        }
                }

                // If only the scan cycle was needed (no sniffer), one-shot then exit.
                if !cfg.Mode.PassiveSniffer {
                        return
                }
                // Sniffer is still running — fall through to wait for the signal.
        }

        // Block until SIGTERM/SIGINT, then drain long-running goroutines.
        <-ctx.Done()
        log.Println("INFO: shutdown signal received — draining")
        wg.Wait()
        log.Println("INFO: probe stopped")
}

// runCycle executes one full active-scan+send cycle:
//  1. Active TLS scan  (if mode.activeScan=true and scan.networks is non-empty)
//  2. Cert store read  (if certStore.enabled=true)
//  3. POST combined results to the CryptoSight ingest endpoint
func runCycle(cfg *config.Config) error {
        hostname, _ := os.Hostname()
        var assets []types.DiscoveredAsset

        if cfg.Mode.ActiveScan && len(cfg.Scan.Networks) > 0 {
                log.Printf("INFO: active TLS scan starting — %d network(s), ports %v, concurrency %d",
                        len(cfg.Scan.Networks), cfg.Scan.Ports, cfg.Scan.Concurrency)
                found, err := scanner.Run(cfg)
                if err != nil {
                        log.Printf("WARN: active scan error: %v", err)
                } else {
                        log.Printf("INFO: active scan complete — %d TLS asset(s) found", len(found))
                        assets = append(assets, found...)
                }
        }

        if cfg.CertStore.Enabled {
                log.Printf("INFO: cert store scan starting — %d path(s)", len(cfg.CertStore.Paths))
                found, err := certstore.Read(cfg)
                if err != nil {
                        log.Printf("WARN: cert store scan error: %v", err)
                } else {
                        log.Printf("INFO: cert store scan complete — %d asset(s) found", len(found))
                        assets = append(assets, found...)
                }
        }

        if len(assets) == 0 {
                log.Println("INFO: no assets discovered this cycle — nothing to send")
                return nil
        }

        log.Printf("INFO: sending %d asset(s) to %s", len(assets), cfg.Probe.Endpoint)
        resp, err := sender.Send(cfg.Probe.Endpoint, cfg.Probe.APIKey, version, hostname, assets, nil)
        if err != nil {
                return err
        }
        log.Printf("INFO: ingest complete — accepted=%d rejected=%d", resp.Accepted, resp.Rejected)
        if resp.Rejected > 0 {
                log.Printf("WARN: %d asset(s) rejected by server (check server logs for validation details)", resp.Rejected)
        }
        return nil
}

// defaultConfigPath returns /config/config.yaml when running inside the Docker
// image (mount point) and falls back to ./config.yaml for local builds.
func defaultConfigPath() string {
        if _, err := os.Stat("/config/config.yaml"); err == nil {
                return "/config/config.yaml"
        }
        return "config.yaml"
}
