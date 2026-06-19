// Package sender POSTs the collected DiscoveredAssets to the CryptoSight
// probe ingest endpoint with Bearer token authentication.
//
// Retry policy: up to 3 attempts with exponential back-off (2 s, 4 s).
// Any non-2xx final response is treated as a hard error so the caller can
// log it and decide whether to retry on the next cron tick.
package sender

import (
        "bytes"
        "encoding/json"
        "fmt"
        "io"
        "log"
        "net/http"
        "strings"
        "time"

        "github.com/cryptosight/probe/types"
)

const (
        maxAttempts    = 3
        initialBackoff = 2 * time.Second
)

// Send batches assets into a single POST to <endpoint>/probes/ingest.
// Pass snifferStats as non-nil only from the passive sniffer flush path;
// active-scan callers should pass nil.
// It returns the server's accepted/rejected counts on success.
func Send(endpoint, apiKey, probeVersion, hostname string, assets []types.DiscoveredAsset, snifferStats *types.SnifferStats) (*types.IngestResponse, error) {
        url := strings.TrimRight(endpoint, "/") + "/probes/ingest"

        body := types.IngestRequest{
                Assets:       assets,
                ProbeVersion: probeVersion,
                Hostname:     hostname,
                SnifferStats: snifferStats,
        }

        payload, err := json.Marshal(body)
        if err != nil {
                return nil, fmt.Errorf("marshalling ingest payload: %w", err)
        }

        var lastErr error
        backoff := initialBackoff

        for attempt := 1; attempt <= maxAttempts; attempt++ {
                resp, err := post(url, apiKey, payload)
                if err == nil {
                        return resp, nil
                }
                lastErr = err
                if attempt < maxAttempts {
                        log.Printf("WARN: ingest attempt %d/%d failed: %v — retrying in %s", attempt, maxAttempts, err, backoff)
                        time.Sleep(backoff)
                        backoff *= 2
                }
        }

        return nil, fmt.Errorf("ingest failed after %d attempts: %w", maxAttempts, lastErr)
}

func post(url, apiKey string, payload []byte) (*types.IngestResponse, error) {
        req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
        if err != nil {
                return nil, fmt.Errorf("building request: %w", err)
        }
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("Authorization", "Bearer "+apiKey)

        client := &http.Client{Timeout: 30 * time.Second}
        res, err := client.Do(req)
        if err != nil {
                return nil, fmt.Errorf("HTTP POST: %w", err)
        }
        defer res.Body.Close()

        respBody, _ := io.ReadAll(res.Body)

        if res.StatusCode < 200 || res.StatusCode >= 300 {
                return nil, fmt.Errorf("server returned %d: %s", res.StatusCode, strings.TrimSpace(string(respBody)))
        }

        var ingestResp types.IngestResponse
        if err := json.Unmarshal(respBody, &ingestResp); err != nil {
                // Non-JSON success body is tolerated.
                return &types.IngestResponse{}, nil
        }
        return &ingestResp, nil
}
