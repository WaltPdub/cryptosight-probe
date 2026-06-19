// capture.go — pcap-based passive TLS traffic capture.
//
// This file contains the CGO-dependent pcap integration. It opens the network
// interface in promiscuous mode, runs gopacket TCP stream reassembly, feeds
// reassembled streams into the TLS handshake parser in tls.go, and flushes
// discovered assets to the CryptoSight API on the configured interval or when
// the buffer fills.
//
// Capture statistics are collected atomically and piggybacked onto every
// ingest flush so the server always has an up-to-date view of sniffer health
// without a separate polling endpoint.
//
// Required Linux capabilities: CAP_NET_ADMIN, CAP_NET_RAW (see docker-compose.yml).
package sniffer

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"

	"github.com/cryptosight/probe/config"
	"github.com/cryptosight/probe/sender"
	"github.com/cryptosight/probe/types"
)

// well-known TLS server ports used to determine stream direction.
// When the destination port is in this set, the stream is client→server
// (contains ClientHello). Otherwise it is server→client (ServerHello + Certificate).
var tlsServerPorts = map[uint16]bool{
	443: true, 465: true, 636: true, 993: true, 995: true,
	3269: true, 5671: true, 5986: true, 8080: true, 8443: true,
	8883: true, 9200: true,
}

func isServerPort(p uint16) bool { return tlsServerPorts[p] }

// connKey is a canonical, direction-independent identifier for a TCP connection.
// It is built by lexicographically sorting the two "ip:port" endpoint strings.
type connKey [2]string

func makeConnKey(net, transport gopacket.Flow) connKey {
	srcPort := binary.BigEndian.Uint16(transport.Src().Raw())
	dstPort := binary.BigEndian.Uint16(transport.Dst().Raw())
	a := fmt.Sprintf("%s:%d", net.Src().String(), srcPort)
	b := fmt.Sprintf("%s:%d", net.Dst().String(), dstPort)
	if a < b {
		return connKey{a, b}
	}
	return connKey{b, a}
}

// snifferCtx is the shared mutable state threaded through all stream goroutines.
type snifferCtx struct {
	buffer         *AssetBuffer
	sessions       sync.Map // connKey → *tlsSession
	probeName      string
	captureStarted time.Time

	// Live capture counters — updated from multiple goroutines.
	packetsTotal  atomic.Uint64 // total packets received from pcap
	activeStreams  atomic.Int64  // currently live TCP reassembly goroutines
	windowSuites  sync.Map      // cipher suite name → struct{} (cleared after each flush)
}

// snapshotStats builds a SnifferStats snapshot at flush time.
// bufDepth is the buffer depth BEFORE the flush so the server sees the peak.
func (s *snifferCtx) snapshotStats(bufDepth int) types.SnifferStats {
	var suites []string
	s.windowSuites.Range(func(k, _ any) bool {
		suites = append(suites, k.(string))
		return true
	})
	sort.Strings(suites)
	return types.SnifferStats{
		PacketsTotal:   s.packetsTotal.Load(),
		ActiveStreams:  s.activeStreams.Load(),
		CipherSuites:  suites,
		BufferDepth:   bufDepth,
		CaptureStarted: s.captureStarted.UTC().Format(time.RFC3339),
	}
}

// clearWindowSuites resets the per-flush-window cipher suite set.
func (s *snifferCtx) clearWindowSuites() {
	s.windowSuites.Range(func(k, _ any) bool {
		s.windowSuites.Delete(k)
		return true
	})
}

// ── TCP stream factory ────────────────────────────────────────────────────────

type tlsStreamFactory struct{ s *snifferCtx }

type tlsStream struct {
	reader         tcpreader.ReaderStream
	session        *tlsSession
	serverToClient bool
	s              *snifferCtx
}

// New is called by the TCP assembler for every new TCP stream direction.
func (f *tlsStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	dstPort := binary.BigEndian.Uint16(transport.Dst().Raw())

	// Determine which endpoint is the TLS server.
	serverIP := net.Dst().String()
	isS2C := false
	if !isServerPort(dstPort) {
		// Destination is not a server port → this stream flows server→client.
		serverIP = net.Src().String()
		isS2C = true
	}

	key := makeConnKey(net, transport)
	raw, _ := f.s.sessions.LoadOrStore(key, &tlsSession{serverIP: serverIP})

	stream := &tlsStream{
		reader:         tcpreader.NewReaderStream(),
		session:        raw.(*tlsSession),
		serverToClient: isS2C,
		s:              f.s,
	}
	f.s.activeStreams.Add(1)
	go stream.run()
	return &stream.reader
}

func (s *tlsStream) run() {
	defer s.s.activeStreams.Add(-1)
	// Drain the reader on exit — the assembler blocks if bytes are left unconsumed.
	defer io.Copy(io.Discard, &s.reader) //nolint:errcheck

	var buf []byte
	tmp := make([]byte, 4096)

	for {
		n, err := s.reader.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			var found []types.DiscoveredAsset
			found, buf = parseTLSStream(buf, s.session, s.s.probeName, s.serverToClient)
			for _, a := range found {
				s.s.buffer.Add(a)
				// Track unique cipher suite names seen this flush window.
				if a.Type == "crypto_library" {
					if name, ok := a.CustomMetadata["cipherSuiteName"].(string); ok && name != "" {
						s.s.windowSuites.Store(name, struct{}{})
					}
				}
			}
		}
		if err != nil {
			break
		}
	}
}

// ── Main capture loop ─────────────────────────────────────────────────────────

// Run opens the pcap capture handle on the configured interface, starts the
// TCP stream assembler, and periodically flushes captured assets + sniffer
// stats to the CryptoSight ingest API.
//
// It blocks until ctx is cancelled, then flushes any remaining assets before
// returning.
func Run(ctx context.Context, cfg *config.Config, probeVersion string) error {
	iface := cfg.Sniffer.Interface
	if iface == "" {
		iface = "eth0"
	}

	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("opening pcap on %q: %w", iface, err)
	}
	defer handle.Close()

	if filter := cfg.Sniffer.BPFFilter; filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			return fmt.Errorf("setting BPF filter %q: %w", filter, err)
		}
		log.Printf("INFO: sniffer BPF filter: %q", filter)
	}

	maxBuf := cfg.Sniffer.MaxBufferAssets
	if maxBuf <= 0 {
		maxBuf = 500
	}
	buf := NewAssetBuffer(maxBuf)

	s := &snifferCtx{
		buffer:         buf,
		probeName:      cfg.Probe.Name,
		captureStarted: time.Now(),
	}

	factory := &tlsStreamFactory{s: s}
	pool := tcpassembly.NewStreamPool(factory)
	assembler := tcpassembly.NewAssembler(pool)

	flushInterval := time.Duration(cfg.Sniffer.FlushIntervalSeconds) * time.Second
	if flushInterval <= 0 {
		flushInterval = 60 * time.Second
	}
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	hostname, _ := os.Hostname()

	// flushNow ships accumulated assets + sniffer stats to the CryptoSight API.
	// It always fires — even when there are no new assets — so the server
	// receives a regular heartbeat with updated capture counters.
	flushNow := func() {
		bufDepth := buf.Len()
		stats := s.snapshotStats(bufDepth)
		s.clearWindowSuites()

		assets := buf.Flush()
		log.Printf("INFO: sniffer flush — %d asset(s), %d packets total, %d active streams",
			len(assets), stats.PacketsTotal, stats.ActiveStreams)

		resp, err := sender.Send(cfg.Probe.Endpoint, cfg.Probe.APIKey, probeVersion, hostname, assets, &stats)
		if err != nil {
			log.Printf("WARN: sniffer flush error: %v", err)
			return
		}
		log.Printf("INFO: sniffer ingest complete — accepted=%d rejected=%d", resp.Accepted, resp.Rejected)
		if resp.Rejected > 0 {
			log.Printf("WARN: sniffer: %d asset(s) rejected (check server validation logs)", resp.Rejected)
		}
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := src.Packets()

	log.Printf("INFO: passive sniffer started on interface %q (flush every %s, max buffer %d)",
		iface, flushInterval, maxBuf)

	for {
		select {
		case <-ctx.Done():
			log.Println("INFO: sniffer shutting down — flushing remaining assets")
			assembler.FlushAll()
			flushNow()
			return nil

		case <-ticker.C:
			// Evict half-open streams older than 2× the flush interval to
			// prevent the assembler's connection table from growing unboundedly.
			assembler.FlushOlderThan(time.Now().Add(-2 * flushInterval))
			flushNow()

		case <-buf.Full():
			log.Printf("INFO: sniffer buffer full (%d assets) — early flush", buf.Len())
			flushNow()

		case pkt, ok := <-packets:
			if !ok {
				return fmt.Errorf("pcap packet source closed unexpectedly")
			}
			s.packetsTotal.Add(1)
			tcpLayer := pkt.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				continue
			}
			tcp, _ := tcpLayer.(*layers.TCP)
			netLayer := pkt.NetworkLayer()
			if netLayer == nil {
				continue
			}
			assembler.Assemble(netLayer.NetworkFlow(), tcp)
		}
	}
}
