// Package sniffer implements passive TLS traffic capture using libpcap.
// buffer.go provides the thread-safe AssetBuffer used to accumulate
// discovered assets before periodic flushing to the CryptoSight API.
package sniffer

import (
	"sync"

	"github.com/cryptosight/probe/types"
)

// AssetBuffer accumulates DiscoveredAssets from captured TLS traffic.
// Assets are deduplicated by UID within a flush window so the same cert
// observed in multiple handshakes is sent to the server only once per
// flush interval.
type AssetBuffer struct {
	mu      sync.Mutex
	items   map[string]types.DiscoveredAsset // uid → asset (last-write wins)
	maxSize int
	fullCh  chan struct{} // receives one token when len(items) >= maxSize
}

// NewAssetBuffer creates a buffer that signals Full() when maxSize assets
// have accumulated.
func NewAssetBuffer(maxSize int) *AssetBuffer {
	return &AssetBuffer{
		items:   make(map[string]types.DiscoveredAsset),
		maxSize: maxSize,
		fullCh:  make(chan struct{}, 1),
	}
}

// Add inserts or replaces the asset for a given UID.
// It sends a single non-blocking token to Full() when the buffer reaches
// maxSize so the flush goroutine can trigger an early send.
func (b *AssetBuffer) Add(a types.DiscoveredAsset) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items[a.UID] = a
	if len(b.items) >= b.maxSize {
		select {
		case b.fullCh <- struct{}{}:
		default:
		}
	}
}

// Flush drains and returns all buffered assets, resetting the buffer.
// It also drains any pending Full() token so the next cycle starts clean.
func (b *AssetBuffer) Flush() []types.DiscoveredAsset {
	b.mu.Lock()
	out := make([]types.DiscoveredAsset, 0, len(b.items))
	for _, a := range b.items {
		out = append(out, a)
	}
	b.items = make(map[string]types.DiscoveredAsset)
	b.mu.Unlock()

	select {
	case <-b.fullCh:
	default:
	}
	return out
}

// Full returns the channel that receives a value when the buffer is full.
func (b *AssetBuffer) Full() <-chan struct{} { return b.fullCh }

// Len returns the current number of buffered unique assets.
func (b *AssetBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}
