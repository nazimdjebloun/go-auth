package sqlstore

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/nazimdjebloun/go-auth/internal/crypto"
	"github.com/nazimdjebloun/go-auth/port"
)

// SnapshotStats reports disposable-cache activity, without identifiers.
type SnapshotStats struct {
	Hits, Misses, Errors, Writes uint64
}

// SnapshotCache authenticates opaque, version-bound records. It never decides
// whether a credential is current; the repository must resolve that in SQL.
type SnapshotCache struct {
	store                        port.SnapshotCache
	enc                          *crypto.Encryptor
	ttl                          time.Duration
	maxBytes                     int
	hits, misses, errors, writes atomic.Uint64
}

type snapshotEnvelope struct {
	Codec   int             `json:"codec"`
	Kind    string          `json:"kind"`
	ID      string          `json:"id"`
	Version string          `json:"version"`
	Data    json.RawMessage `json:"data"`
}

// NewSnapshotCache builds a purpose-keyed cache during application wiring.
func NewSnapshotCache(store port.SnapshotCache, key []byte, ttl time.Duration, maxBytes int) (*SnapshotCache, error) {
	enc, err := crypto.NewEncryptor(key)
	if err != nil {
		return nil, err
	}
	if store == nil || ttl <= 0 || maxBytes < 1024 {
		return nil, fmt.Errorf("invalid snapshot cache settings")
	}
	return &SnapshotCache{store: store, enc: enc, ttl: ttl, maxBytes: maxBytes}, nil
}

// Stats is safe to read while requests are running.
func (c *SnapshotCache) Stats() SnapshotStats {
	return SnapshotStats{c.hits.Load(), c.misses.Load(), c.errors.Load(), c.writes.Load()}
}

func snapshotKey(kind, id, version string) string { return kind + ":" + id + ":" + version }

func readSnapshot[T any](ctx context.Context, c *SnapshotCache, kind, id, version string) (*T, bool) {
	if version == "" || version == "legacy" {
		c.misses.Add(1)
		return nil, false
	}
	raw, err := c.store.Get(ctx, snapshotKey(kind, id, version))
	if err != nil {
		c.errors.Add(1)
		return nil, false
	}
	if len(raw) == 0 {
		c.misses.Add(1)
		return nil, false
	}
	if len(raw) > c.maxBytes {
		c.errors.Add(1)
		return nil, false
	}
	plain, err := c.enc.Decrypt(string(raw))
	if err != nil {
		c.errors.Add(1)
		return nil, false
	}
	var env snapshotEnvelope
	if json.Unmarshal([]byte(plain), &env) != nil || env.Codec != 1 || env.Kind != kind || env.ID != id || env.Version != version {
		c.errors.Add(1)
		return nil, false
	}
	var value T
	if len(env.Data) == 0 || string(env.Data) == "null" || json.Unmarshal(env.Data, &value) != nil {
		c.errors.Add(1)
		return nil, false
	}
	c.hits.Add(1)
	return &value, true
}

func writeSnapshot(ctx context.Context, c *SnapshotCache, kind, id, version string, value any) {
	if version == "" || version == "legacy" {
		return
	}
	data, err := json.Marshal(value)
	if err != nil {
		c.errors.Add(1)
		return
	}
	plain, err := json.Marshal(snapshotEnvelope{Codec: 1, Kind: kind, ID: id, Version: version, Data: data})
	if err != nil || len(plain) > c.maxBytes/2 {
		c.errors.Add(1)
		return
	}
	sealed, err := c.enc.Encrypt(string(plain))
	if err != nil || len(sealed) > c.maxBytes {
		c.errors.Add(1)
		return
	}
	if err = c.store.Put(ctx, snapshotKey(kind, id, version), []byte(sealed), c.ttl); err != nil {
		c.errors.Add(1)
		return
	}
	c.writes.Add(1)
}
