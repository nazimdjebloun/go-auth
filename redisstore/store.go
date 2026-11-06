// Package redisstore provides bounded Redis snapshot and fixed-window counter
// adapters. Clients are always caller-owned. Stores have no background workers.
package redisstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/ratelimit"
	"github.com/redis/go-redis/v9"
)

// Config describes one isolated Redis namespace. Zero durations/sizes select
// defaults. Client must honor context deadlines and have finite socket timeouts.
type Config struct {
	Client           redis.UniversalClient
	Prefix           string
	Key              []byte
	OperationTimeout time.Duration
	MaxSnapshotBytes int
}

// Stats reports aggregate activity without including cache keys or identities.
type Stats struct {
	Allowed uint64 `json:"allowed"`
	Denied  uint64 `json:"denied"`
	Errors  uint64 `json:"errors"`
}

// Store implements disposable opaque snapshots and atomic fixed-window limits.
type Store struct {
	client                    redis.UniversalClient
	prefix                    string
	key                       []byte
	timeout                   time.Duration
	maxBytes                  int
	allowed, denied, failures atomic.Uint64
}

var _ port.SnapshotCache = (*Store)(nil)
var _ ratelimit.Store = (*Store)(nil)

// BackendError keeps client addresses and server-provided text out of ordinary
// logs while preserving the original cause for errors.Is/As and trusted tooling.
type BackendError struct {
	Operation string
	Cause     error
}

func (e *BackendError) Error() string { return "redisstore: " + e.Operation + " failed" }

// Unwrap exposes the infrastructure cause for programmatic classification.
func (e *BackendError) Unwrap() error { return e.Cause }

// New validates configuration without I/O. Closing the supplied client remains
// the caller's responsibility, including when construction or startup fails.
func New(cfg Config) (*Store, error) {
	if cfg.Client == nil {
		return nil, errors.New("redisstore: client is required")
	}
	v := reflect.ValueOf(cfg.Client)
	if (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) && v.IsNil() {
		return nil, errors.New("redisstore: client is required")
	}
	// A child context cannot bound socket I/O when the client ignores its
	// deadline. Validate the supported concrete clients without mutating them.
	var contexts bool
	var read, write time.Duration
	switch client := cfg.Client.(type) {
	case *redis.Client:
		o := client.Options()
		contexts, read, write = o.ContextTimeoutEnabled, o.ReadTimeout, o.WriteTimeout
	case *redis.ClusterClient:
		o := client.Options()
		contexts, read, write = o.ContextTimeoutEnabled, o.ReadTimeout, o.WriteTimeout
	default:
		return nil, errors.New("redisstore: use a redis Client, FailoverClient or ClusterClient")
	}
	if !contexts || read < 0 || write < 0 {
		return nil, errors.New("redisstore: client requires ContextTimeoutEnabled and finite socket timeouts")
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "goauth:v1"
	}
	if len(cfg.Prefix) > 160 || strings.ContainsAny(cfg.Prefix, "{}\r\n\x00") {
		return nil, errors.New("redisstore: invalid prefix")
	}
	if len(cfg.Key) != 0 && len(cfg.Key) < 32 {
		return nil, errors.New("redisstore: key must have at least 32 bytes")
	}
	if cfg.OperationTimeout == 0 {
		cfg.OperationTimeout = 250 * time.Millisecond
	}
	if cfg.MaxSnapshotBytes == 0 {
		cfg.MaxSnapshotBytes = 256 * 1024
	}
	if cfg.OperationTimeout <= 0 || cfg.MaxSnapshotBytes < 1024 || cfg.MaxSnapshotBytes > 16*1024*1024 {
		return nil, errors.New("redisstore: invalid timeout or snapshot size")
	}
	return &Store{client: cfg.Client, prefix: cfg.Prefix, key: append([]byte(nil), cfg.Key...), timeout: cfg.OperationTimeout, maxBytes: cfg.MaxSnapshotBytes}, nil
}

func (s *Store) redisKey(kind, key string) string {
	var digest []byte
	if len(s.key) > 0 {
		h := hmac.New(sha256.New, s.key)
		_, _ = h.Write([]byte(key))
		digest = h.Sum(nil)
	} else {
		h := sha256.Sum256([]byte(key))
		digest = h[:]
	}
	return s.prefix + ":" + kind + ":" + hex.EncodeToString(digest)
}

// Stats returns a concurrency-safe counter snapshot.
func (s *Store) Stats() Stats { return Stats{s.allowed.Load(), s.denied.Load(), s.failures.Load()} }

var boundedGet = redis.NewScript(`
local n=redis.call('STRLEN',KEYS[1])
if n>tonumber(ARGV[1]) then return redis.error_reply('snapshot too large') end
return redis.call('GET',KEYS[1])
`)

// Get returns an opaque snapshot or nil on a miss. Oversized values are never
// transferred to the application. Callers must authenticate snapshot contents.
func (s *Store) Get(ctx context.Context, key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	v, err := boundedGet.Run(ctx, s.client, []string{s.redisKey("cache", key)}, s.maxBytes).Text()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, &BackendError{Operation: "snapshot read", Cause: err}
	}
	return []byte(v), nil
}

// Put inserts one immutable, bounded snapshot without extending an existing TTL.
func (s *Store) Put(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if len(value) > s.maxBytes || ttl <= 0 {
		return errors.New("redisstore: invalid snapshot size or ttl")
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	if err := s.client.SetNX(ctx, s.redisKey("cache", key), value, ttl).Err(); err != nil {
		return &BackendError{Operation: "snapshot write", Cause: err}
	}
	return nil
}

var fixedWindow = redis.NewScript(`
local limit=tonumber(ARGV[1])
local window=tonumber(ARGV[2])
local raw=redis.call('GET',KEYS[1])
local count=0
if raw then
  count=tonumber(raw)
  if not count or count<1 or count~=math.floor(count) or count>2147483648 then return redis.error_reply('invalid counter') end
  if redis.call('PTTL',KEYS[1])<0 then return redis.error_reply('counter has no ttl') end
end
if count==0 then
  count=1
  redis.call('SET',KEYS[1],count,'PX',window)
elseif count<limit+1 then
  count=redis.call('INCR',KEYS[1])
end
local now=redis.call('TIME')
return {count,redis.call('PTTL',KEYS[1]),now[1],now[2]}
`)

// Allow counts the request in an anchored fixed window. One key must always use
// the same Rate. Denied counts saturate above the limit to avoid numeric overflow;
// all observable decisions still include the current call. No application retry
// is made after an ambiguous network failure.
func (s *Store) Allow(ctx context.Context, key string, rate ratelimit.Rate) (ratelimit.Result, error) {
	if rate.Requests < 1 || rate.Requests > math.MaxInt32 || rate.Window <= 0 {
		return ratelimit.Result{}, errors.New("redisstore: invalid rate")
	}
	ms := rate.Window / time.Millisecond
	if rate.Window%time.Millisecond != 0 {
		ms++
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	values, err := fixedWindow.Run(ctx, s.client, []string{s.redisKey("counter", key)}, rate.Requests, int64(ms)).Int64Slice()
	if err != nil {
		s.failures.Add(1)
		return ratelimit.Result{}, &BackendError{Operation: "counter", Cause: err}
	}
	if len(values) != 4 || values[0] < 1 || values[1] < 0 || values[1] > int64(ms) || values[2] < 0 || values[3] < 0 || values[3] >= 1000000 {
		s.failures.Add(1)
		return ratelimit.Result{}, errors.New("redisstore: invalid counter response")
	}
	allowed := values[0] <= int64(rate.Requests)
	remaining := max(int64(rate.Requests)-values[0], 0)
	if allowed {
		s.allowed.Add(1)
	} else {
		s.denied.Add(1)
	}
	return ratelimit.Result{Allowed: allowed, Remaining: int(remaining), ResetAt: time.Unix(values[2], values[3]*1000).Add(time.Duration(values[1]) * time.Millisecond)}, nil
}

// Check exercises the actual snapshot and counter commands under an expiring
// random probe key, including script permissions. It never resets live budgets.
func (s *Store) Check(ctx context.Context) error {
	probe := "probe:" + uuid.NewString()
	if err := s.Put(ctx, probe, []byte("ready"), time.Second); err != nil {
		return err
	}
	v, err := s.Get(ctx, probe)
	if err != nil {
		return err
	}
	if string(v) != "ready" {
		return errors.New("redisstore: failed snapshot probe")
	}
	_, err = s.Allow(ctx, probe, ratelimit.Rate{Requests: 1, Window: time.Second})
	return err
}
