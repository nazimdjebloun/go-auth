package ratelimit

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// The default in-memory store is a sharded, bounded, fixed-window counter.
//
// Bounded is the load-bearing word. Rate-limit keys are derived from client
// input (the client IP, and the route the request landed on), so an
// unbounded map of them is a memory-exhaustion primitive: anything that lets
// a caller mint a fresh key per request lets them grow the map for as long
// as they keep sending. The middleware closes the route half of that by
// keying on the matched route *pattern* rather than the raw path; this file
// closes the rest by refusing to hold more than maxEntries counters at once,
// so even a genuine botnet with a large IP pool costs a fixed amount of RAM.
//
// Sharded because the cap has to be enforced on every insert, and a single
// mutex over a single map turns every request into a queue behind that
// enforcement — and turns the periodic expiry sweep into a stall for the
// whole process.
const (
	// defaultMaxEntries is roughly 10–15 MB of counters. Well past what a
	// single instance sees in legitimate traffic, small enough that filling
	// it is not an outage.
	defaultMaxEntries = 100_000

	// shardCount is fixed rather than configurable: it trades lock
	// contention against per-shard cap granularity, and neither end of that
	// trade is something a consumer has the information to tune.
	shardCount = 32

	// evictionSampleK bounds the work an insert into a full shard can do.
	// A full scan for the best victim would make every request during a
	// flood O(shard size) under the shard lock — the flood would pay for
	// itself in latency for everyone else. Sampling K entries approximates
	// the same choice in constant time; Go randomizes map iteration order,
	// so the sample is a real sample and needs no RNG.
	evictionSampleK = 8

	sweepInterval = time.Minute
)

// Stats is a snapshot of a memory store's occupancy and eviction activity.
// Eviction is silent by nature — a dropped counter looks exactly like a
// counter that never existed — so shipping it without a way to observe it
// would mean an operator's first signal is an unexplained rate-limit bypass.
type Stats struct {
	Entries int // live counters held right now

	// Capacity is the store's true ceiling, which is not necessarily the
	// number passed to WithMaxEntries: the cap is enforced per shard, so the
	// requested total is divided by shardCount and rounded down (with a floor
	// of one per shard). WithMaxEntries(100_000) divides evenly; a value that
	// doesn't, or one below shardCount, does not. Reporting the request
	// rather than the ceiling would make this field lie about the one thing
	// it exists to answer. 0 when eviction is disabled.
	//
	// Even this is an upper bound, not a reachable occupancy. Keys are
	// distributed across shards by hash, so a hot shard reaches its own cap
	// and starts evicting while others still have room — real steady-state
	// occupancy sits below Capacity. It can never exceed it, which is the
	// direction that matters for a memory ceiling.
	Capacity int

	Evictions uint64 // live counters dropped to make room since construction
	Expired   uint64 // counters removed because their window ended
}

// MemoryStoreOption configures NewMemoryStore.
type MemoryStoreOption func(*memoryOptions)

type memoryOptions struct {
	maxEntries int
	logger     *slog.Logger
}

// WithMaxEntries caps how many counters the store retains. Once full, an
// insert evicts one existing counter (see evict). The default is 100,000;
// raise it if a single instance legitimately serves more distinct clients
// than that within one rate-limit window.
//
// n is a target, not an exact ceiling: it's divided across shardCount shards
// and rounded down, so a value that isn't a multiple of shardCount honours
// slightly less than asked (and a value below shardCount honours one per
// shard, i.e. shardCount total). Stats().Capacity reports what the store
// actually enforces.
func WithMaxEntries(n int) MemoryStoreOption {
	return func(o *memoryOptions) { o.maxEntries = n }
}

// WithoutEviction removes the cap, making the store grow with its key space.
//
// This is safe only for a *closed* key space — one where the set of possible
// keys is bounded by something other than how many requests a caller can
// send. The 2FA notify counter qualifies (one key per account that has
// recently failed a second factor). A key derived from client IPs does not:
// use this on the rate-limit store and the store is a memory-exhaustion
// target again.
func WithoutEviction() MemoryStoreOption {
	return func(o *memoryOptions) { o.maxEntries = 0 }
}

// WithStoreLogger sets the logger used for the at-capacity warning. Defaults
// to slog.Default().
func WithStoreLogger(l *slog.Logger) MemoryStoreOption {
	return func(o *memoryOptions) { o.logger = l }
}

type memoryStore struct {
	shards   [shardCount]*shard
	perShard int // per-shard cap; 0 = unbounded
	capacity int // perShard*shardCount — the true ceiling, see Stats.Capacity
	log      *slog.Logger

	cancel context.CancelFunc
	done   chan struct{}

	evictions atomic.Uint64
	expired   atomic.Uint64
	lastWarn  atomic.Int64 // unix nanos of the last at-capacity warning
}

type shard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	count   int
	limit   int // this window's limit, kept so eviction can rank by headroom
	resetAt time.Time
}

func NewMemoryStore(opts ...MemoryStoreOption) Store {
	o := memoryOptions{maxEntries: defaultMaxEntries}
	for _, opt := range opts {
		opt(&o)
	}
	if o.logger == nil {
		o.logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &memoryStore{
		log:    o.logger,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	// The requested total is enforced per shard, so the ceiling the store
	// actually honours is perShard*shardCount, not o.maxEntries. Resolve that
	// once here and report it everywhere (Stats, the at-capacity warning)
	// rather than echoing back the request.
	if o.maxEntries > 0 {
		s.perShard = o.maxEntries / shardCount
		if s.perShard < 1 {
			s.perShard = 1
		}
		s.capacity = s.perShard * shardCount
	}
	for i := range s.shards {
		s.shards[i] = &shard{buckets: make(map[string]*bucket)}
	}
	go s.cleanup(ctx)
	return s
}

// StoreCloser is an optional capability a Store can implement to release
// background resources (e.g. a cleanup goroutine). It's a separate
// interface from Store, not an addition to it, so a consumer-provided Store
// (Redis-backed or otherwise) that has nothing to close isn't forced to grow
// a no-op method — Auth.Close checks for it via a type assertion.
type StoreCloser interface {
	Close()
}

var _ StoreCloser = (*memoryStore)(nil)

// Close stops the background cleanup goroutine. Safe to call once; the
// store remains readable/writable after Close (Allow/Reset don't depend
// on cleanup running), it just stops pruning expired buckets.
func (s *memoryStore) Close() {
	s.cancel()
	<-s.done
}

// IsDefaultStore reports whether s is a Store returned by NewMemoryStore —
// used by Auth.New to warn that rate limiting doesn't share state across
// instances. This matches by type, not by construction site: a store built
// via an explicit WithRateLimitStore(ratelimit.NewMemoryStore()) matches
// too, since the underlying multi-instance caveat is identical either way —
// only a genuinely different Store implementation (e.g. Redis-backed)
// avoids the warning.
func IsDefaultStore(s Store) bool {
	_, ok := s.(*memoryStore)
	return ok
}

// Stats reports occupancy and eviction counts. Only the concrete in-memory
// store implements it; reach it with a type assertion:
//
//	if st, ok := store.(interface{ Stats() ratelimit.Stats }); ok { ... }
func (s *memoryStore) Stats() Stats {
	entries := 0
	for _, sh := range s.shards {
		sh.mu.Lock()
		entries += len(sh.buckets)
		sh.mu.Unlock()
	}
	return Stats{
		Entries:   entries,
		Capacity:  s.capacity,
		Evictions: s.evictions.Load(),
		Expired:   s.expired.Load(),
	}
}

// Allow implements Store, including its "one key, one Rate" requirement: the
// window end is fixed when a counter is created and the limit is refreshed on
// every call, so passing two different Rates for one key leaves both derived
// from whichever call came first (window) or last (limit). The returned
// decision always uses the Rate passed to this call.
//
// ctx is ignored — nothing here blocks or does I/O, so there is nothing to
// abandon. A Store doing real I/O should honour it; see Store's contract for
// the client-disconnect caveat.
func (s *memoryStore) Allow(_ context.Context, key string, rate Rate) (Result, error) {
	sh := s.shards[shardIndex(key)]
	now := time.Now()

	sh.mu.Lock()
	b, ok := sh.buckets[key]
	if !ok || now.After(b.resetAt) {
		if !ok && s.perShard > 0 && len(sh.buckets) >= s.perShard {
			s.evict(sh, now)
		}
		b = &bucket{resetAt: now.Add(rate.Window)}
		sh.buckets[key] = b
	}
	b.count++
	b.limit = rate.Requests
	count, resetAt := b.count, b.resetAt
	sh.mu.Unlock()

	remaining := rate.Requests - count
	if remaining < 0 {
		remaining = 0
	}
	return Result{Allowed: count <= rate.Requests, Remaining: remaining, ResetAt: resetAt}, nil
}

// evict frees one slot in a full shard. The caller holds sh.mu.
//
// It walks a bounded sample. An expired counter found along the way wins
// immediately — it is dead weight and dropping it costs nothing. Otherwise
// the victim is the sampled entry with the most budget left (limit - count),
// tie-broken toward the one expiring soonest.
//
// Ranking by headroom is the security property, not a tuning detail: an
// eviction policy an attacker can steer is a rate-limit bypass in the same
// way an unbounded map is a memory leak. Rank by earliest expiry and a flood
// of long-window junk evicts exactly the short-window login counters you
// most need to keep — the attacker chooses what gets forgotten. Under
// headroom-descending the flood's own count=1 entries are the *preferred*
// victims, so a flood mostly evicts itself, and displacing a counter that is
// close to tripping costs a full `limit` requests per decoy rather than one.
func (s *memoryStore) evict(sh *shard, now time.Time) {
	victim := ""
	bestHeadroom := -1
	var bestResetAt time.Time

	seen := 0
	for k, b := range sh.buckets {
		if now.After(b.resetAt) {
			delete(sh.buckets, k)
			s.expired.Add(1)
			return
		}
		headroom := b.limit - b.count
		if headroom < 0 {
			headroom = 0
		}
		if victim == "" || headroom > bestHeadroom ||
			(headroom == bestHeadroom && b.resetAt.Before(bestResetAt)) {
			victim, bestHeadroom, bestResetAt = k, headroom, b.resetAt
		}
		if seen++; seen >= evictionSampleK {
			break
		}
	}

	if victim != "" {
		delete(sh.buckets, victim)
		s.evictions.Add(1)
		s.warnAtCapacity()
	}
}

// warnAtCapacity logs at most once a minute. Eviction fires per request once
// the store is full, so an unthrottled warning would turn a flood into a
// second flood, this one aimed at the log pipeline.
func (s *memoryStore) warnAtCapacity() {
	if s.log == nil {
		return
	}
	now := time.Now().UnixNano()
	last := s.lastWarn.Load()
	if now-last < int64(time.Minute) {
		return
	}
	if !s.lastWarn.CompareAndSwap(last, now) {
		return // another goroutine is logging this one
	}
	s.log.Warn("goauth: rate-limit store is at capacity and is evicting live counters",
		"capacity", s.capacity,
		"evictions", s.evictions.Load(),
		"fix", "raise the cap with ratelimit.NewMemoryStore(ratelimit.WithMaxEntries(n)), or move to a shared store (e.g. Redis) via WithRateLimitStore")
}

func (s *memoryStore) cleanup(ctx context.Context) {
	defer close(s.done)
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweep(time.Now())
		}
	}
}

// sweep drops expired counters one shard at a time, releasing each shard's
// lock before taking the next. Eviction alone keeps the store bounded; the
// sweep is what keeps it *small* under normal traffic, so the cap is a
// backstop rather than the steady state.
func (s *memoryStore) sweep(now time.Time) {
	for _, sh := range s.shards {
		sh.mu.Lock()
		removed := 0
		for k, b := range sh.buckets {
			if now.After(b.resetAt) {
				delete(sh.buckets, k)
				removed++
			}
		}
		sh.mu.Unlock()
		if removed > 0 {
			s.expired.Add(uint64(removed))
		}
	}
}

// shardIndex is FNV-1a, written out rather than taken from hash/fnv so it
// allocates nothing on a path that runs once per request.
func shardIndex(key string) int {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= prime32
	}
	return int(h % shardCount)
}
