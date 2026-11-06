package redisstore

import (
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/ratelimit"
	"github.com/redis/go-redis/v9"
)

func liveStore(t *testing.T) (*Store, *redis.Client) {
	t.Helper()
	addr := os.Getenv("GOAUTH_REDIS_TEST_ADDR")
	if addr == "" {
		t.Skip("GOAUTH_REDIS_TEST_ADDR not selected")
	}
	c := redis.NewClient(&redis.Options{Addr: addr, MaxRetries: -1, ContextTimeoutEnabled: true, DialTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second})
	t.Cleanup(func() { _ = c.Close() })
	s, e := New(Config{Client: c, Prefix: "goauth-test:" + uuid.NewString(), Key: []byte(strings.Repeat("k", 32)), OperationTimeout: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Check(t.Context()); e != nil {
		t.Fatal("selected Redis is unavailable", e)
	}
	return s, c
}

func TestRedisOperationDeadline(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		<-stop
	})
	t.Cleanup(func() { close(stop); _ = listener.Close(); wg.Wait() })
	c := redis.NewClient(&redis.Options{Addr: listener.Addr().String(), ContextTimeoutEnabled: true, MaxRetries: -1, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second})
	t.Cleanup(func() { _ = c.Close() })
	s, e := New(Config{Client: c, OperationTimeout: 30 * time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	started := time.Now()
	_, e = s.Allow(t.Context(), "hung", ratelimit.Rate{Requests: 1, Window: time.Second})
	if e == nil || time.Since(started) > 2*time.Second {
		t.Fatal("operation deadline did not bound a stalled peer", e)
	}
}

func TestRedisRestrictedACL(t *testing.T) {
	s, admin := liveStore(t)
	ctx := t.Context()
	user := "goauth-test-" + uuid.NewString()
	password := uuid.NewString()
	if e := admin.ACLSetUser(ctx, user, "on", ">"+password, "~"+s.prefix+":*", "+@connection", "+eval", "+evalsha", "+get", "+set", "+strlen", "+pttl", "+time").Err(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if e := admin.ACLDelUser(ctx, user).Err(); e != nil {
			t.Error(e)
		}
	})
	c := redis.NewClient(&redis.Options{Addr: admin.Options().Addr, Username: user, Password: password, ContextTimeoutEnabled: true, MaxRetries: -1, ReadTimeout: time.Second, WriteTimeout: time.Second})
	t.Cleanup(func() { _ = c.Close() })
	limited, e := New(Config{Client: c, Prefix: s.prefix, Key: s.key, OperationTimeout: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	if v, e := limited.Allow(ctx, "acl", ratelimit.Rate{Requests: 2, Window: time.Minute}); e != nil || !v.Allowed {
		t.Fatal("initial SET should be permitted", e)
	}
	if _, e = limited.Allow(ctx, "acl", ratelimit.Rate{Requests: 2, Window: time.Minute}); e == nil {
		t.Fatal("INCR permission denial failed open")
	}
}

func TestRedisConfiguration(t *testing.T) {
	var nilClient *redis.Client
	client := redis.NewClient(&redis.Options{Addr: "unused:1", ContextTimeoutEnabled: true})
	t.Cleanup(func() { _ = client.Close() })
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"missing", Config{}}, {"typed nil", Config{Client: nilClient}}, {"hash tag", Config{Client: client, Prefix: "{all}"}}, {"short key", Config{Client: client, Key: []byte("x")}}, {"negative timeout", Config{Client: client, OperationTimeout: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := New(tc.cfg); e == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}

func TestRedisGlobalFixedWindow(t *testing.T) {
	s, c := liveStore(t)
	other, e := New(Config{Client: c, Prefix: s.prefix, Key: s.key, OperationTimeout: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	rate := ratelimit.Rate{Requests: 13, Window: time.Second}
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			store := s
			if i%2 == 0 {
				store = other
			}
			v, e := store.Allow(t.Context(), "shared", rate)
			if e != nil {
				t.Error(e)
				return
			}
			if v.Allowed {
				allowed.Add(1)
			}
			if v.Remaining < 0 {
				t.Error("negative remaining")
			}
		})
	}
	wg.Wait()
	if allowed.Load() != 13 {
		t.Fatalf("global allowed=%d, want 13", allowed.Load())
	}
	first, e := s.Allow(t.Context(), "expiry", ratelimit.Rate{Requests: 2, Window: 100 * time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	second, e := other.Allow(t.Context(), "expiry", ratelimit.Rate{Requests: 2, Window: 100 * time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	if first.ResetAt.Sub(second.ResetAt).Abs() > 2*time.Millisecond {
		t.Fatal("window slid")
	}
	time.Sleep(120 * time.Millisecond)
	third, e := s.Allow(t.Context(), "expiry", ratelimit.Rate{Requests: 2, Window: 100 * time.Millisecond})
	if e != nil || !third.Allowed || third.Remaining != 1 {
		t.Fatal(third, e)
	}
}

func TestRedisSnapshotBoundsAndCounterCorruption(t *testing.T) {
	s, c := liveStore(t)
	ctx := t.Context()
	if e := s.Put(ctx, "record", []byte("first"), time.Second); e != nil {
		t.Fatal(e)
	}
	if e := s.Put(ctx, "record", []byte("second"), time.Second); e != nil {
		t.Fatal(e)
	}
	v, e := s.Get(ctx, "record")
	if e != nil || string(v) != "first" {
		t.Fatal(string(v), e)
	}
	if e = c.Set(ctx, s.redisKey("cache", "large"), strings.Repeat("x", s.maxBytes+1), time.Second).Err(); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Get(ctx, "large"); e == nil {
		t.Fatal("accepted oversized snapshot")
	}
	for _, value := range []string{"3", "garbage", "2147483649"} {
		if e = c.Set(ctx, s.redisKey("counter", "bad"), value, 0).Err(); e != nil {
			t.Fatal(e)
		}
		if _, e = s.Allow(ctx, "bad", ratelimit.Rate{Requests: 5, Window: time.Second}); e == nil {
			t.Fatal("repaired invalid counter silently")
		}
	}
	if e = c.Del(ctx, s.redisKey("counter", "bad")).Err(); e != nil {
		t.Fatal(e)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = s.Allow(canceled, "abandoned", ratelimit.Rate{Requests: 1, Window: time.Second}); e == nil {
		t.Fatal("ignored cancellation")
	}
}
