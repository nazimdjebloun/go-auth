package redisstore

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/ratelimit"
	"github.com/redis/go-redis/v9"
)

func TestRedisOOMFailsClosed(t *testing.T) {
	addr := os.Getenv("GOAUTH_REDIS_OOM_ADDR")
	if addr == "" {
		t.Skip("isolated OOM server not selected")
	}
	c := redis.NewClient(&redis.Options{Addr: addr, ContextTimeoutEnabled: true, MaxRetries: -1, ReadTimeout: time.Second, WriteTimeout: time.Second})
	t.Cleanup(func() { _ = c.Close() })
	s, e := New(Config{Client: c, Prefix: "oom-test"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Allow(t.Context(), "budget", ratelimit.Rate{Requests: 1, Window: time.Minute}); e == nil {
		t.Fatal("out-of-memory counter write was allowed")
	}
}

func TestRedisCluster(t *testing.T) {
	addresses := os.Getenv("GOAUTH_REDIS_CLUSTER_ADDRS")
	if addresses == "" {
		t.Skip("cluster topology not selected")
	}
	c := redis.NewClusterClient(&redis.ClusterOptions{Addrs: strings.Split(addresses, ","), ContextTimeoutEnabled: true, MaxRetries: -1, DialTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second})
	t.Cleanup(func() { _ = c.Close() })
	s, e := New(Config{Client: c, Prefix: "cluster-test:" + uuid.NewString(), OperationTimeout: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Check(t.Context()); e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"one", "two", "three", "four", "five"} {
		for i := range 3 {
			v, e := s.Allow(t.Context(), key, ratelimit.Rate{Requests: 2, Window: time.Minute})
			if e != nil || v.Allowed != (i < 2) {
				t.Fatalf("cluster counter %s: %+v %v", key, v, e)
			}
		}
		if e = s.Put(t.Context(), key, []byte("snapshot"), time.Minute); e != nil {
			t.Fatal(e)
		}
		v, e := s.Get(t.Context(), key)
		if e != nil || string(v) != "snapshot" {
			t.Fatal(string(v), e)
		}
	}
}

func TestRedisSentinelFailover(t *testing.T) {
	addr := os.Getenv("GOAUTH_REDIS_SENTINEL_ADDR")
	if addr == "" {
		t.Skip("sentinel topology not selected")
	}
	name := "goauth"
	c := redis.NewFailoverClient(&redis.FailoverOptions{MasterName: name, SentinelAddrs: []string{addr}, ContextTimeoutEnabled: true, MaxRetries: -1, DialTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second})
	t.Cleanup(func() { _ = c.Close() })
	s, e := New(Config{Client: c, Prefix: "sentinel-test:" + uuid.NewString(), OperationTimeout: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Check(t.Context()); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Allow(t.Context(), "budget", ratelimit.Rate{Requests: 1, Window: time.Minute}); e != nil {
		t.Fatal(e)
	}
	replica := redis.NewClient(&redis.Options{Addr: os.Getenv("GOAUTH_REDIS_REPLICA_ADDR"), ContextTimeoutEnabled: true, MaxRetries: -1})
	t.Cleanup(func() { _ = replica.Close() })
	deadline := time.Now().Add(20 * time.Second)
	for {
		v, e := replica.Get(t.Context(), s.redisKey("counter", "budget")).Result()
		if e == nil && v == "1" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("replica did not receive initial budget", e)
		}
		time.Sleep(50 * time.Millisecond)
	}
	sentinel := redis.NewSentinelClient(&redis.Options{Addr: addr, ContextTimeoutEnabled: true, MaxRetries: -1})
	t.Cleanup(func() { _ = sentinel.Close() })
	old, e := sentinel.GetMasterAddrByName(t.Context(), name).Result()
	if e != nil {
		t.Fatal(e)
	}
	if e = sentinel.Failover(t.Context(), name).Err(); e != nil {
		t.Fatal(e)
	}
	deadline = time.Now().Add(25 * time.Second)
	for {
		current, e := sentinel.GetMasterAddrByName(t.Context(), name).Result()
		if e == nil && strings.Join(current, ":") != strings.Join(old, ":") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sentinel did not promote replica", e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	for {
		v, e := s.Allow(t.Context(), "budget", ratelimit.Rate{Requests: 1, Window: time.Minute})
		if e == nil {
			if v.Allowed {
				t.Fatal("replicated budget was lost")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("client did not reconnect after failover", e)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
