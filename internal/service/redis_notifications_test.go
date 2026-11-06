package service_test

import (
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/redisstore"
	"github.com/redis/go-redis/v9"
)

func TestRedisTwoFactorSharedNotifications(t *testing.T) {
	addr := os.Getenv("GOAUTH_REDIS_TEST_ADDR")
	if addr == "" {
		t.Skip("Redis notification integration not selected")
	}
	client := redis.NewClient(&redis.Options{Addr: addr, ContextTimeoutEnabled: true, MaxRetries: -1, ReadTimeout: time.Second, WriteTimeout: time.Second})
	t.Cleanup(func() { _ = client.Close() })
	prefix := "notification-test:" + uuid.NewString()
	stores := make([]*redisstore.Store, 2)
	for i := range stores {
		var err error
		stores[i], err = redisstore.New(redisstore.Config{Client: client, Prefix: prefix})
		if err != nil {
			t.Fatal(err)
		}
	}
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	mail := &testutil.MockMailer{}
	u := newTwoFactorUser(users, "shared@example.test")
	cfg := newTwoFactorConfig()
	cfg.DisableTwoFactorChallengeBinding = true
	services := make([]*service.TwoFactorService, 2)
	for i := range services {
		services[i] = service.NewTwoFactorService(&testutil.MockTxManager{}, users, nil, tokens, &testutil.MockHasher{}, mail, stores[i], cfg, nil)
	}
	challenge, err := services[0].Challenge(t.Context(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	wrong := wrongTwoFactorCode(lastTwoFactorCode(t, mail))
	for i := range 24 {
		if _, err = services[i%2].Verify(t.Context(), api.TwoFactorVerifyInput{ChallengeID: challenge.ID, Code: wrong}); err == nil {
			t.Fatal("wrong code issued a session")
		}
	}
	if mail.SentCount() != 2 {
		t.Fatalf("expected challenge and one shared suspicious notification; sent %d", mail.SentCount())
	}
}
