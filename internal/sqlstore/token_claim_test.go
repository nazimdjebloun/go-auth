package sqlstore

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestConsumeIfValidUnderCapGuardsEveryPredicate(t *testing.T) {
	for _, name := range []string{"valid", "hash", "user", "type", "expiry", "used", "cap"} {
		t.Run(name, func(t *testing.T) {
			raw := testdb.OpenSelected(t)
			testdb.Apply(t, raw)
			db := NewDB(raw, testdb.Driver(raw))
			now := time.Now().UTC().Truncate(time.Second)
			expires := now.Add(time.Minute)
			var used *time.Time
			attempts := 0
			input := port.ConsumeTokenInput{ID: "00000000-0000-4000-8000-000000000041", UserID: "00000000-0000-4000-8000-000000000042", TokenHash: "hash", Type: domain.TokenTwoFactor, UsedAt: now}
			switch name {
			case "hash":
				input.TokenHash = "old hash"
			case "user":
				input.UserID = "00000000-0000-4000-8000-000000000043"
			case "type":
				input.Type = domain.TokenResetPass
			case "expiry":
				expires = now
			case "used":
				used = &now
			case "cap":
				attempts = 5
			}
			if _, err := db.ExecContext(t.Context(), "INSERT INTO users (id,email,name,created_at,updated_at) VALUES ($1,$2,$3,$4,$5)", "00000000-0000-4000-8000-000000000042", "token@example.com", "Token", now, now); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(t.Context(), "INSERT INTO verification_tokens (id,user_id,email,token_hash,type,expires_at,used_at,attempts,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)", "00000000-0000-4000-8000-000000000041", "00000000-0000-4000-8000-000000000042", "token@example.com", "hash", domain.TokenTwoFactor, expires, used, attempts, now); err != nil {
				t.Fatal(err)
			}
			claimed, err := NewTokenRepository(db).ConsumeIfValidUnderCap(context.Background(), input, 5)
			if err != nil || claimed != (name == "valid") {
				t.Fatalf("claim=%v err=%v", claimed, err)
			}
			if claimed {
				second, err := NewTokenRepository(db).ConsumeIfValidUnderCap(context.Background(), input, 5)
				if err != nil || second {
					t.Fatalf("replayed claim=%v err=%v", second, err)
				}
			}
		})
	}
}
