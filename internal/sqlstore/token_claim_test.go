package sqlstore

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestConsumeIfValidUnderCapGuardsEveryPredicate(t *testing.T) {
	for _, name := range []string{"valid", "hash", "user", "type", "expiry", "used", "cap"} {
		t.Run(name, func(t *testing.T) {
			db := newSQLiteTestDB(t)
			if _, err := db.Exec(`CREATE TABLE verification_tokens (
				id TEXT PRIMARY KEY,user_id TEXT,token_hash TEXT,type TEXT,
				expires_at DATETIME,used_at DATETIME,attempts INTEGER)`); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			expires := now.Add(time.Minute)
			var used *time.Time
			attempts := 0
			input := port.ConsumeTokenInput{ID: "token", UserID: "user", TokenHash: "hash", Type: domain.TokenTwoFactor, UsedAt: now}
			switch name {
			case "hash":
				input.TokenHash = "old hash"
			case "user":
				input.UserID = "other"
			case "type":
				input.Type = domain.TokenResetPass
			case "expiry":
				expires = now
			case "used":
				used = &now
			case "cap":
				attempts = 5
			}
			if _, err := db.Exec("INSERT INTO verification_tokens VALUES (?,?,?,?,?,?,?)",
				"token", "user", "hash", domain.TokenTwoFactor, expires, used, attempts); err != nil {
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
