package sqlstore

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestConsumeIfValid_GuardsTokenIdentityAndState(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name      string
		input     port.ConsumeTokenInput
		expiresAt time.Time
		usedAt    *time.Time
		want      bool
	}{
		{
			name:      "exact live token",
			input:     resetTokenConsumeInput(now),
			expiresAt: now.Add(time.Hour),
			want:      true,
		},
		{
			name: "wrong id",
			input: func() port.ConsumeTokenInput {
				input := resetTokenConsumeInput(now)
				input.ID = "wrong"
				return input
			}(),
			expiresAt: now.Add(time.Hour),
		},
		{
			name: "wrong hash",
			input: func() port.ConsumeTokenInput {
				input := resetTokenConsumeInput(now)
				input.TokenHash = "wrong"
				return input
			}(),
			expiresAt: now.Add(time.Hour),
		},
		{
			name: "wrong user",
			input: func() port.ConsumeTokenInput {
				input := resetTokenConsumeInput(now)
				input.UserID = "wrong"
				return input
			}(),
			expiresAt: now.Add(time.Hour),
		},
		{
			name: "wrong type",
			input: func() port.ConsumeTokenInput {
				input := resetTokenConsumeInput(now)
				input.Type = domain.TokenVerifyEmail
				return input
			}(),
			expiresAt: now.Add(time.Hour),
		},
		{
			name:      "expired",
			input:     resetTokenConsumeInput(now),
			expiresAt: now.Add(-time.Second),
		},
		{
			name:      "already used",
			input:     resetTokenConsumeInput(now),
			expiresAt: now.Add(time.Hour),
			usedAt:    timePointer(now.Add(-time.Minute)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newSQLiteTestDB(t)
			if _, err := db.Exec(`
				CREATE TABLE verification_tokens (
					id TEXT PRIMARY KEY,
					user_id TEXT,
					token_hash TEXT NOT NULL,
					type TEXT NOT NULL,
					expires_at DATETIME NOT NULL,
					used_at DATETIME
				)
			`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`
				INSERT INTO verification_tokens (id, user_id, token_hash, type, expires_at, used_at)
				VALUES (?, ?, ?, ?, ?, ?)
			`, "token-id", "user-id", "token-hash", domain.TokenResetPass, tt.expiresAt, tt.usedAt); err != nil {
				t.Fatal(err)
			}

			repo := NewTokenRepository(db)
			consumed, err := repo.ConsumeIfValid(context.Background(), tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if consumed != tt.want {
				t.Fatalf("ConsumeIfValid() = %v, want %v", consumed, tt.want)
			}

			var storedUsedAt *time.Time
			if err := db.QueryRowContext(context.Background(),
				"SELECT used_at FROM verification_tokens WHERE id = ?", "token-id",
			).Scan(&storedUsedAt); err != nil {
				t.Fatal(err)
			}
			if tt.want && storedUsedAt == nil {
				t.Fatal("successful consumption did not stamp used_at")
			}
			if !tt.want && tt.usedAt == nil && storedUsedAt != nil {
				t.Fatal("rejected consumption changed used_at")
			}
		})
	}
}

func TestConsumeIfValid_IsSingleUse(t *testing.T) {
	db := newSQLiteTestDB(t)
	if _, err := db.Exec(`
		CREATE TABLE verification_tokens (
			id TEXT PRIMARY KEY,
			user_id TEXT,
			token_hash TEXT NOT NULL,
			type TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			used_at DATETIME
		)
	`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := db.Exec(`
		INSERT INTO verification_tokens (id, user_id, token_hash, type, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`, "token-id", "user-id", "token-hash", domain.TokenResetPass, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	repo := NewTokenRepository(db)
	input := resetTokenConsumeInput(now)
	first, err := repo.ConsumeIfValid(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := repo.ConsumeIfValid(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !first || second {
		t.Fatalf("consumption results = %v then %v, want true then false", first, second)
	}
}

func resetTokenConsumeInput(now time.Time) port.ConsumeTokenInput {
	return port.ConsumeTokenInput{
		ID:        "token-id",
		TokenHash: "token-hash",
		UserID:    "user-id",
		Type:      domain.TokenResetPass,
		UsedAt:    now,
	}
}

func timePointer(value time.Time) *time.Time {
	return &value
}
