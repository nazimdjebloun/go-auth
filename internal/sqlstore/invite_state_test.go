package sqlstore

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

func TestInviteTransitionsPreserveTerminalStates(t *testing.T) {
	for _, status := range []domain.InviteStatus{domain.InvitePending, domain.InviteExpired, domain.InviteAccepted, domain.InviteRevoked} {
		for _, operation := range []string{"resend", "revoke"} {
			t.Run(string(status)+"/"+operation, func(t *testing.T) {
				db := newSQLiteTestDB(t)
				if _, err := db.Exec("CREATE TABLE invites (id TEXT PRIMARY KEY,code TEXT,status TEXT,expires_at DATETIME,accepted_at DATETIME)"); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec("INSERT INTO invites (id,code,status,expires_at) VALUES (?,?,?,?)", "invite", "old", status, time.Now()); err != nil {
					t.Fatal(err)
				}
				repo := NewInviteRepository(db)
				var changed bool
				var err error
				if operation == "resend" {
					changed, err = repo.RotateCode(context.Background(), "invite", "old", "new", time.Now().Add(time.Hour))
				} else {
					changed, err = repo.Revoke(context.Background(), "invite")
				}
				want := status == domain.InvitePending || status == domain.InviteExpired
				if err != nil || changed != want {
					t.Fatalf("changed=%v err=%v want=%v", changed, err, want)
				}
				if operation == "resend" && changed {
					second, err := repo.RotateCode(context.Background(), "invite", "old", "stale", time.Now().Add(time.Hour))
					if err != nil || second {
						t.Fatalf("stale resend changed=%v err=%v", second, err)
					}
					oldClaim, err := repo.ClaimInvite(context.Background(), "old", time.Now())
					if err != nil || oldClaim {
						t.Fatalf("old code redeemed: %v, %v", oldClaim, err)
					}
				}
			})
		}
	}
}
