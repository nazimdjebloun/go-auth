package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

type inviteGenerationBoundary struct {
	port.TokenGenerator
	before func() error
}

func (g *inviteGenerationBoundary) Generate() (string, error) {
	if g.before != nil {
		before := g.before
		g.before = nil
		if err := before(); err != nil {
			return "", err
		}
	}
	return g.TokenGenerator.Generate()
}

type inviteExpiryReadBoundary struct {
	port.InviteRepository
	after func() error
}

func (r *inviteExpiryReadBoundary) GetByCode(ctx context.Context, code string) (*domain.Invite, error) {
	invite, err := r.InviteRepository.GetByCode(ctx, code)
	if err != nil {
		return nil, err
	}
	if r.after != nil {
		after := r.after
		r.after = nil
		if err := after(); err != nil {
			return nil, err
		}
	}
	return invite, nil
}

func TestInviteRevocationCannotBeOverwrittenByResendOrExpiryRead(t *testing.T) {
	for _, name := range []string{"resend", "expiry read"} {
		t.Run(name, func(t *testing.T) {
			f := newPasswordTransactionFixture(t)
			ctx := context.Background()
			if _, err := f.db.ExecContext(context.Background(), "UPDATE users SET role = 'admin' WHERE id = $1", f.userID); err != nil {
				t.Fatal(err)
			}
			repo := sqlstore.NewInviteRepository(f.db)
			now := time.Now().UTC()
			expires := now.Add(time.Hour)
			if name == "expiry read" {
				expires = now.Add(-time.Hour)
			}
			invite := &domain.Invite{ID: "00000000-0000-4000-8000-000000000050", Email: "invitee@example.com", Code: hashToken("old-code"),
				CreatedBy: f.userID, Status: domain.InvitePending, ExpiresAt: expires, CreatedAt: now}
			if err := repo.Create(ctx, invite); err != nil {
				t.Fatal(err)
			}
			mail := &testutil.MockMailer{}
			gen := &inviteGenerationBoundary{TokenGenerator: &testutil.MockTokenGen{Length: 32}}
			read := &inviteExpiryReadBoundary{InviteRepository: repo}
			svc := NewInviteService(f.users, f.sessions, read, f.hasher, gen, mail, f.db, defaultTestConfig(), nil, nil)
			revoke := func() error { return svc.RevokeInvite(ctx, invite.ID, f.userID) }
			if name == "resend" {
				gen.before = revoke
				if err := svc.ResendInviteEmail(ctx, invite.ID, f.userID); !errors.Is(err, domain.ErrInviteAlreadyUsed) {
					t.Fatalf("resend error=%v, want invite_already_used", err)
				}
				if len(mail.Calls) != 0 {
					t.Fatal("lost resend sent a new invitation")
				}
			} else {
				read.after = revoke
				if _, err := svc.GetInviteByToken(ctx, "old-code"); !errors.Is(err, domain.ErrInviteExpired) {
					t.Fatalf("expiry read error=%v", err)
				}
			}
			stored, err := repo.GetByID(ctx, invite.ID)
			if err != nil || stored.Status != domain.InviteRevoked || stored.Code != invite.Code {
				t.Fatalf("revocation overwritten: %+v, %v", stored, err)
			}
		})
	}
}
