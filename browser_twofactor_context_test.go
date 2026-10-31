package goauth

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sessioncontext"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
)

type contextCodeMailer struct {
	mu   sync.Mutex
	code string
}

func (m *contextCodeMailer) Send(_ context.Context, _, _, _, plain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, line := range strings.Split(plain, "\n") {
		if strings.HasPrefix(line, "Your code: ") {
			m.code = strings.TrimSpace(strings.TrimPrefix(line, "Your code: "))
		}
	}
	return nil
}
func (m *contextCodeMailer) last(t *testing.T) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.code == "" {
		t.Fatal("no challenge code delivered")
	}
	return m.code
}

func TestBrowserSessionContexts_TwoFactorLineages(t *testing.T) {
	mailer := &contextCodeMailer{}
	f := newAppHTTPFixture(t, true, false, WithMailer(mailer))
	svc := f.a.Services().TwoFactor
	app := sessioncontext.With(t.Context(), sessioncontext.App)
	admin := sessioncontext.With(t.Context(), sessioncontext.Admin)
	first, err := svc.Challenge(app, f.admin.UserID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Challenge(admin, f.admin.UserID)
	if err != nil {
		t.Fatal(err)
	}
	adminCode := mailer.last(t)
	if first.ID == second.ID {
		t.Fatal("app and admin reused one challenge lineage")
	}
	for _, ctx := range []context.Context{app, admin} {
		again, err := svc.Challenge(ctx, f.admin.UserID)
		if err != nil {
			t.Fatal(err)
		}
		want := first.ID
		if sessioncontext.Current(ctx) == sessioncontext.Admin {
			want = second.ID
		}
		if again.ID != want || again.Sent {
			t.Fatal("context did not reuse its own pending challenge")
		}
	}
	// A matching binding cookie and correct code still cannot cross contexts.
	if _, err := svc.Verify(app, api.TwoFactorVerifyInput{ChallengeID: second.ID, BindingToken: second.BindingToken, Code: adminCode}); err != domain.ErrTwoFactorCodeInvalid {
		t.Fatalf("wrong-context verify: %v", err)
	}
	if _, err := svc.Resend(app, api.TwoFactorResendInput{ChallengeID: second.ID, BindingToken: second.BindingToken}); err == nil {
		t.Fatal("resend crossed contexts")
	}
	if _, err := svc.Resend(app, api.TwoFactorResendInput{ChallengeID: first.ID, BindingToken: first.BindingToken}); err != nil {
		t.Fatal(err)
	}
	appCode := mailer.last(t)
	verified, err := svc.Verify(admin, api.TwoFactorVerifyInput{ChallengeID: second.ID, BindingToken: second.BindingToken, Code: adminCode})
	if err != nil {
		t.Fatal(err)
	}
	if sessioncontext.Of(verified.SessionToken) != sessioncontext.Admin {
		t.Fatal("admin 2FA issued app credentials")
	}
	if _, err := svc.Verify(app, api.TwoFactorVerifyInput{ChallengeID: first.ID, BindingToken: first.BindingToken, Code: appCode}); err != nil {
		t.Fatalf("admin verification consumed app challenge: %v", err)
	}
	// Cleanup replaces only the selected lineage, including expired/capped rows.
	third, err := svc.Challenge(admin, f.admin.UserID)
	if err != nil {
		t.Fatal(err)
	}
	fourth, err := svc.Challenge(app, f.admin.UserID)
	if err != nil {
		t.Fatal(err)
	}
	repo := sqlstore.NewTokenRepository(f.db)
	if err := repo.DeleteUnusedTwoFactor(app, f.admin.UserID, false); err != nil {
		t.Fatal(err)
	}
	appRow, err := repo.GetByID(app, fourth.ID)
	if err != nil {
		t.Fatal(err)
	}
	adminRow, err := repo.GetByID(admin, third.ID)
	if err != nil {
		t.Fatal(err)
	}
	if appRow != nil || adminRow == nil {
		t.Fatal("cleanup did not isolate pending contexts")
	}
}
