package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestSession_RefreshReuseDetection_PublishesAuditEvent(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()

	loginResult, err := a.Register(ctx, goauth.RegisterInput{Email: "reuse@example.com", Password: "Passw0rd!", Name: "Reuse"})
	if err != nil {
		t.Fatal(err)
	}
	oldRefreshToken := loginResult.RefreshToken

	if _, err := a.Services.Session.RefreshSession(ctx, oldRefreshToken); err != nil {
		t.Fatal(err)
	}

	// Presenting the now-rotated-away token again is reuse — the session
	// underneath gets revoked, and RefreshSession must report it exactly
	// like any other revoked session (no client-facing behavior change).
	_, err = a.Services.Session.RefreshSession(ctx, oldRefreshToken)
	if err == nil {
		t.Fatal("expected an error for reused refresh token")
	}

	// Audit events flush asynchronously (ServiceConfig's default
	// FlushInterval is 100ms).
	time.Sleep(200 * time.Millisecond)

	reuseType := string(audit.EventSessionRefreshReuseDetected)
	events, err := a.Services.AuditLog.List(ctx, port.AuditLogFilter{Types: []string{reuseType}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 session.refresh_reuse_detected event, got %d: %+v", len(events), events)
	}
	if events[0].ActorID == nil || *events[0].ActorID != loginResult.User.ID {
		t.Errorf("expected ActorID %s, got %+v", loginResult.User.ID, events[0].ActorID)
	}
}

func TestSession_RefreshCannotReviveIdleSession(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()
	registered, err := a.Register(ctx, goauth.RegisterInput{Email: "idle-refresh@example.com", Password: "Passw0rd!", Name: "Idle"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE sessions SET last_active_at = ? WHERE id = ?", time.Now().UTC().Add(-2*time.Hour), registered.Session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Services.Session.RefreshSession(ctx, registered.RefreshToken); !errors.Is(err, domain.ErrSessionExpired) {
		t.Fatalf("refresh after idle timeout = %v, want ErrSessionExpired", err)
	}
	var storedHash string
	if err := db.QueryRow("SELECT refresh_token_hash FROM sessions WHERE id = ?", registered.Session.ID).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if storedHash != sha256Hex(registered.RefreshToken) {
		t.Fatal("rejected refresh rotated the token")
	}
}

func TestSession_RefreshAuditFailureKeepsOldToken(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	migrateDB(t, db, "sqlite")
	a, err := newTestAuth(db, &testMailer{}, goauth.AuditConfig{
		Enabled: true,
		EnqueueFailureMode: func(event audit.Event) audit.FailureMode {
			if event.Type == audit.EventSessionRefreshed {
				return audit.FailureClosed
			}
			return audit.FailureOpen
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx := context.Background()
	registered, err := a.Register(ctx, goauth.RegisterInput{Email: "audit-refresh@example.com", Password: "Passw0rd!", Name: "Audit"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER block_refresh_audit BEFORE INSERT ON audit_log
		WHEN NEW.event_type = 'session.refreshed'
		BEGIN SELECT RAISE(FAIL, 'blocked refresh audit'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Services.Session.RefreshSession(ctx, registered.RefreshToken); !errors.Is(err, audit.ErrRecordBlocked) {
		t.Fatalf("refresh with failed audit = %v, want ErrRecordBlocked", err)
	}
	if _, err := db.Exec("DROP TRIGGER block_refresh_audit"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Services.Session.RefreshSession(ctx, registered.RefreshToken); err != nil {
		t.Fatalf("old refresh token was stranded after rollback: %v", err)
	}
}

func TestSession_RefreshReuseDetection_RevocationFailurePropagates(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()

	registered, err := a.Register(ctx, goauth.RegisterInput{
		Email: "reuse-revoke-failure@example.com", Password: "Passw0rd!", Name: "Reuse Failure",
	})
	if err != nil {
		t.Fatal(err)
	}
	oldRefreshToken := registered.RefreshToken
	rotated, err := a.Services.Session.RefreshSession(ctx, oldRefreshToken)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`CREATE TRIGGER block_reuse_revoke BEFORE DELETE ON sessions
		BEGIN SELECT RAISE(FAIL, 'blocked reuse revocation'); END`); err != nil {
		t.Fatal(err)
	}
	_, err = a.Services.Session.RefreshSession(ctx, oldRefreshToken)
	if err == nil {
		t.Fatal("expected revocation failure to propagate")
	}
	if errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("revocation failure was misreported as a successfully revoked session: %v", err)
	}

	if _, err := db.Exec("DROP TRIGGER block_reuse_revoke"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Services.Session.RefreshSession(ctx, rotated.RefreshToken); err != nil {
		t.Fatalf("current refresh token should remain usable because deletion did not occur: %v", err)
	}
}
