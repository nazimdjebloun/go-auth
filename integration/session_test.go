package integration_test

import (
	"context"
	"errors"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"testing"
	"time"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestSession_RefreshReuseDetection_PublishesAuditEvent(t *testing.T) {
	db, closeDB := newTestDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()

	loginResult, err := a.Register(ctx, api.RegisterInput{Email: "reuse@example.com", Password: "Passw0rd!", Name: "Reuse"})
	if err != nil {
		t.Fatal(err)
	}
	oldRefreshToken := loginResult.RefreshToken

	if _, err := a.Services().Session.RefreshSession(ctx, oldRefreshToken); err != nil {
		t.Fatal(err)
	}

	// Presenting the now-rotated-away token again is reuse — the session
	// underneath gets revoked, and RefreshSession must report it exactly
	// like any other revoked session (no client-facing behavior change).
	_, err = a.Services().Session.RefreshSession(ctx, oldRefreshToken)
	if err == nil {
		t.Fatal("expected an error for reused refresh token")
	}

	// Audit events flush asynchronously (ServiceConfig's default
	// FlushInterval is 100ms).
	waitAuditCount(t, db, "SELECT COUNT(*) FROM audit_log WHERE event_type = 'session.refresh_reuse_detected'", 1)

	reuseType := string(audit.EventSessionRefreshReuseDetected)
	events, err := a.Services().AuditLog.List(ctx, port.AuditLogFilter{Types: []string{reuseType}, Limit: 10})
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
	db, closeDB := newTestDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()
	registered, err := a.Register(ctx, api.RegisterInput{Email: "idle-refresh@example.com", Password: "Passw0rd!", Name: "Idle"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(testdb.SQL(db, "UPDATE sessions SET last_active_at = ? WHERE id = ?"), time.Now().UTC().Add(-2*time.Hour), registered.Session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Services().Session.RefreshSession(ctx, registered.RefreshToken); !errors.Is(err, domain.ErrSessionExpired) {
		t.Fatalf("refresh after idle timeout = %v, want ErrSessionExpired", err)
	}
	var storedHash string
	if err := db.QueryRow(testdb.SQL(db, "SELECT refresh_token_hash FROM sessions WHERE id = ?"), registered.Session.ID).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if storedHash != sha256Hex(registered.RefreshToken) {
		t.Fatal("rejected refresh rotated the token")
	}
}

func TestSession_RefreshAuditFailureKeepsOldToken(t *testing.T) {
	db, closeDB := newTestDB(t)
	defer closeDB()
	migrateDB(t, db, testdb.Driver(db))
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
	registered, err := a.Register(ctx, api.RegisterInput{Email: "audit-refresh@example.com", Password: "Passw0rd!", Name: "Audit"})
	if err != nil {
		t.Fatal(err)
	}
	removeFailure := testdb.FailWrites(t, db, "block_refresh_audit", "audit_log", "INSERT", "NEW.event_type = 'session.refreshed'")
	if _, err := a.Services().Session.RefreshSession(ctx, registered.RefreshToken); !errors.Is(err, audit.ErrRecordBlocked) {
		t.Fatalf("refresh with failed audit = %v, want ErrRecordBlocked", err)
	}
	removeFailure()
	if _, err := a.Services().Session.RefreshSession(ctx, registered.RefreshToken); err != nil {
		t.Fatalf("old refresh token was stranded after rollback: %v", err)
	}
}

func TestSession_RefreshReuseDetection_RevocationFailurePropagates(t *testing.T) {
	db, closeDB := newTestDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()

	registered, err := a.Register(ctx, api.RegisterInput{
		Email: "reuse-revoke-failure@example.com", Password: "Passw0rd!", Name: "Reuse Failure",
	})
	if err != nil {
		t.Fatal(err)
	}
	oldRefreshToken := registered.RefreshToken
	rotated, err := a.Services().Session.RefreshSession(ctx, oldRefreshToken)
	if err != nil {
		t.Fatal(err)
	}

	removeFailure := testdb.FailWrites(t, db, "block_reuse_revoke", "sessions", "DELETE", "")
	_, err = a.Services().Session.RefreshSession(ctx, oldRefreshToken)
	if err == nil {
		t.Fatal("expected revocation failure to propagate")
	}
	if errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("revocation failure was misreported as a successfully revoked session: %v", err)
	}

	removeFailure()
	if _, err := a.Services().Session.RefreshSession(ctx, rotated.RefreshToken); err != nil {
		t.Fatalf("current refresh token should remain usable because deletion did not occur: %v", err)
	}
}
