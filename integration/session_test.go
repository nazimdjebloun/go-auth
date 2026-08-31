package integration_test

import (
	"context"
	"testing"
	"time"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/audit"
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

	// Audit events flush asynchronously (AuditServiceConfig's default
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
