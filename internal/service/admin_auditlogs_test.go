package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

// ─── ListAuditLogs ───────────────────────────────────────────────────

func parsedUA(t *testing.T, deviceType string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(domain.UserAgentInfo{DeviceType: deviceType})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAdminListAuditLogs_MultiEventType(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	auditLogs := testutil.NewMockAuditLogRepo()
	svc, actorID, _ := newTestAdminServiceWithAudit(users, sessions, auditLogs, &testutil.MockHasher{})

	now := time.Now().UTC()
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e1", Type: "login.success", CreatedAt: now})
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e2", Type: "login.failed", CreatedAt: now})
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e3", Type: "logout", CreatedAt: now})

	result, err := svc.ListAuditLogs(context.Background(), AdminListAuditLogsInput{
		ActorID: actorID, EventTypes: []string{"login.success", "logout"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Events) != 2 {
		t.Fatalf("expected 2 events (login.success + logout), got %d: %+v", len(result.Events), result.Events)
	}
}

func TestAdminListAuditLogs_ActorByEmail(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	auditLogs := testutil.NewMockAuditLogRepo()
	svc, actorID, _ := newTestAdminServiceWithAudit(users, sessions, auditLogs, &testutil.MockHasher{})
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{ID: "alice-id", Email: "alice@example.com"}))
	alice, bob := "alice-id", "bob-id"
	now := time.Now().UTC()
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e1", Type: "login.success", ActorID: &alice, CreatedAt: now})
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e2", Type: "login.success", ActorID: &bob, CreatedAt: now})

	email := "alice@example.com"
	result, err := svc.ListAuditLogs(context.Background(), AdminListAuditLogsInput{
		ActorID: actorID, EventActorEmail: &email,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Events) != 1 || *result.Events[0].ActorID != "alice-id" {
		t.Fatalf("expected 1 event for alice-id, got %+v", result.Events)
	}
}

func TestAdminListAuditLogs_ActorByEmail_NotFound(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	auditLogs := testutil.NewMockAuditLogRepo()
	svc, actorID, _ := newTestAdminServiceWithAudit(users, sessions, auditLogs, &testutil.MockHasher{})

	email := "nobody@example.com"
	_, err := svc.ListAuditLogs(context.Background(), AdminListAuditLogsInput{
		ActorID: actorID, EventActorEmail: &email,
	})
	if authErrCode(err) != "user_not_found" {
		t.Fatalf("expected user_not_found, got %v", err)
	}
}

func TestAdminListAuditLogs_TargetByEmail(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	auditLogs := testutil.NewMockAuditLogRepo()
	svc, actorID, _ := newTestAdminServiceWithAudit(users, sessions, auditLogs, &testutil.MockHasher{})
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{ID: "target-id", Email: "target@example.com"}))
	target, other := "target-id", "other-id"
	now := time.Now().UTC()
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e1", Type: "admin.user.banned", TargetUserID: &target, CreatedAt: now})
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e2", Type: "admin.user.banned", TargetUserID: &other, CreatedAt: now})

	email := "target@example.com"
	result, err := svc.ListAuditLogs(context.Background(), AdminListAuditLogsInput{
		ActorID: actorID, TargetEmail: &email,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Events) != 1 || *result.Events[0].TargetUserID != "target-id" {
		t.Fatalf("expected 1 event for target-id, got %+v", result.Events)
	}
}

func TestAdminListAuditLogs_DeviceType(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	auditLogs := testutil.NewMockAuditLogRepo()
	svc, actorID, _ := newTestAdminServiceWithAudit(users, sessions, auditLogs, &testutil.MockHasher{})

	now := time.Now().UTC()
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e1", Type: "login.success", ParsedUA: parsedUA(t, "mobile"), CreatedAt: now})
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e2", Type: "login.success", ParsedUA: parsedUA(t, "desktop"), CreatedAt: now})

	mobile := "mobile"
	result, err := svc.ListAuditLogs(context.Background(), AdminListAuditLogsInput{
		ActorID: actorID, DeviceType: &mobile,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Events) != 1 || result.Events[0].ID != "e1" {
		t.Fatalf("expected 1 mobile event, got %+v", result.Events)
	}
}

func TestAdminListAuditLogs_IPFilter(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	auditLogs := testutil.NewMockAuditLogRepo()
	svc, actorID, _ := newTestAdminServiceWithAudit(users, sessions, auditLogs, &testutil.MockHasher{})

	now := time.Now().UTC()
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e1", Type: "login.success", IP: "10.0.0.1", CreatedAt: now})
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e2", Type: "login.success", IP: "10.0.0.2", CreatedAt: now})

	ip := "10.0.0.2"
	result, err := svc.ListAuditLogs(context.Background(), AdminListAuditLogsInput{
		ActorID: actorID, IP: &ip,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Events) != 1 || result.Events[0].ID != "e2" {
		t.Fatalf("expected 1 event from 10.0.0.2, got %+v", result.Events)
	}
}

func TestAdminListAuditLogs_PerUserRouteScoping(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	auditLogs := testutil.NewMockAuditLogRepo()
	svc, actorID, _ := newTestAdminServiceWithAudit(users, sessions, auditLogs, &testutil.MockHasher{})

	target, other := "target-id", "other-id"
	now := time.Now().UTC()
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e1", Type: "login.success", TargetUserID: &target, CreatedAt: now})
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e2", Type: "login.success", TargetUserID: &other, CreatedAt: now})

	result, err := svc.ListAuditLogs(context.Background(), AdminListAuditLogsInput{
		ActorID: actorID, TargetUserID: &target,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Events) != 1 || result.Events[0].ID != "e1" {
		t.Fatalf("expected 1 event for target-id, got %+v", result.Events)
	}
}

func TestAdminListAuditLogs_ResolvesActorAndTargetEmails(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	auditLogs := testutil.NewMockAuditLogRepo()
	svc, actorID, _ := newTestAdminServiceWithAudit(users, sessions, auditLogs, &testutil.MockHasher{})
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{ID: "alice-id", Email: "alice@example.com"}))
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{ID: "bob-id", Email: "bob@example.com"}))
	alice, bob, ghost := "alice-id", "bob-id", "deleted-user-id"
	now := time.Now().UTC()
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e1", Type: "admin.user.banned", ActorID: &alice, TargetUserID: &bob, CreatedAt: now})
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e2", Type: "login.success", ActorID: &ghost, CreatedAt: now})

	result, err := svc.ListAuditLogs(context.Background(), AdminListAuditLogsInput{ActorID: actorID})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(result.Events))
	}

	var e1, e2 *AdminAuditLogEntry
	for i := range result.Events {
		switch result.Events[i].ID {
		case "e1":
			e1 = &result.Events[i]
		case "e2":
			e2 = &result.Events[i]
		}
	}
	if e1 == nil || e2 == nil {
		t.Fatalf("expected both e1 and e2 in results, got %+v", result.Events)
	}
	if e1.ActorEmail == nil || *e1.ActorEmail != "alice@example.com" {
		t.Errorf("expected e1.ActorEmail alice@example.com, got %+v", e1.ActorEmail)
	}
	if e1.TargetEmail == nil || *e1.TargetEmail != "bob@example.com" {
		t.Errorf("expected e1.TargetEmail bob@example.com, got %+v", e1.TargetEmail)
	}
	if e2.ActorEmail != nil {
		t.Errorf("expected e2.ActorEmail nil (deleted user), got %+v", e2.ActorEmail)
	}
}

func TestAdminListAuditLogs_ActorNotAdmin_Forbidden(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	auditLogs := testutil.NewMockAuditLogRepo()
	svc, _, _ := newTestAdminServiceWithAudit(users, sessions, auditLogs, &testutil.MockHasher{})

	nonAdmin := &domain.User{ID: "not-admin", Email: "not-admin@example.com", Role: domain.RoleUser}
	checkTestErrors(t).noError(users.Create(context.Background(), nonAdmin))

	_, err := svc.ListAuditLogs(context.Background(), AdminListAuditLogsInput{ActorID: "not-admin"})
	if err != domain.ErrForbidden {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}
