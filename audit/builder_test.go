package audit

import "testing"

func TestEmailOnlyEventsKeepActorIDDatabaseSafe(t *testing.T) {
	tests := []struct {
		name  string
		event Event
	}{
		{"login failed", NewLoginFailedEvent("a@example.com", nil, "")},
		{"login locked", NewLoginLockedEvent("a@example.com", nil, "")},
		{"admin login failed", NewAdminLoginFailedEvent("a@example.com", nil, "")},
		{"verification sent", NewEmailVerificationSentEvent("a@example.com")},
		{"password reset requested", NewPasswordResetRequestedEvent("a@example.com", nil, "")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.event.ActorID != nil {
				t.Fatalf("ActorID = %q, want nil for unresolved email", *tt.event.ActorID)
			}
			if got := tt.event.Metadata["email"]; got != "a@example.com" {
				t.Fatalf("metadata email = %v, want a@example.com", got)
			}
		})
	}
}

func TestNewInviteEvent(t *testing.T) {
	e := NewInviteEvent(EventAdminInviteCreated, "admin-1", "inv-9", "a@example.com")
	if !e.Success || e.Type != EventAdminInviteCreated {
		t.Fatalf("Type = %q Success = %v", e.Type, e.Success)
	}
	if e.ActorID == nil || *e.ActorID != "admin-1" {
		t.Errorf("ActorID = %v, want admin-1", e.ActorID)
	}
	// the subject is an invite, so nothing goes in the user-typed target column
	if e.TargetUserID != nil {
		t.Errorf("TargetUserID = %v, want nil", *e.TargetUserID)
	}
	if e.Metadata["inviteId"] != "inv-9" || e.Metadata["email"] != "a@example.com" {
		t.Errorf("Metadata = %v", e.Metadata)
	}
	if e.Severity != SeverityInfo {
		t.Errorf("Severity = %q, want info", e.Severity)
	}
	if got := NewInviteEvent(EventAdminInviteRevoked, "a", "i", "e").Severity; got != SeverityWarning {
		t.Errorf("revoke severity = %q, want warning", got)
	}
	if bad := NewInviteEvent(EventLoginSuccess, "a", "i", "e"); bad.Success {
		t.Error("a non-invite event type must be rejected")
	}
}
