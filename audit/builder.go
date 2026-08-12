package audit

import (
	"fmt"
	"net"
	"time"
)

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ─── Generic Builder ────────────────────────────────────────

func NewEvent(typ EventType, opts ...EventOption) Event {
	e := Event{
		ID:        generateID(),
		Type:      typ,
		CreatedAt: time.Now().UTC(),
	}
	for _, opt := range opts {
		opt(&e)
	}
	return e
}

type EventOption func(*Event)

func WithActor(userID string) EventOption {
	return func(e *Event) { e.ActorID = strPtr(userID) }
}

func WithTarget(userID string) EventOption {
	return func(e *Event) { e.TargetUserID = strPtr(userID) }
}

func WithSession(sessionID string) EventOption {
	return func(e *Event) { e.SessionID = strPtr(sessionID) }
}

func WithOrg(orgID string) EventOption {
	return func(e *Event) { e.OrgID = strPtr(orgID) }
}

func WithIP(ip net.IP) EventOption {
	return func(e *Event) { e.IP = ip }
}

func WithUserAgent(ua string) EventOption {
	return func(e *Event) { e.UserAgent = ua }
}

func WithRequestID(id string) EventOption {
	return func(e *Event) { e.RequestID = id }
}

func WithCorrelationID(id string) EventOption {
	return func(e *Event) { e.CorrelationID = id }
}

func WithMetadata(key string, value any) EventOption {
	return func(e *Event) {
		if e.Metadata == nil {
			e.Metadata = make(map[string]any)
		}
		e.Metadata[key] = value
	}
}

func WithSuccess(success bool) EventOption {
	return func(e *Event) { e.Success = success }
}

func WithSeverity(severity Severity) EventOption {
	return func(e *Event) { e.Severity = severity }
}

// ─── Typed Builders (internal) ──────────────────────────────

func NewLoginEvent(actorID, sessionID string, ip net.IP, ua string, success bool) Event {
	return Event{
		ID:        generateID(),
		Type:      EventLoginSuccess,
		Severity:  SeverityInfo,
		Success:   success,
		ActorID:   strPtr(actorID),
		SessionID: strPtr(sessionID),
		IP:        ip,
		UserAgent: ua,
		CreatedAt: time.Now().UTC(),
	}
}

func NewLoginFailedEvent(email string, ip net.IP, ua string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventLoginFailed,
		Severity:  SeverityWarning,
		Success:   false,
		ActorID:   strPtr(email),
		IP:        ip,
		UserAgent: ua,
		CreatedAt: time.Now().UTC(),
	}
}

func NewLoginLockedEvent(email string, ip net.IP, ua string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventLoginLocked,
		Severity:  SeverityWarning,
		Success:   false,
		ActorID:   strPtr(email),
		IP:        ip,
		UserAgent: ua,
		CreatedAt: time.Now().UTC(),
	}
}

// The 2FA builders key on userID as ActorID. Do not copy
// NewEmailVerificationSentEvent's pattern of putting the email there — every
// 2FA path resolves a real user before it publishes.

func NewTwoFactorCodeSentEvent(userID string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventTwoFactorCodeSent,
		Severity:  SeverityInfo,
		Success:   true,
		ActorID:   strPtr(userID),
		CreatedAt: time.Now().UTC(),
	}
}

func NewTwoFactorVerifiedEvent(userID, sessionID string, ip net.IP, ua string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventTwoFactorVerified,
		Severity:  SeverityInfo,
		Success:   true,
		ActorID:   strPtr(userID),
		SessionID: strPtr(sessionID),
		IP:        ip,
		UserAgent: ua,
		CreatedAt: time.Now().UTC(),
	}
}

func NewTwoFactorFailedEvent(userID string, ip net.IP, ua string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventTwoFactorFailed,
		Severity:  SeverityWarning,
		Success:   false,
		ActorID:   strPtr(userID),
		IP:        ip,
		UserAgent: ua,
		CreatedAt: time.Now().UTC(),
	}
}

func NewTwoFactorEnabledEvent(userID string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventTwoFactorEnabled,
		Severity:  SeverityInfo,
		Success:   true,
		ActorID:   strPtr(userID),
		CreatedAt: time.Now().UTC(),
	}
}

func NewTwoFactorDisabledEvent(userID string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventTwoFactorDisabled,
		Severity:  SeverityInfo,
		Success:   true,
		ActorID:   strPtr(userID),
		CreatedAt: time.Now().UTC(),
	}
}

// NewTwoFactorSuspiciousEvent marks an account crossing the failed-2FA notify
// threshold. It records a condition, not a refusal — nothing is blocked.
func NewTwoFactorSuspiciousEvent(userID string, ip net.IP, ua string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventTwoFactorSuspicious,
		Severity:  SeverityWarning,
		Success:   false,
		ActorID:   strPtr(userID),
		IP:        ip,
		UserAgent: ua,
		CreatedAt: time.Now().UTC(),
	}
}

func NewAdminLoginSuccessEvent(actorID, sessionID string, ip net.IP, ua string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventAdminLoginSuccess,
		Severity:  SeverityInfo,
		Success:   true,
		ActorID:   strPtr(actorID),
		SessionID: strPtr(sessionID),
		IP:        ip,
		UserAgent: ua,
		CreatedAt: time.Now().UTC(),
	}
}

func NewAdminLoginFailedEvent(email string, ip net.IP, ua string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventAdminLoginFailed,
		Severity:  SeverityWarning,
		Success:   false,
		ActorID:   strPtr(email),
		IP:        ip,
		UserAgent: ua,
		CreatedAt: time.Now().UTC(),
	}
}

func NewLogoutEvent(actorID, sessionID string, ip net.IP, ua string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventLogout,
		Severity:  SeverityInfo,
		Success:   true,
		ActorID:   strPtr(actorID),
		SessionID: strPtr(sessionID),
		IP:        ip,
		UserAgent: ua,
		CreatedAt: time.Now().UTC(),
	}
}

func NewUserRegisteredEvent(actorID string, ip net.IP, ua string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventUserRegistered,
		Severity:  SeverityInfo,
		Success:   true,
		ActorID:   strPtr(actorID),
		IP:        ip,
		UserAgent: ua,
		CreatedAt: time.Now().UTC(),
	}
}

func NewEmailVerifiedEvent(actorID string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventEmailVerified,
		Severity:  SeverityInfo,
		Success:   true,
		ActorID:   strPtr(actorID),
		CreatedAt: time.Now().UTC(),
	}
}

func NewEmailVerificationSentEvent(email string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventEmailVerificationSent,
		Severity:  SeverityInfo,
		Success:   true,
		ActorID:   strPtr(email),
		CreatedAt: time.Now().UTC(),
	}
}

func NewPasswordChangedEvent(actorID string, ip net.IP, ua string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventPasswordChanged,
		Severity:  SeverityInfo,
		Success:   true,
		ActorID:   strPtr(actorID),
		IP:        ip,
		UserAgent: ua,
		CreatedAt: time.Now().UTC(),
	}
}

func NewPasswordResetRequestedEvent(email string, ip net.IP, ua string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventPasswordResetRequest,
		Severity:  SeverityInfo,
		Success:   true,
		ActorID:   strPtr(email),
		IP:        ip,
		UserAgent: ua,
		CreatedAt: time.Now().UTC(),
	}
}

func NewPasswordResetCompletedEvent(actorID string, ip net.IP, ua string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventPasswordResetDone,
		Severity:  SeverityInfo,
		Success:   true,
		ActorID:   strPtr(actorID),
		IP:        ip,
		UserAgent: ua,
		CreatedAt: time.Now().UTC(),
	}
}

func NewSessionEvent(typ EventType, actorID, sessionID string, ip net.IP, ua string) Event {
	if typ != EventSessionCreated && typ != EventSessionRefreshed &&
		typ != EventSessionRevoked && typ != EventSessionRevokedAll {
		return Event{
			ID:        generateID(),
			Type:      typ,
			Severity:  SeverityInfo,
			Success:   false,
			CreatedAt: time.Now().UTC(),
			Metadata:  map[string]any{"error": fmt.Sprintf("invalid session event type: %s", typ)},
		}
	}
	return Event{
		ID:        generateID(),
		Type:      typ,
		Severity:  SeverityInfo,
		Success:   true,
		ActorID:   strPtr(actorID),
		SessionID: strPtr(sessionID),
		IP:        ip,
		UserAgent: ua,
		CreatedAt: time.Now().UTC(),
	}
}

func NewOAuthEvent(typ EventType, actorID, provider string, ip net.IP, ua string) Event {
	if typ != EventOAuthLogin && typ != EventOAuthLinked && typ != EventOAuthUnlinked {
		return Event{
			ID:        generateID(),
			Type:      typ,
			Severity:  SeverityInfo,
			Success:   false,
			CreatedAt: time.Now().UTC(),
			Metadata:  map[string]any{"error": fmt.Sprintf("invalid oauth event type: %s", typ)},
		}
	}
	return Event{
		ID:        generateID(),
		Type:      typ,
		Severity:  SeverityInfo,
		Success:   true,
		ActorID:   strPtr(actorID),
		IP:        ip,
		UserAgent: ua,
		Metadata:  map[string]any{"provider": provider},
		CreatedAt: time.Now().UTC(),
	}
}

func NewAdminEvent(typ EventType, actorID, targetID string) Event {
	if typ != EventAdminUserCreated && typ != EventAdminUserUpdated &&
		typ != EventAdminUserDeleted && typ != EventAdminUserBanned &&
		typ != EventAdminUserUnbanned {
		return Event{
			ID:        generateID(),
			Type:      typ,
			Severity:  SeverityInfo,
			Success:   false,
			CreatedAt: time.Now().UTC(),
			Metadata:  map[string]any{"error": fmt.Sprintf("invalid admin event type: %s", typ)},
		}
	}
	sev := SeverityInfo
	if typ == EventAdminUserDeleted || typ == EventAdminUserBanned {
		sev = SeverityWarning
	}
	return Event{
		ID:           generateID(),
		Type:         typ,
		Severity:     sev,
		Success:      true,
		ActorID:      strPtr(actorID),
		TargetUserID: strPtr(targetID),
		CreatedAt:    time.Now().UTC(),
	}
}

func NewOrgEvent(typ EventType, actorID, orgID string, targetID *string) Event {
	if typ != EventOrgCreated && typ != EventOrgDeleted &&
		typ != EventOrgMemberInvited && typ != EventOrgMemberRemoved {
		return Event{
			ID:        generateID(),
			Type:      typ,
			Severity:  SeverityInfo,
			Success:   false,
			CreatedAt: time.Now().UTC(),
			Metadata:  map[string]any{"error": fmt.Sprintf("invalid org event type: %s", typ)},
		}
	}
	sev := SeverityInfo
	if typ == EventOrgDeleted || typ == EventOrgMemberRemoved {
		sev = SeverityWarning
	}
	return Event{
		ID:           generateID(),
		Type:         typ,
		Severity:     sev,
		Success:      true,
		ActorID:      strPtr(actorID),
		OrgID:        strPtr(orgID),
		TargetUserID: targetID,
		CreatedAt:    time.Now().UTC(),
	}
}

func NewRoleChangedEvent(actorID, targetID string, oldRole, newRole string) Event {
	return Event{
		ID:           generateID(),
		Type:         EventRoleChanged,
		Severity:     SeverityInfo,
		Success:      true,
		ActorID:      strPtr(actorID),
		TargetUserID: strPtr(targetID),
		Metadata:     map[string]any{"old_role": oldRole, "new_role": newRole},
		CreatedAt:    time.Now().UTC(),
	}
}
