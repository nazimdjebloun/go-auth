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

func emailMetadata(email string) map[string]any {
	if email == "" {
		return nil
	}
	return map[string]any{"email": email}
}

// ─── Generic Builder ────────────────────────────────────────

// NewEvent returns an audit event of the given type.
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

// EventOption changes an event built by NewEvent.
type EventOption func(*Event)

// WithActor sets the event actor.
func WithActor(userID string) EventOption {
	return func(e *Event) { e.ActorID = strPtr(userID) }
}

// WithTarget sets the event target user.
func WithTarget(userID string) EventOption {
	return func(e *Event) { e.TargetUserID = strPtr(userID) }
}

// WithSession sets the event session.
func WithSession(sessionID string) EventOption {
	return func(e *Event) { e.SessionID = strPtr(sessionID) }
}

// WithOrg sets the event organization.
func WithOrg(orgID string) EventOption {
	return func(e *Event) { e.OrgID = strPtr(orgID) }
}

// WithIP sets the event IP address.
func WithIP(ip net.IP) EventOption {
	return func(e *Event) { e.IP = ip }
}

// WithUserAgent sets the event user agent.
func WithUserAgent(ua string) EventOption {
	return func(e *Event) { e.UserAgent = ua }
}

// WithRequestID sets the event request ID.
func WithRequestID(id string) EventOption {
	return func(e *Event) { e.RequestID = id }
}

// WithCorrelationID sets the event correlation ID.
func WithCorrelationID(id string) EventOption {
	return func(e *Event) { e.CorrelationID = id }
}

// WithMetadata adds one metadata value to the event.
func WithMetadata(key string, value any) EventOption {
	return func(e *Event) {
		if e.Metadata == nil {
			e.Metadata = make(map[string]any)
		}
		e.Metadata[key] = value
	}
}

// WithSuccess sets whether the audited operation succeeded.
func WithSuccess(success bool) EventOption {
	return func(e *Event) { e.Success = success }
}

// WithSeverity sets the event severity.
func WithSeverity(severity Severity) EventOption {
	return func(e *Event) { e.Severity = severity }
}

// ─── Typed Builders (internal) ──────────────────────────────

// NewLoginEvent returns a user login audit event.
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

// NewLoginFailedEvent returns a failed user login audit event.
func NewLoginFailedEvent(email string, ip net.IP, ua string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventLoginFailed,
		Severity:  SeverityWarning,
		Success:   false,
		IP:        ip,
		UserAgent: ua,
		Metadata:  emailMetadata(email),
		CreatedAt: time.Now().UTC(),
	}
}

// NewNameChangedEvent records a self-service profile name change. The actor
// is the user whose name changed — there is no admin in this path.
func NewNameChangedEvent(userID string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventNameChanged,
		Severity:  SeverityInfo,
		Success:   true,
		ActorID:   strPtr(userID),
		CreatedAt: time.Now().UTC(),
	}
}

// NewAccountDeletedEvent records a completed self-service account deletion,
// after the user row and all its sessions are gone. SeverityWarning matches
// the admin-side deletion: the action is user-initiated and legitimate, but
// an identity disappearing is worth surfacing in security review.
func NewAccountDeletedEvent(userID string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventAccountDeleted,
		Severity:  SeverityWarning,
		Success:   true,
		ActorID:   strPtr(userID),
		CreatedAt: time.Now().UTC(),
	}
}

// The 2FA builders key on userID as ActorID. Unresolved email addresses belong
// in metadata because PostgreSQL stores actor_id as UUID.

// NewTwoFactorCodeSentEvent returns a code-sent audit event.
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

// NewTwoFactorVerifiedEvent returns a successful two-factor audit event.
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

// NewTwoFactorFailedEvent returns a failed two-factor audit event.
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

// NewTwoFactorEnabledEvent returns a two-factor-enabled audit event.
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

// NewTwoFactorDisabledEvent returns a two-factor-disabled audit event.
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

// NewAdminLoginSuccessEvent returns a successful administrator login audit event.
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

// NewAdminLoginFailedEvent returns a failed administrator login audit event.
func NewAdminLoginFailedEvent(email string, ip net.IP, ua string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventAdminLoginFailed,
		Severity:  SeverityWarning,
		Success:   false,
		IP:        ip,
		UserAgent: ua,
		Metadata:  emailMetadata(email),
		CreatedAt: time.Now().UTC(),
	}
}

// NewLogoutEvent returns a logout audit event.
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

// NewUserRegisteredEvent returns a user-registration audit event.
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

// NewEmailVerifiedEvent returns an email-verified audit event.
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

// NewEmailVerificationSentEvent returns a verification-email-sent audit event.
func NewEmailVerificationSentEvent(email string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventEmailVerificationSent,
		Severity:  SeverityInfo,
		Success:   true,
		Metadata:  emailMetadata(email),
		CreatedAt: time.Now().UTC(),
	}
}

// NewPasswordChangedEvent returns a password-changed audit event.
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

// NewPasswordResetRequestedEvent returns a password-reset-requested audit event.
func NewPasswordResetRequestedEvent(email string, ip net.IP, ua string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventPasswordResetRequest,
		Severity:  SeverityInfo,
		Success:   true,
		IP:        ip,
		UserAgent: ua,
		Metadata:  emailMetadata(email),
		CreatedAt: time.Now().UTC(),
	}
}

// NewPasswordResetCompletedEvent returns a password-reset-completed audit event.
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

// NewSessionEvent returns an audit event for a session action.
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

// NewSessionReuseDetectedEvent marks a suspected refresh-token theft: a
// token already rotated once got presented again outside the grace window.
// Unlike NewSessionEvent's other session types, this always records a
// failure at critical severity — it's an attack signal, not routine
// activity.
func NewSessionReuseDetectedEvent(userID, sessionID string) Event {
	return Event{
		ID:        generateID(),
		Type:      EventSessionRefreshReuseDetected,
		Severity:  SeverityCritical,
		Success:   false,
		ActorID:   strPtr(userID),
		SessionID: strPtr(sessionID),
		CreatedAt: time.Now().UTC(),
	}
}

// NewOAuthEvent returns an audit event for an OAuth action.
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

// NewAdminEvent returns an audit event for an administrator action.
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

// NewInviteEvent records an admin action against an app-wide invite.
//
// Separate from NewAdminEvent because the subject isn't a user: there's no
// TargetUserID to set, and actor_id is a UUID column, so the invite id and
// recipient address go in Metadata instead.
func NewInviteEvent(typ EventType, actorID, inviteID, email string) Event {
	if typ != EventAdminInviteCreated && typ != EventAdminInviteResent &&
		typ != EventAdminInviteRevoked && typ != EventAdminInviteDeleted {
		return Event{
			ID:        generateID(),
			Type:      typ,
			Severity:  SeverityInfo,
			Success:   false,
			CreatedAt: time.Now().UTC(),
			Metadata:  map[string]any{"error": fmt.Sprintf("invalid invite event type: %s", typ)},
		}
	}
	sev := SeverityInfo
	if typ == EventAdminInviteDeleted || typ == EventAdminInviteRevoked {
		sev = SeverityWarning
	}
	meta := map[string]any{}
	if inviteID != "" {
		meta["inviteId"] = inviteID
	}
	if email != "" {
		meta["email"] = email
	}
	return Event{
		ID:        generateID(),
		Type:      typ,
		Severity:  sev,
		Success:   true,
		ActorID:   strPtr(actorID),
		Metadata:  meta,
		CreatedAt: time.Now().UTC(),
	}
}

// NewOrgEvent returns an audit event for an organization action.
func NewOrgEvent(typ EventType, actorID, orgID string, targetID *string) Event {
	switch typ {
	case EventOrgCreated, EventOrgDeleted, EventOrgMemberInvited, EventOrgMemberRemoved,
		EventOrgMemberRoleChanged, EventAdminOrgDeleted, EventAdminOrgMemberAdded,
		EventAdminOrgMemberRemoved, EventAdminOrgMemberRoleChanged, EventAdminOrgViewed:
	default:
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
	if typ == EventOrgDeleted || typ == EventOrgMemberRemoved ||
		typ == EventAdminOrgDeleted || typ == EventAdminOrgMemberRemoved {
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

// NewRoleChangedEvent returns a role-changed audit event.
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
