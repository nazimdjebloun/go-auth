// Package audit records and delivers authentication audit events.
package audit

import (
	"net"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// EventType identifies an audited operation.
type EventType string

// EventLoginSuccess and the following constants identify audit event types.
const (
	// EventLoginSuccess and the following values identify authentication events.
	EventLoginSuccess      EventType = "login.success"
	EventLoginFailed       EventType = "login.failed"
	EventLogout            EventType = "logout"
	EventAdminLoginSuccess EventType = "admin.login.success"
	EventAdminLoginFailed  EventType = "admin.login.failed"

	// EventUserRegistered identifies a user registration.
	EventUserRegistered EventType = "user.registered"

	// EventNameChanged and EventAccountDeleted identify self-service account changes.
	// user.name_changed fires from the profile
	// name change; user.account_deleted fires after a self-service account
	// deletion (password or emailed-code path) has fully succeeded. Both
	// are distinct from the admin.user.* family: the actor is the user,
	// never an admin.
	EventNameChanged    EventType = "user.name_changed"
	EventAccountDeleted EventType = "user.account_deleted"

	// EventEmailVerificationSent and EventEmailVerified identify email verification events.
	EventEmailVerificationSent EventType = "email.verification.sent"
	EventEmailVerified         EventType = "email.verified"

	// EventTwoFactorCodeSent and the following values identify two-factor events.
	EventTwoFactorCodeSent   EventType = "2fa.code.sent"
	EventTwoFactorVerified   EventType = "2fa.verified"
	EventTwoFactorFailed     EventType = "2fa.failed"
	EventTwoFactorEnabled    EventType = "2fa.enabled"
	EventTwoFactorDisabled   EventType = "2fa.disabled"
	EventTwoFactorSuspicious EventType = "2fa.suspicious"

	// EventPasswordChanged and the following values identify password events.
	EventPasswordChanged      EventType = "password.changed"
	EventPasswordResetRequest EventType = "password.reset.requested"
	EventPasswordResetDone    EventType = "password.reset.completed"

	// EventSessionCreated and the following values identify session events.
	EventSessionCreated    EventType = "session.created"
	EventSessionRefreshed  EventType = "session.refreshed"
	EventSessionRevoked    EventType = "session.revoked"
	EventSessionRevokedAll EventType = "session.revoked_all"
	// EventSessionRefreshReuseDetected fires when a refresh token that was
	// already rotated gets presented again outside the grace window — the
	// token has leaked, and the session it belonged to has already been
	// revoked as a theft-response measure by the time this publishes.
	EventSessionRefreshReuseDetected EventType = "session.refresh_reuse_detected"

	// EventOAuthLogin and the following values identify OAuth events.
	EventOAuthLogin    EventType = "oauth.login"
	EventOAuthLinked   EventType = "oauth.linked"
	EventOAuthUnlinked EventType = "oauth.unlinked"

	// EventAdminUserCreated and the following values identify administrator user events.
	EventAdminUserCreated  EventType = "admin.user.created"
	EventAdminUserUpdated  EventType = "admin.user.updated"
	EventAdminUserDeleted  EventType = "admin.user.deleted"
	EventAdminUserBanned   EventType = "admin.user.banned"
	EventAdminUserUnbanned EventType = "admin.user.unbanned"

	// EventAdminInviteCreated and the following values identify administrator invite events.
	// The target is an invite, not a user, so the invite id
	// and address ride in Metadata rather than TargetUserID.
	EventAdminInviteCreated EventType = "admin.invite.created"
	EventAdminInviteResent  EventType = "admin.invite.resent"
	EventAdminInviteRevoked EventType = "admin.invite.revoked"
	EventAdminInviteDeleted EventType = "admin.invite.deleted"

	// EventRoleChanged identifies a role change.
	EventRoleChanged EventType = "role.changed"

	// EventOrgCreated and the following values identify organization events.
	EventOrgCreated           EventType = "organization.created"
	EventOrgDeleted           EventType = "organization.deleted"
	EventOrgMemberInvited     EventType = "organization.member.invited"
	EventOrgMemberRemoved     EventType = "organization.member.removed"
	EventOrgMemberRoleChanged EventType = "organization.member.role_changed"

	// EventAdminOrgDeleted and the following values identify administrator organization events.
	// They are distinct from the EventOrg family so a
	// platform-admin override is never indistinguishable, in the audit log,
	// from the org's own owner/admin doing the same thing.
	EventAdminOrgDeleted           EventType = "admin.org.deleted"
	EventAdminOrgMemberAdded       EventType = "admin.org.member.added"
	EventAdminOrgMemberRemoved     EventType = "admin.org.member.removed"
	EventAdminOrgMemberRoleChanged EventType = "admin.org.member.role_changed"
	EventAdminOrgViewed            EventType = "admin.org.viewed"
)

// Severity classifies an audit event's importance.
type Severity string

// SeverityInfo and the following values are audit severity levels.
const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

// Event describes one audited operation.
type Event struct {
	ID            string                `json:"id"`
	Type          EventType             `json:"type"`
	Severity      Severity              `json:"severity"`
	Success       bool                  `json:"success"`
	ActorID       *string               `json:"actorId,omitempty"`
	TargetUserID  *string               `json:"targetUserId,omitempty"`
	SessionID     *string               `json:"sessionId,omitempty"`
	OrgID         *string               `json:"orgId,omitempty"`
	IP            net.IP                `json:"ip,omitempty"`
	UserAgent     string                `json:"userAgent,omitempty"`
	ParsedUA      *domain.UserAgentInfo `json:"parsedUA,omitempty"`
	RequestID     string                `json:"requestId,omitempty"`
	CorrelationID string                `json:"correlationId,omitempty"`
	Metadata      map[string]any        `json:"metadata,omitempty"`
	CreatedAt     time.Time             `json:"createdAt"`
}
