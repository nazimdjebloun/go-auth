package audit

import (
	"net"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

type EventType string

const (
	// Authentication
	EventLoginSuccess      EventType = "login.success"
	EventLoginFailed       EventType = "login.failed"
	EventLoginLocked       EventType = "login.locked"
	EventLogout            EventType = "logout"
	EventAdminLoginSuccess EventType = "admin.login.success"
	EventAdminLoginFailed  EventType = "admin.login.failed"

	// Registration
	EventUserRegistered EventType = "user.registered"

	// Email
	EventEmailVerificationSent EventType = "email.verification.sent"
	EventEmailVerified        EventType = "email.verified"

	// Password
	EventPasswordChanged      EventType = "password.changed"
	EventPasswordResetRequest EventType = "password.reset.requested"
	EventPasswordResetDone    EventType = "password.reset.completed"

	// Sessions
	EventSessionCreated    EventType = "session.created"
	EventSessionRefreshed  EventType = "session.refreshed"
	EventSessionRevoked    EventType = "session.revoked"
	EventSessionRevokedAll EventType = "session.revoked_all"

	// OAuth
	EventOAuthLogin    EventType = "oauth.login"
	EventOAuthLinked   EventType = "oauth.linked"
	EventOAuthUnlinked EventType = "oauth.unlinked"

	// Admin
	EventAdminUserCreated  EventType = "admin.user.created"
	EventAdminUserUpdated  EventType = "admin.user.updated"
	EventAdminUserDeleted  EventType = "admin.user.deleted"
	EventAdminUserBanned   EventType = "admin.user.banned"
	EventAdminUserUnbanned EventType = "admin.user.unbanned"

	// Roles
	EventRoleChanged EventType = "role.changed"

	// Organizations
	EventOrgCreated         EventType = "organization.created"
	EventOrgDeleted         EventType = "organization.deleted"
	EventOrgMemberInvited   EventType = "organization.member.invited"
	EventOrgMemberRemoved   EventType = "organization.member.removed"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

type Event struct {
	ID            string                 `json:"id"`
	Type          EventType              `json:"type"`
	Severity      Severity               `json:"severity"`
	Success       bool                   `json:"success"`
	ActorID       *string                `json:"actorId,omitempty"`
	TargetUserID  *string                `json:"targetUserId,omitempty"`
	SessionID     *string                `json:"sessionId,omitempty"`
	OrgID         *string                `json:"orgId,omitempty"`
	IP            net.IP                 `json:"ip,omitempty"`
	UserAgent     string                 `json:"userAgent,omitempty"`
	ParsedUA      *domain.UserAgentInfo  `json:"parsedUA,omitempty"`
	RequestID     string                 `json:"requestId,omitempty"`
	CorrelationID string                 `json:"correlationId,omitempty"`
	Metadata      map[string]any         `json:"metadata,omitempty"`
	CreatedAt     time.Time              `json:"createdAt"`
}
