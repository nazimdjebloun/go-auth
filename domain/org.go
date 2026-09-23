package domain

import "time"

// OrgRole identifies a member's permissions in an organization.
type OrgRole string

// OrgRoleOwner and the following values are valid organization roles.
const (
	OrgRoleOwner  OrgRole = "owner"
	OrgRoleAdmin  OrgRole = "admin"
	OrgRoleMember OrgRole = "member"
)

// IsValid reports whether r is a supported organization role.
func (r OrgRole) IsValid() bool {
	switch r {
	case OrgRoleOwner, OrgRoleAdmin, OrgRoleMember:
		return true
	default:
		return false
	}
}

// Weight returns the role's permission rank, or zero for an unknown role.
func (r OrgRole) Weight() int {
	switch r {
	case OrgRoleOwner:
		return 3
	case OrgRoleAdmin:
		return 2
	case OrgRoleMember:
		return 1
	default:
		return 0
	}
}

// Organization holds an organization's identity, counts, and metadata.
type Organization struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Slug        string                 `json:"slug"`
	CreatedBy   *string                `json:"createdBy,omitempty"`
	OwnerCount  int                    `json:"ownerCount"`
	MemberCount int                    `json:"memberCount"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"createdAt"`
	UpdatedAt   time.Time              `json:"updatedAt"`
}

// OrgMember records a user's role in an organization.
type OrgMember struct {
	OrgID    string    `json:"orgId"`
	UserID   string    `json:"userId"`
	Role     OrgRole   `json:"role"`
	JoinedAt time.Time `json:"joinedAt"`
}

// OrgMemberDetail combines a membership with its user.
type OrgMemberDetail struct {
	OrgMember
	User *User `json:"user"`
}

// OrgInvite records an invitation to join an organization.
type OrgInvite struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"orgId"`
	Email     string    `json:"email"`
	Role      OrgRole   `json:"role"`
	CodeHash  string    `json:"-"`
	RawCode   string    `json:"rawCode,omitempty"` // populated once on creation, omitted in list
	InvitedBy string    `json:"invitedBy"`
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

// ReservedOrgSlugs lists slugs unavailable for organization creation.
var ReservedOrgSlugs = map[string]bool{
	"api": true, "admin": true, "auth": true, "www": true, "app": true,
	"static": true, "assets": true, "public": true, "cdn": true, "status": true,
	"billing": true, "settings": true, "support": true, "help": true, "login": true,
	"register": true, "signup": true, "logout": true, "oauth": true, "root": true,
	"system": true, "org": true, "orgs": true, "organization": true, "organizations": true,
}
