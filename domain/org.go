package domain

import "time"

type OrgRole string

const (
	OrgRoleOwner  OrgRole = "owner"
	OrgRoleAdmin  OrgRole = "admin"
	OrgRoleMember OrgRole = "member"
)

func (r OrgRole) IsValid() bool {
	switch r {
	case OrgRoleOwner, OrgRoleAdmin, OrgRoleMember:
		return true
	default:
		return false
	}
}

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

type Organization struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Slug        string                 `json:"slug"`
	CreatedBy   *string                `json:"created_by,omitempty"`
	OwnerCount  int                    `json:"owner_count"`
	MemberCount int                    `json:"member_count"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

type OrgMember struct {
	OrgID    string    `json:"org_id"`
	UserID   string    `json:"user_id"`
	Role     OrgRole   `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
}

type OrgMemberDetail struct {
	OrgMember
	User *User `json:"user"`
}

type OrgInvite struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Email     string    `json:"email"`
	Role      OrgRole   `json:"role"`
	CodeHash  string    `json:"-"`
	RawCode   string    `json:"rawCode,omitempty"` // populated once on creation, omitted in list
	InvitedBy string    `json:"invited_by"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

var ReservedOrgSlugs = map[string]bool{
	"api": true, "admin": true, "auth": true, "www": true, "app": true,
	"static": true, "assets": true, "public": true, "cdn": true, "status": true,
	"billing": true, "settings": true, "support": true, "help": true, "login": true,
	"register": true, "signup": true, "logout": true, "oauth": true, "root": true,
	"system": true, "org": true, "orgs": true, "organization": true, "organizations": true,
}
