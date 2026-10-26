package domain

import "time"

// OrgPermission is an installed business or library delegation definition.
type OrgPermission struct {
	OrgID       string    `json:"orgId"`
	ID          string    `json:"id"`
	Key         string    `json:"key"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsEnabled   bool      `json:"isEnabled"`
	IsSystem    bool      `json:"isSystem"`
	Revision    uint64    `json:"revision"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// OrgPermissionRole has one explicit permission set; protected roles have fixed policy.
type OrgPermissionRole struct {
	OrgID          string    `json:"orgId"`
	ID             string    `json:"id"`
	Slug           string    `json:"slug"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	IsEnabled      bool      `json:"isEnabled"`
	SystemKey      *string   `json:"systemKey,omitempty"`
	Revision       uint64    `json:"revision"`
	PermissionKeys []string  `json:"permissionKeys"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

// IsOwner recognizes the immutable full-access organization identity.
func (r *OrgPermissionRole) IsOwner() bool {
	return r != nil && r.IsEnabled && r.SystemKey != nil && *r.SystemKey == string(OrgRoleOwner)
}

// OrgLibraryPermissionDefinition describes a supported action independently of SQL.
type OrgLibraryPermissionDefinition struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
}
