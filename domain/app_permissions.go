package domain

import "time"

// AppRoleAdmin and AppRoleUser identify protected roles independently of names.
const (
	AppRoleAdmin = "platform_admin"
	AppRoleUser  = "user"
)

// AppPermission is an installed business or library delegation definition.
type AppPermission struct {
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

// AppRole has one explicit permission set; protected roles have fixed policy.
type AppRole struct {
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

// IsAdmin recognizes the protected full-access identity, never a custom name.
func (r *AppRole) IsAdmin() bool {
	return r != nil && r.IsEnabled && r.SystemKey != nil && *r.SystemKey == AppRoleAdmin
}

// AppLibraryPermissionDefinition describes a supported action independently of SQL.
type AppLibraryPermissionDefinition struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
}
