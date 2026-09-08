package service

import "github.com/nazimdjebloun/go-auth/internal/id"

// generateID is a package-local alias for internal/id.New. It stays a wrapper
// rather than being inlined at the call sites because "id" is already a common
// loop variable in this package (see admin_bulk.go, invite.go), and an
// id.New() call inside one of those loops would resolve to the variable.
func generateID() string {
	return id.New()
}
