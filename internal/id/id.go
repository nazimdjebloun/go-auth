// Package id is go-auth's single source of identifier generation.
//
// Every stored row the library creates — users, sessions, tokens, invites,
// orgs, audit events — takes its primary key from New(). Keeping that in one
// place makes the ID format one decision rather than one per package: changing
// to a sortable format (UUIDv7, ULID) is a change here, not a hunt for every
// uuid.New() call site.
package id

import "github.com/google/uuid"

// New returns a random (version 4) UUID in its canonical string form.
func New() string {
	return uuid.New().String()
}
