package service

import (
	"slices"

	"github.com/nazimdjebloun/go-auth/domain"
)

var appLibraryCatalog = []domain.AppLibraryPermissionDefinition{
	{Key: "goauth.app.audit.read", Name: "Read audit records", Description: "Inspect application audit records"},
	{Key: "goauth.app.invites.create", Name: "Create signup invitations", Description: "Invite accounts to the application"},
	{Key: "goauth.app.invites.delete", Name: "Delete signup invitations", Description: "Delete signup invitations"},
	{Key: "goauth.app.invites.read", Name: "Read signup invitations", Description: "Inspect signup invitations"},
	{Key: "goauth.app.invites.resend", Name: "Resend signup invitations", Description: "Resend invitation email"},
	{Key: "goauth.app.invites.revoke", Name: "Revoke signup invitations", Description: "Revoke pending signup invitations"},
	{Key: "goauth.app.permissions.create", Name: "Create permissions", Description: "create custom application permissions"},
	{Key: "goauth.app.permissions.delete", Name: "Delete permissions", Description: "delete custom application permissions"},
	{Key: "goauth.app.permissions.read", Name: "Read permissions", Description: "read custom application permissions"},
	{Key: "goauth.app.permissions.update", Name: "Update permissions", Description: "update custom application permissions"},
	{Key: "goauth.app.roles.assign", Name: "Assign roles", Description: "Replace account application roles"},
	{Key: "goauth.app.roles.create", Name: "Create roles", Description: "create custom application roles"},
	{Key: "goauth.app.roles.delete", Name: "Delete roles", Description: "delete custom application roles"},
	{Key: "goauth.app.roles.read", Name: "Read roles", Description: "read custom application roles"},
	{Key: "goauth.app.roles.update", Name: "Update roles", Description: "update custom application roles"},
	{Key: "goauth.app.sessions.read", Name: "Read sessions", Description: "Inspect and list application sessions"},
	{Key: "goauth.app.sessions.revoke", Name: "Revoke sessions", Description: "Revoke sessions through application administration"},
	{Key: "goauth.app.stats.read", Name: "Read statistics", Description: "Inspect account and session statistics"},
	{Key: "goauth.app.users.ban", Name: "Ban accounts", Description: "Ban application accounts"},
	{Key: "goauth.app.users.create", Name: "Create accounts", Description: "Create application accounts"},
	{Key: "goauth.app.users.delete", Name: "Delete accounts", Description: "Delete application accounts"},
	{Key: "goauth.app.users.read", Name: "Read accounts", Description: "Inspect and list application accounts"},
	{Key: "goauth.app.users.unban", Name: "Unban accounts", Description: "Unban application accounts"},
}

// AppLibraryPermissionCatalog returns a copy of the fixed catalog without SQL.
func AppLibraryPermissionCatalog() []domain.AppLibraryPermissionDefinition {
	return slices.Clone(appLibraryCatalog)
}

func appLibraryDefinition(key string) (domain.AppLibraryPermissionDefinition, bool) {
	for _, d := range appLibraryCatalog {
		if d.Key == key {
			return d, true
		}
	}
	return domain.AppLibraryPermissionDefinition{}, false
}
