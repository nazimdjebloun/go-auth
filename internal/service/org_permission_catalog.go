package service

import "github.com/nazimdjebloun/go-auth/domain"

var orgLibraryCatalog = []domain.OrgLibraryPermissionDefinition{
	{Key: "goauth.org.organization.delete", Name: "Delete organization", Description: "Delete organization within this organization"},
	{Key: "goauth.org.invites.create", Name: "Create invitations", Description: "Create invitations within this organization"},
	{Key: "goauth.org.invites.delete", Name: "Delete invitations", Description: "Delete invitations within this organization"},
	{Key: "goauth.org.invites.read", Name: "Read invitations", Description: "Read invitations within this organization"},
	{Key: "goauth.org.invites.resend", Name: "Resend invitations", Description: "Resend invitations within this organization"},
	{Key: "goauth.org.members.create", Name: "Add members", Description: "Add members within this organization"},
	{Key: "goauth.org.members.read", Name: "Read members", Description: "Read members within this organization"},
	{Key: "goauth.org.members.remove", Name: "Remove members", Description: "Remove members within this organization"},
	{Key: "goauth.org.permissions.create", Name: "Create permissions", Description: "Create permissions within this organization"},
	{Key: "goauth.org.permissions.delete", Name: "Delete permissions", Description: "Delete permissions within this organization"},
	{Key: "goauth.org.permissions.read", Name: "Read permissions", Description: "Read permissions within this organization"},
	{Key: "goauth.org.permissions.update", Name: "Update permissions", Description: "Update permissions within this organization"},
	{Key: "goauth.org.organization.read", Name: "Read organization", Description: "Read organization within this organization"},
	{Key: "goauth.org.roles.assign", Name: "Assign roles", Description: "Assign roles within this organization"},
	{Key: "goauth.org.roles.create", Name: "Create roles", Description: "Create roles within this organization"},
	{Key: "goauth.org.roles.delete", Name: "Delete roles", Description: "Delete roles within this organization"},
	{Key: "goauth.org.roles.read", Name: "Read roles", Description: "Read roles within this organization"},
	{Key: "goauth.org.roles.update", Name: "Update roles", Description: "Update roles within this organization"},
	{Key: "goauth.org.organization.update", Name: "Update organization", Description: "Update organization within this organization"},
}

func orgLibraryDefinition(key string) (domain.OrgLibraryPermissionDefinition, bool) {
	for _, d := range orgLibraryCatalog {
		if d.Key == key {
			return d, true
		}
	}
	return domain.OrgLibraryPermissionDefinition{}, false
}

func orgPreset(identity string) []string {
	keys := []string{}
	if identity == "owner" {
		for _, d := range orgLibraryCatalog {
			keys = append(keys, d.Key)
		}
		return keys
	}
	if identity == "member" {
		return []string{"goauth.org.members.read", "goauth.org.organization.read"}
	}
	if identity == "admin" {
		return []string{"goauth.org.invites.create", "goauth.org.invites.delete", "goauth.org.invites.read", "goauth.org.invites.resend", "goauth.org.members.create", "goauth.org.members.read", "goauth.org.members.remove", "goauth.org.organization.read", "goauth.org.roles.assign", "goauth.org.organization.update"}
	}
	return keys
}
