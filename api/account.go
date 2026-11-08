package api

import "github.com/nazimdjebloun/go-auth/domain"

// ChangeOwnPasswordInput changes the bound account's password and retains only
// its initiating session. Target user/session IDs are never client inputs.
type ChangeOwnPasswordInput struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

// ConfirmOwnSetPasswordInput proves password setup for the bound account.
type ConfirmOwnSetPasswordInput struct {
	Code        string `json:"code"`
	NewPassword string `json:"newPassword"`
}

// SessionPageInput bounds an account's session listing. Nonpositive Limit uses
// 20, Limit caps at 100, and negative Offset starts at the first row.
type SessionPageInput struct {
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
}

// EnableOwnTwoFactorInput carries the bound user's password or settings proof.
type EnableOwnTwoFactorInput struct {
	Password          string `json:"password"`
	ChallengeID       string `json:"challengeId,omitempty"`
	Code              string `json:"code,omitempty"`
	KeepOtherSessions bool   `json:"keepOtherSessions"`
}

// DisableOwnTwoFactorInput proves disabling the bound user's optional setting.
type DisableOwnTwoFactorInput struct {
	Password    string `json:"password"`
	ChallengeID string `json:"challengeId,omitempty"`
	Code        string `json:"code,omitempty"`
}

// CreateOwnOrgInput creates an organization owned by the bound account.
type CreateOwnOrgInput struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// ListOwnOrgsInput filters the bound account's memberships, never another user.
type ListOwnOrgsInput struct {
	Search         *string          `json:"search,omitempty"`
	Role           *domain.OrgRole  `json:"role,omitempty"`
	OrderBy        UserOrgSortField `json:"orderBy,omitempty"`
	OrderDirection SortDirection    `json:"orderDirection,omitempty"`
	Offset         int              `json:"offset"`
	Limit          *int             `json:"limit,omitempty"`
}
