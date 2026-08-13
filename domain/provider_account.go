package domain

import "time"

// ProviderAccount links a user to one OAuth provider identity. AccessToken
// and RefreshToken are encrypted at rest (see internal/crypto, wired up in
// New() when the app secret is present) and are never serialized — a
// consumer that needs them must read the repository directly, not this
// struct's zero-valued fields.
type ProviderAccount struct {
	ID             string     `json:"id"`
	UserID         string     `json:"userId"`
	Provider       string     `json:"provider"`
	ProviderUserID string     `json:"providerUserId"`
	ProviderEmail  string     `json:"providerEmail"`
	ProviderName   string     `json:"providerName"`
	AvatarURL      string     `json:"avatarUrl"`
	AccessToken    string     `json:"-"`
	RefreshToken   string     `json:"-"`
	TokenExpiresAt *time.Time `json:"tokenExpiresAt,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
}
