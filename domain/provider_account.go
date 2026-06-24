package domain

import "time"

type ProviderAccount struct {
	ID             string
	UserID         string
	Provider       string
	ProviderUserID string
	ProviderEmail  string
	ProviderName   string
	AvatarURL      string
	AccessToken    string
	RefreshToken   string
	TokenExpiresAt *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
