package port

import (
	"context"
	"time"
)

type ProviderUserInfo struct {
	Provider       string
	ProviderID     string
	Email          string
	EmailVerified  bool
	Name           string
	AvatarURL      string
	AccessToken    string
	RefreshToken   string
	TokenExpiresAt *time.Time
}

type Provider interface {
	Name() string
	GetAuthorizeURL(state string) string
	ExchangeCode(ctx context.Context, code string) (*ProviderUserInfo, error)
}
