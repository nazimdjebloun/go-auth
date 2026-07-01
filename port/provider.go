package port

import (
	"context"
	"time"
)

type OAuthProfile struct {
	Provider       string
	ProviderUserID string
	Email          string
	EmailVerified  bool
	Name           string
	AvatarURL      string
	AccessToken    string
	RefreshToken   string
	TokenExpiresAt *time.Time
	Raw            map[string]any
}

type OAuthProvider interface {
	Name() string
	AuthURL(state string) string
	Exchange(ctx context.Context, code string) (*OAuthProfile, error)
}
