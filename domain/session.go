package domain

import "time"

type Session struct {
	ID                  string     `json:"id"`
	UserID              string     `json:"user_id"`
	TokenHash           string     `json:"-"`
	RefreshTokenHash    string     `json:"-"`
	PreviousRefreshHash string     `json:"-"`
	IP                  string     `json:"ip_address,omitempty"`
	UserAgent           string     `json:"user_agent,omitempty"`
	IsRevoked           bool       `json:"is_revoked"`
	ExpiresAt           time.Time  `json:"expires_at"`
	RefreshExpiresAt    time.Time  `json:"refresh_expires_at,omitempty"`
	RefreshRotatedAt    *time.Time `json:"refresh_rotated_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
	LastActiveAt        time.Time  `json:"last_active_at,omitempty"`
}
