package domain

import "time"

type Session struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	TokenHash    string    `json:"-"`
	RefreshToken string    `json:"-"`
	IP           string    `json:"ip,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	IsRevoked    bool      `json:"is_revoked"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}
