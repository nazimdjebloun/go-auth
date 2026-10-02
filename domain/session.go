package domain

import (
	"time"

	ua "github.com/mileusna/useragent"
)

// UserAgentInfo contains browser, operating system, and device details.
type UserAgentInfo struct {
	BrowserName    string `json:"browser"`
	BrowserVersion string `json:"browserVersion,omitempty"`
	OS             string `json:"os"`
	OSVersion      string `json:"osVersion,omitempty"`
	DeviceType     string `json:"deviceType"`
}

// ParseUserAgent parses a user-agent string into normalized device details.
func ParseUserAgent(raw string) *UserAgentInfo {
	parsed := ua.Parse(raw)
	info := &UserAgentInfo{
		BrowserName:    parsed.Name,
		BrowserVersion: parsed.VersionNoShort(),
		OS:             parsed.OS,
		OSVersion:      parsed.OSVersion,
	}
	switch {
	case parsed.Bot:
		info.DeviceType = "bot"
	case parsed.Mobile:
		info.DeviceType = "mobile"
	case parsed.Tablet:
		info.DeviceType = "tablet"
	default:
		info.DeviceType = "desktop"
	}
	return info
}

// Session records an authenticated login and its token lifecycle.
type Session struct {
	ID                  string         `json:"id"`
	UserID              string         `json:"userId"`
	TokenHash           string         `json:"-"`
	RefreshTokenHash    string         `json:"-"`
	PreviousRefreshHash string         `json:"-"`
	IP                  string         `json:"ipAddress,omitempty"`
	UserAgent           string         `json:"userAgent,omitempty"`
	ParsedUA            *UserAgentInfo `json:"parsedUA,omitempty"`
	IsRevoked           bool           `json:"isRevoked"`
	ExpiresAt           time.Time      `json:"expiresAt"`
	RefreshExpiresAt    time.Time      `json:"refreshExpiresAt,omitempty"`
	RefreshRotatedAt    *time.Time     `json:"refreshRotatedAt,omitempty"`
	CreatedAt           time.Time      `json:"createdAt"`
	RevokedAt           *time.Time     `json:"revokedAt,omitempty"`
	LastActiveAt        time.Time      `json:"lastActiveAt,omitempty"`
	// Set only when the session is created after a successful 2FA claim.
	TwoFactorVerifiedAt *time.Time `json:"-"`

	ActiveOrgID   *string `json:"activeOrgId,omitempty"`
	ActiveOrgRole *string `json:"activeOrgRole,omitempty"`
}
