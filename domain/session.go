package domain

import (
	"encoding/json"
	"time"

	ua "github.com/mileusna/useragent"
)

type UserAgentInfo struct {
	BrowserName    string `json:"browser"`
	BrowserVersion string `json:"browser_version,omitempty"`
	OS             string `json:"os"`
	OSVersion      string `json:"os_version,omitempty"`
	DeviceType     string `json:"device_type"`
}

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

func (u *UserAgentInfo) MarshalJSON() ([]byte, error) {
	type Alias UserAgentInfo
	return json.Marshal((*Alias)(u))
}

func ParseUserAgentFromJSON(data []byte) *UserAgentInfo {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	var info UserAgentInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil
	}
	return &info
}

type Session struct {
	ID                  string         `json:"id"`
	UserID              string         `json:"user_id"`
	TokenHash           string         `json:"-"`
	RefreshTokenHash    string         `json:"-"`
	PreviousRefreshHash string         `json:"-"`
	IP                  string         `json:"ip_address,omitempty"`
	UserAgent           string         `json:"user_agent,omitempty"`
	ParsedUA            *UserAgentInfo `json:"parsed_ua,omitempty"`
	IsRevoked           bool           `json:"is_revoked"`
	ExpiresAt           time.Time      `json:"expires_at"`
	RefreshExpiresAt    time.Time      `json:"refresh_expires_at,omitempty"`
	RefreshRotatedAt    *time.Time     `json:"refresh_rotated_at,omitempty"`
	CreatedAt           time.Time      `json:"created_at"`
	RevokedAt           *time.Time     `json:"revoked_at,omitempty"`
	LastActiveAt        time.Time      `json:"last_active_at,omitempty"`

	ActiveOrgID   *string `json:"active_org_id,omitempty"`
	ActiveOrgRole *string `json:"active_org_role,omitempty"`
}
