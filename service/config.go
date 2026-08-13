package service

import (
	"log/slog"
	"time"
)

// CommonConfig groups the fields every service config needs, so they're
// derived once in Auth.New() and embedded into each service's own config
// rather than independently assigned — the same six fields drifting between
// Config and OAuthServiceConfig (e.g. a future change to how SessionTTL is
// derived that updates one but not the other) would compile fine and only
// surface as an inconsistency at runtime between password-login and
// OAuth-login session lifetimes.
type CommonConfig struct {
	AppName    string
	BaseURL    string
	SessionTTL time.Duration
	TokenTTL   time.Duration
	Logger     *slog.Logger
	Audit      AuditPublisher
}
