package goauth

import "net/http"

// ConfigDescription is a detached, data-only view of effective startup policy.
// It allowlists operational settings; credentials, connection strings, key
// material, provider configuration and live objects are never copied into it.
// Durations are strings in Go duration syntax. It is not an importable Config,
// a connectivity check, a permission decision or a worker-health snapshot.
// Browser is nil for TransportServices; HTTP rate limiting and management
// capabilities then report disabled, independently of their inactive options.
type ConfigDescription struct {
	Environment    Environment               `json:"environment"`
	Transport      Transport                 `json:"transport"`
	Browser        *BrowserDescription       `json:"browser,omitempty"`
	Session        SessionDescription        `json:"session"`
	Authentication AuthenticationDescription `json:"authentication"`
	Capabilities   CapabilityDescription     `json:"capabilities"`
	Database       DatabaseDescription       `json:"database"`
	RateLimit      RateLimitDescription      `json:"rateLimit"`
	Redis          RedisDescription          `json:"redis"`
	Background     BackgroundDescription     `json:"background"`
}

// BrowserDescription reports public origins and authentication-cookie policy.
// Challenge, CSRF and browser-binding cookies are always host-only at /.
type BrowserDescription struct {
	APIURL         string            `json:"apiUrl"`
	AllowedOrigins []string          `json:"allowedOrigins"`
	Cookies        CookieDescription `json:"cookies"`
}

// CookieDescription names cookies without including any cookie values.
// Domain and Path apply to session/refresh cookies in both app/admin contexts.
type CookieDescription struct {
	Name               string `json:"name"`
	RefreshName        string `json:"refreshName"`
	ChallengeName      string `json:"challengeName"`
	AdminName          string `json:"adminName"`
	AdminRefreshName   string `json:"adminRefreshName"`
	AdminChallengeName string `json:"adminChallengeName"`
	Domain             string `json:"domain"`
	Path               string `json:"path"`
	SameSite           string `json:"sameSite"`
	Secure             bool   `json:"secure"`
	HTTPOnly           bool   `json:"httpOnly"`
}

// SessionDescription reports resolved lifetimes, including explicit zero
// grace/debounce values and a zero MaxLifetime meaning no lifetime cap.
type SessionDescription struct {
	TTL             string `json:"ttl"`
	IdleTTL         string `json:"idleTtl"`
	RefreshTokenTTL string `json:"refreshTokenTtl"`
	MaxLifetime     string `json:"maxLifetime"`
	TokenTTL        string `json:"tokenTtl"`
	GraceWindow     string `json:"graceWindow"`
	TouchDebounce   string `json:"touchDebounce"`
}

// AuthenticationDescription reports method selection and global account policy.
// Account-specific settings and action-specific assurance checks still apply.
type AuthenticationDescription struct {
	EmailPassword             bool `json:"emailPassword"`
	OAuth                     bool `json:"oauth"`
	EmailPasswordRegistration bool `json:"emailPasswordRegistration"`
	OAuthRegistration         bool `json:"oauthRegistration"`
	PublicRegistration        bool `json:"publicRegistration"`
	InviteSignup              bool `json:"inviteSignup"`
	RequireEmailVerification  bool `json:"requireEmailVerification"`
	RequireEmail2FA           bool `json:"requireEmail2FA"`
	DefaultTwoFactor          bool `json:"defaultTwoFactor"`
	AdminTwoFactor            bool `json:"adminTwoFactor"`
}

// CapabilityDescription reports optional service availability and audit recording.
// OAuth availability means providers are registered; the authentication and
// registration policy determines which provider flows may be used.
type CapabilityDescription struct {
	EmailChange                 bool `json:"emailChange"`
	OAuth                       bool `json:"oauth"`
	Organizations               bool `json:"organizations"`
	AppPermissions              bool `json:"appPermissions"`
	AppPermissionManagementHTTP bool `json:"appPermissionManagementHttp"`
	OrgPermissions              bool `json:"orgPermissions"`
	OrgPermissionManagementHTTP bool `json:"orgPermissionManagementHttp"`
	Audit                       bool `json:"audit"`
}

// DatabaseDescription omits the connection string, addresses and live handles.
// Source is "url", "db" or "pool". A borrowed pgx pool has a library-owned
// SQL adapter, so CloseSQLHandle is true while CloseSuppliedPool stays false.
type DatabaseDescription struct {
	Driver            Driver                     `json:"driver"`
	Source            string                     `json:"source"`
	CloseSQLHandle    bool                       `json:"closeSqlHandle"`
	CloseSuppliedPool bool                       `json:"closeSuppliedPool"`
	URLLimits         *DatabaseLimitsDescription `json:"urlLimits,omitempty"`
}

// DatabaseLimitsDescription reports limits go-auth applies to a URL-created
// database. Borrowed DB/Pool limits are caller-managed and are not inspected.
type DatabaseLimitsDescription struct {
	MaxOpenConns    int    `json:"maxOpenConns"`
	MaxIdleConns    int    `json:"maxIdleConns"`
	ConnMaxLifetime string `json:"connMaxLifetime"`
	ConnMaxIdleTime string `json:"connMaxIdleTime"`
}

// RateDescription reports one request budget and its duration window.
type RateDescription struct {
	Requests int    `json:"requests"`
	Window   string `json:"window"`
}

// RateLimitDescription reports middleware policy, not route registration.
// Store is "disabled", "memory", "redis" or "custom". Custom stores and
// Redis clients remain caller-owned. Routes contains configured overrides;
// DisabledRoutes exemptions and enabled HTTP routes determine their use.
type RateLimitDescription struct {
	Enabled              bool                       `json:"enabled"`
	Store                string                     `json:"store"`
	CloseStoreOnShutdown bool                       `json:"closeStoreOnShutdown"`
	Default              RateDescription            `json:"default"`
	Routes               map[string]RateDescription `json:"routes"`
	DisabledRoutes       []string                   `json:"disabledRoutes"`
	TrustedIPs           []string                   `json:"trustedIps"`
	IPv6Subnet           int                        `json:"ipv6Subnet"`
	IPAddressHeader      string                     `json:"ipAddressHeader"`
}

// RedisDescription reports selected capabilities without client configuration,
// prefixes, addresses or keys. SQL remains authoritative for cached records.
type RedisDescription struct {
	Sessions               bool `json:"sessions"`
	Tokens                 bool `json:"tokens"`
	RateLimits             bool `json:"rateLimits"`
	TwoFactorNotifications bool `json:"twoFactorNotifications"`
}

// BackgroundDescription identifies library work enabled at startup. Config
// inspection predicts this work; it starts none. Auth inspection describes the
// constructed instance, not current worker health or whether Close was called.
// Cleanup inside caller-supplied integrations is outside this description.
type BackgroundDescription struct {
	Maintenance         bool   `json:"maintenance"`
	MaintenanceInterval string `json:"maintenanceInterval"`
	RecoveryEmail       bool   `json:"recoveryEmail"`
	AuditDelivery       bool   `json:"auditDelivery"`
	AuditRetention      bool   `json:"auditRetention"`
	RateLimitCleanup    bool   `json:"rateLimitCleanup"`
	TwoFactorCleanup    bool   `json:"twoFactorCleanup"`
}

// Describe resolves and validates a private copy using the same rules as New.
// It opens no connections and starts no workers. Validation can consult custom
// integration metadata, just as NewConfig does. Errors return a zero description.
// Apply options sequentially; concurrent mutation of Config is unsupported.
func (c *Config) Describe() (ConfigDescription, error) {
	cfg, err := resolveConfig(c)
	if err != nil {
		return ConfigDescription{}, err
	}
	return describeConfig(&cfg), nil
}

// Describe returns the effective startup policy captured by this Auth instance.
// Returned collections are detached. It performs no SQL/Redis calls and does
// not invoke integration methods. Startup policy remains inspectable after Close.
func (a *Auth) Describe() ConfigDescription {
	return describeConfig(&a.cfg)
}

func describeConfig(c *Config) ConfigDescription {
	redis := RedisDescription{}
	if r := c.redis; r != nil {
		redis = RedisDescription{
			Sessions: redisEnabled(r.Sessions), Tokens: redisEnabled(r.Tokens),
			RateLimits:             c.httpRateLimitEnabled() && redisEnabled(r.RateLimits),
			TwoFactorNotifications: redisEnabled(r.TwoFactorNotifications),
		}
	}
	var browser *BrowserDescription
	if c.browserEnabled() {
		browser = describeBrowser(c)
	}
	rate := describeRateLimit(c, redis)
	return ConfigDescription{
		Environment: c.app.Environment.normalize(), Transport: c.transport, Browser: browser,
		Session: SessionDescription{
			TTL: c.session.TTL.String(), IdleTTL: c.session.IdleTTL.String(),
			RefreshTokenTTL: c.session.RefreshTokenTTL.String(), MaxLifetime: c.session.MaxLifetime.String(),
			TokenTTL: c.session.TokenTTL.String(), GraceWindow: c.resolved.graceWindow.String(),
			TouchDebounce: c.resolved.touchDebounce.String(),
		},
		Authentication: AuthenticationDescription{
			EmailPassword: c.authentication.EmailPassword, OAuth: c.authentication.OAuth,
			EmailPasswordRegistration: c.registration.EmailPassword, OAuthRegistration: c.registration.OAuth,
			PublicRegistration: c.registration.AllowPublic, InviteSignup: c.registration.InviteSignup,
			RequireEmailVerification: c.registration.RequireEmailVerification,
			RequireEmail2FA:          c.twoFactor.RequireEmail2FA, DefaultTwoFactor: c.twoFactor.DefaultEnabled,
			AdminTwoFactor: !c.twoFactor.DisableAdminTwoFactor,
		},
		Capabilities: CapabilityDescription{
			EmailChange: c.security.AllowEmailChange, OAuth: len(c.providers) > 0,
			Organizations: c.organizations.Enable, AppPermissions: c.appPermissions.Enable,
			OrgPermissions: c.orgPermissions.Enable, Audit: c.audit.Enabled,
			AppPermissionManagementHTTP: c.browserEnabled() && c.appPermissions.EnableManagementHTTP,
			OrgPermissionManagementHTTP: c.browserEnabled() && c.orgPermissions.EnableManagementHTTP,
		},
		Database: describeDatabase(c.app.Database), RateLimit: rate, Redis: redis,
		Background: BackgroundDescription{
			Maintenance: !c.maintenance.Disable, MaintenanceInterval: c.maintenance.withDefaults().Interval.String(),
			RecoveryEmail:    c.mailer != nil || c.email != nil,
			AuditDelivery:    c.audit.Enabled && len(c.audit.Sinks)+len(c.auditSinks) > 0,
			AuditRetention:   c.audit.Enabled && c.audit.RetentionDays > 0,
			RateLimitCleanup: rate.CloseStoreOnShutdown, TwoFactorCleanup: !redis.TwoFactorNotifications,
		},
	}
}

func describeBrowser(c *Config) *BrowserDescription {
	b := c.browser.Cookies
	sameSite := "default"
	switch b.SameSite {
	case http.SameSiteLaxMode:
		sameSite = "lax"
	case http.SameSiteStrictMode:
		sameSite = "strict"
	case http.SameSiteNoneMode:
		sameSite = "none"
	}
	return &BrowserDescription{
		APIURL: c.resolved.apiURL, AllowedOrigins: append([]string(nil), c.browser.AllowedOrigins...),
		Cookies: CookieDescription{
			Name: b.Name, RefreshName: b.RefreshName, ChallengeName: b.ChallengeName,
			AdminName: b.AdminName, AdminRefreshName: b.AdminRefreshName, AdminChallengeName: b.AdminChallengeName,
			Domain: b.Domain, Path: b.Path, SameSite: sameSite, Secure: c.resolved.cookieSecure, HTTPOnly: true,
		},
	}
}

func describeDatabase(c DatabaseConfig) DatabaseDescription {
	d := DatabaseDescription{Driver: c.Driver}
	switch {
	case c.Pool != nil:
		d.Source, d.CloseSQLHandle = "pool", true
	case c.DB != nil:
		d.Source = "db"
	default:
		d.Source, d.CloseSQLHandle = "url", true
		open, idle, _ := c.connectionLimits() // configuration was validated
		d.URLLimits = &DatabaseLimitsDescription{
			MaxOpenConns: open, MaxIdleConns: idle,
			ConnMaxLifetime: c.ConnMaxLifetime.String(), ConnMaxIdleTime: c.ConnMaxIdleTime.String(),
		}
	}
	return d
}

func describeRateLimit(c *Config, redis RedisDescription) RateLimitDescription {
	if !c.browserEnabled() {
		// Inactive HTTP intent is neither effective policy nor diagnostic data.
		return RateLimitDescription{Store: "disabled", Default: RateDescription{Window: "0s"}}
	}
	r := c.rateLimit
	d := RateLimitDescription{
		Enabled: c.httpRateLimitEnabled(), Store: "disabled",
		Default:        RateDescription{Requests: r.Default.Requests, Window: r.Default.Window.String()},
		Routes:         make(map[string]RateDescription, len(r.Routes)),
		DisabledRoutes: append([]string(nil), r.DisabledRoutes...), TrustedIPs: append([]string(nil), r.TrustedIPs...),
		IPv6Subnet: r.IPv6Subnet, IPAddressHeader: r.IPAddressHeader,
	}
	for pattern, rate := range r.Routes {
		d.Routes[pattern] = RateDescription{Requests: rate.Requests, Window: rate.Window.String()}
	}
	if d.Enabled {
		switch {
		case redis.RateLimits:
			d.Store = "redis"
		case c.set.rateLimitStore:
			d.Store = "custom"
		default:
			d.Store, d.CloseStoreOnShutdown = "memory", true
		}
	}
	return d
}
