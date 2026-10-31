package goauth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// BrowserConfig describes the public HTTP deployment. CSRF and challenge
// binding are mandatory; this section only configures browser transport.
type BrowserConfig struct {
	APIURL         string   // public API origin; defaults to the origin of AppConfig.BaseURL
	AllowedOrigins []string // exact frontend origins; no wildcards
	Cookies        CookieConfig
}

// CookieConfig controls authentication-cookie delivery. CSRF and browser
// binding cookies remain host-only at / and inherit Secure and SameSite.
// Every authentication, challenge, and CSRF cookie is HttpOnly.
type CookieConfig struct {
	Name               string        // default goauth_session
	RefreshName        string        // default goauth_refresh
	ChallengeName      string        // default _2fa_challenge
	AdminName          string        // default goauth_admin_session
	AdminRefreshName   string        // default goauth_admin_refresh
	AdminChallengeName string        // default _goauth_admin_2fa_challenge
	Domain             string        // session/refresh scope; empty means host-only
	Path               string        // session/refresh path; default /; must be / for built-in routes
	SameSite           http.SameSite // default Lax
	Secure             *bool         // nil derives from APIURL and Environment; false is development-only
}

// WithBrowser configures browser origins and cookie delivery. Repeated calls
// replace this section. Slices and pointer values are copied on application.
func WithBrowser(cfg BrowserConfig) Option {
	return func(c *Config) {
		c.browser = cfg
		c.browser.AllowedOrigins = append([]string(nil), cfg.AllowedOrigins...)
		if cfg.Cookies.Secure != nil {
			v := *cfg.Cookies.Secure
			c.browser.Cookies.Secure = &v
		}
	}
}

// SecureAlways requires secure cookies, including in development.
func SecureAlways() *bool { return boolPtr(true) }

// SecureNever permits ordinary HTTP cookies in EnvironmentDev only.
func SecureNever() *bool { return boolPtr(false) }

func (c *Config) applyBrowserDefaults() {
	c.resolved.apiURL = c.browser.APIURL
	if c.resolved.apiURL == "" {
		if u, err := url.Parse(c.app.BaseURL); err == nil {
			c.resolved.apiURL = u.Scheme + "://" + u.Host
		}
	}
	b := &c.browser.Cookies
	if b.Name == "" {
		b.Name = "goauth_session"
	}
	if b.RefreshName == "" {
		b.RefreshName = "goauth_refresh"
	}
	if b.ChallengeName == "" {
		b.ChallengeName = "_2fa_challenge"
	}
	if b.AdminName == "" {
		b.AdminName = "goauth_admin_session"
	}
	if b.AdminRefreshName == "" {
		b.AdminRefreshName = "goauth_admin_refresh"
	}
	if b.AdminChallengeName == "" {
		b.AdminChallengeName = "_goauth_admin_2fa_challenge"
	}
	if b.Path == "" {
		b.Path = "/"
	}
	if b.SameSite == 0 {
		b.SameSite = http.SameSiteLaxMode
	}
	c.resolved.cookieSecure = c.resolveCookieSecure()
}

func (c *Config) resolveCookieSecure() bool {
	if c.browser.Cookies.Secure != nil {
		return *c.browser.Cookies.Secure
	}
	u, err := url.Parse(c.resolved.apiURL)
	return c.app.Environment.normalize() != EnvironmentDev || err != nil || u.Scheme != "http"
}

func parseBrowserOrigin(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") ||
		u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Path != "" ||
		u.RawQuery != "" || u.ForceQuery || strings.Contains(value, "#") || strings.Contains(u.Hostname(), "*") || strings.TrimSpace(value) != value {
		return nil, errors.New("must be an HTTP or HTTPS origin without credentials, path, query, or fragment")
	}
	if p := u.Port(); p != "" {
		if port, err := strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			return nil, errors.New("invalid origin port")
		}
	}
	return u, nil
}

func (c *Config) validateBrowser() []error {
	var errs []error
	dev := c.app.Environment.normalize() == EnvironmentDev
	u, err := parseBrowserOrigin(c.resolved.apiURL)
	if err != nil {
		errs = append(errs, fmt.Errorf("browser: api_url %w", err))
	} else if !dev && u.Scheme != "https" {
		errs = append(errs, errors.New("browser: api_url requires HTTPS outside EnvironmentDev"))
	}
	if len(c.browser.AllowedOrigins) == 0 {
		errs = append(errs, errors.New("browser: allowed_origins must include at least one origin"))
	}
	for _, origin := range c.browser.AllowedOrigins {
		parsed, err := parseBrowserOrigin(origin)
		if err != nil {
			errs = append(errs, fmt.Errorf("browser: allowed_origins %q %w", origin, err))
		} else if !dev && parsed.Scheme != "https" {
			errs = append(errs, fmt.Errorf("browser: allowed_origins %q requires HTTPS outside EnvironmentDev", origin))
		}
	}
	b := c.browser.Cookies
	seen := map[string]bool{"_csrf": true, "_goauth_browser": true, "__Host-goauth_browser": true, "_goauth_admin_csrf": true, "_goauth_admin_browser": true, "__Host-goauth_admin_browser": true}
	for index, name := range []string{b.Name, b.RefreshName, b.ChallengeName, b.AdminName, b.AdminRefreshName, b.AdminChallengeName} {
		if err := (&http.Cookie{Name: name, Value: "valid", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}).Valid(); err != nil {
			errs = append(errs, fmt.Errorf("browser: invalid cookie name %q: %w", name, err))
		}
		if seen[name] {
			errs = append(errs, fmt.Errorf("browser: conflicting cookie name %q", name))
		}
		seen[name] = true
		domain, path := b.Domain, b.Path
		if index == 2 || index == 5 {
			domain, path = "", "/" // challenge binding is always host-only
		}
		if strings.HasPrefix(name, "__Host-") && (!c.resolved.cookieSecure || domain != "" || path != "/") {
			errs = append(errs, fmt.Errorf("browser: __Host- cookie %q requires Secure, Path=/, and no Domain", name))
		}
		if strings.HasPrefix(name, "__Secure-") && !c.resolved.cookieSecure {
			errs = append(errs, fmt.Errorf("browser: __Secure- cookie %q requires Secure", name))
		}
	}
	if b.Path != "/" {
		errs = append(errs, errors.New("browser: cookie path must be / to cover the built-in /auth and /admin routes"))
	}
	if err := (&http.Cookie{Name: b.Name, Value: "valid", Domain: b.Domain, Path: b.Path, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}).Valid(); err != nil {
		errs = append(errs, fmt.Errorf("browser: invalid cookie scope: %w", err))
	}
	if b.Domain != "" && u != nil {
		domain := strings.TrimPrefix(b.Domain, ".")
		host := u.Hostname()
		if !strings.EqualFold(host, domain) && !strings.HasSuffix(strings.ToLower(host), "."+strings.ToLower(domain)) {
			errs = append(errs, errors.New("browser: cookie domain must match the public API host or a parent domain"))
		}
	}
	if b.SameSite != http.SameSiteLaxMode && b.SameSite != http.SameSiteStrictMode && b.SameSite != http.SameSiteNoneMode {
		errs = append(errs, errors.New("browser: same_site must be Lax, Strict, or None"))
	}
	if b.SameSite == http.SameSiteNoneMode && !c.resolved.cookieSecure {
		errs = append(errs, errors.New("browser: same_site=None requires Secure cookies, including in development"))
	}
	if !dev && !c.resolved.cookieSecure {
		errs = append(errs, errors.New("browser: insecure cookies are only allowed in EnvironmentDev"))
	}
	return errs
}
