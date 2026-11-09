package goauth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/nazimdjebloun/go-auth/middleware"
)

// BrowserConfig describes the public HTTP deployment. CSRF and challenge
// binding are mandatory; this section only configures browser transport.
type BrowserConfig struct {
	APIURL         string     // public API origin; defaults to the origin of AppConfig.BaseURL
	AllowedOrigins []string   // exact frontend origins; no wildcards
	CORS           CORSConfig // additional application headers and methods
	Cookies        CookieConfig
}

// CORSConfig extends the default CORS headers and methods. Empty slices keep
// the defaults. Origins and cookie policy remain in BrowserConfig.
type CORSConfig = middleware.CORSConfig

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
		c.browser.CORS.AllowedHeaders = append([]string(nil), cfg.CORS.AllowedHeaders...)
		c.browser.CORS.ExposedHeaders = append([]string(nil), cfg.CORS.ExposedHeaders...)
		c.browser.CORS.AllowedMethods = append([]string(nil), cfg.CORS.AllowedMethods...)
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
	errs = append(errs, c.validateCORS()...)
	dev := c.app.Environment.normalize() == EnvironmentDev
	u, err := parseBrowserOrigin(c.resolved.apiURL)
	if err != nil {
		errs = append(errs, configIssue("Browser.APIURL", ConfigInvalid, "browser: api_url %v", err))
	} else if !dev && u.Scheme != "https" {
		errs = append(errs, configIssue(
			"Browser.APIURL", ConfigInsecure,
			"browser: api_url requires HTTPS outside EnvironmentDev",
		))
	}
	if len(c.browser.AllowedOrigins) == 0 {
		errs = append(errs, configIssue(
			"Browser.AllowedOrigins", ConfigRequired,
			"browser: allowed_origins must include at least one origin",
		))
	}
	for index, origin := range c.browser.AllowedOrigins {
		field := fmt.Sprintf("Browser.AllowedOrigins[%d]", index)
		parsed, err := parseBrowserOrigin(origin)
		if err != nil {
			errs = append(errs, configIssue(field, ConfigInvalid, "browser: allowed_origins %v", err))
		} else if !dev && parsed.Scheme != "https" {
			errs = append(errs, configIssue(field, ConfigInsecure,
				"browser: allowed_origins requires HTTPS outside EnvironmentDev"))
		}
	}
	b := c.browser.Cookies
	seen := map[string]bool{"_csrf": true, "_goauth_browser": true, "__Host-goauth_browser": true, "_goauth_admin_csrf": true, "_goauth_admin_browser": true, "__Host-goauth_admin_browser": true}
	fields := []string{
		"Name", "RefreshName", "ChallengeName",
		"AdminName", "AdminRefreshName", "AdminChallengeName",
	}
	for index, name := range []string{b.Name, b.RefreshName, b.ChallengeName, b.AdminName, b.AdminRefreshName, b.AdminChallengeName} {
		field := "Browser.Cookies." + fields[index]
		if err := (&http.Cookie{Name: name, Value: "valid", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}).Valid(); err != nil {
			errs = append(errs, configIssue(field, ConfigInvalid, "browser: invalid cookie name"))
		}
		if seen[name] {
			errs = append(errs, configIssue(field, ConfigDuplicate, "browser: conflicting cookie name"))
		}
		seen[name] = true
		domain, path := b.Domain, b.Path
		if index == 2 || index == 5 {
			domain, path = "", "/" // challenge binding is always host-only
		}
		if strings.HasPrefix(name, "__Host-") && (!c.resolved.cookieSecure || domain != "" || path != "/") {
			errs = append(errs, configIssue(field, ConfigConflict,
				"browser: __Host- cookie requires Secure, Path=/, and no Domain"))
		}
		if strings.HasPrefix(name, "__Secure-") && !c.resolved.cookieSecure {
			errs = append(errs, configIssue(field, ConfigConflict, "browser: __Secure- cookie requires Secure"))
		}
	}
	if b.Path != "/" {
		errs = append(errs, configIssue(
			"Browser.Cookies.Path", ConfigInvalid,
			"browser: cookie path must be / to cover the built-in /auth and /admin routes",
		))
	}
	if err := (&http.Cookie{Name: b.Name, Value: "valid", Domain: b.Domain, Path: b.Path, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}).Valid(); err != nil {
		errs = append(errs, configIssue("Browser.Cookies", ConfigInvalid, "browser: invalid cookie scope"))
	}
	if b.Domain != "" && u != nil {
		domain := strings.TrimPrefix(b.Domain, ".")
		host := u.Hostname()
		if !strings.EqualFold(host, domain) && !strings.HasSuffix(strings.ToLower(host), "."+strings.ToLower(domain)) {
			errs = append(errs, configIssue(
				"Browser.Cookies.Domain", ConfigConflict,
				"browser: cookie domain must match the public API host or a parent domain",
			))
		}
	}
	if b.SameSite != http.SameSiteLaxMode && b.SameSite != http.SameSiteStrictMode && b.SameSite != http.SameSiteNoneMode {
		errs = append(errs, configIssue(
			"Browser.Cookies.SameSite", ConfigUnsupported,
			"browser: same_site must be Lax, Strict, or None",
		))
	}
	if b.SameSite == http.SameSiteNoneMode && !c.resolved.cookieSecure {
		errs = append(errs, configIssue(
			"Browser.Cookies.SameSite", ConfigConflict,
			"browser: same_site=None requires Secure cookies, including in development",
		))
	}
	if !dev && !c.resolved.cookieSecure {
		errs = append(errs, configIssue(
			"Browser.Cookies.Secure", ConfigInsecure,
			"browser: insecure cookies are only allowed in EnvironmentDev",
		))
	}
	return errs
}

func (c *Config) validateCORS() []error {
	var errs []error
	for _, group := range []struct {
		field  string
		name   string
		values []string
	}{
		{"AllowedHeaders", "allowed_headers", c.browser.CORS.AllowedHeaders},
		{"ExposedHeaders", "exposed_headers", c.browser.CORS.ExposedHeaders},
		{"AllowedMethods", "allowed_methods", c.browser.CORS.AllowedMethods},
	} {
		for index, value := range group.values {
			var candidate CORSConfig
			switch group.field {
			case "AllowedHeaders":
				candidate.AllowedHeaders = []string{value}
			case "ExposedHeaders":
				candidate.ExposedHeaders = []string{value}
			case "AllowedMethods":
				candidate.AllowedMethods = []string{value}
			}
			if candidate.Validate() != nil {
				// Child validation can echo submitted text. Report only its field
				// and rule, including when a malformed name contains a credential.
				message := "browser: cors: %s contains invalid name; use explicit HTTP tokens"
				if group.field == "AllowedMethods" {
					message = "browser: cors: %s contains invalid or browser-forbidden method"
				}
				errs = append(errs, configIssue(
					fmt.Sprintf("Browser.CORS.%s[%d]", group.field, index), ConfigInvalid, message, group.name,
				))
			}
		}
	}
	return errs
}
