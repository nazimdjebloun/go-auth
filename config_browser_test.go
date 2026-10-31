package goauth

import (
	"net/http"
	"strings"
	"testing"
)

func TestBrowserValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		browser BrowserConfig
		want    string
	}{
		{"sibling frontend", BrowserConfig{APIURL: "https://api.example.com", AllowedOrigins: []string{"https://app.example.com", "https://admin.example.com"}}, ""},
		{"hostless API", BrowserConfig{APIURL: "https://", AllowedOrigins: []string{"https://app.example.com"}}, "api_url"},
		{"HTTP API in production", BrowserConfig{APIURL: "http://api.example.com", AllowedOrigins: []string{"https://app.example.com"}}, "HTTPS"},
		{"missing origins", BrowserConfig{}, "allowed_origins"},
		{"wildcard", BrowserConfig{AllowedOrigins: []string{"*"}}, "allowed_origins"},
		{"wildcard host", BrowserConfig{AllowedOrigins: []string{"https://*.example.com"}}, "allowed_origins"},
		{"fragment", BrowserConfig{AllowedOrigins: []string{"https://app.example.com#"}}, "allowed_origins"},
		{"zero port", BrowserConfig{APIURL: "https://api.example.com:0", AllowedOrigins: []string{"https://app.example.com"}}, "port"},
		{"host challenge with shared auth domain", BrowserConfig{APIURL: "https://api.example.com", AllowedOrigins: []string{"https://app.example.com"}, Cookies: CookieConfig{Domain: "example.com", ChallengeName: "__Host-challenge"}}, ""},
		{"origin path", BrowserConfig{AllowedOrigins: []string{"https://app.example.com/path"}}, "allowed_origins"},
		{"origin credentials", BrowserConfig{AllowedOrigins: []string{"https://user@app.example.com"}}, "allowed_origins"},
		{"origin query", BrowserConfig{AllowedOrigins: []string{"https://app.example.com?x=1"}}, "allowed_origins"},
		{"invalid port", BrowserConfig{APIURL: "https://api.example.com:99999", AllowedOrigins: []string{"https://app.example.com"}}, "port"},
		{"cookie collision", BrowserConfig{AllowedOrigins: []string{"https://app.example.com"}, Cookies: CookieConfig{Name: "same", RefreshName: "same"}}, "conflicting"},
		{"reserved cookie", BrowserConfig{AllowedOrigins: []string{"https://app.example.com"}, Cookies: CookieConfig{Name: "_csrf"}}, "conflicting"},
		{"app admin collision", BrowserConfig{AllowedOrigins: []string{"https://app.example.com"}, Cookies: CookieConfig{AdminName: "goauth_session"}}, "conflicting"},
		{"reserved admin csrf", BrowserConfig{AllowedOrigins: []string{"https://app.example.com"}, Cookies: CookieConfig{AdminRefreshName: "_goauth_admin_csrf"}}, "conflicting"},
		{"reserved admin browser binding", BrowserConfig{AllowedOrigins: []string{"https://app.example.com"}, Cookies: CookieConfig{AdminChallengeName: "__Host-goauth_admin_browser"}}, "conflicting"},
		{"invalid cookie name", BrowserConfig{AllowedOrigins: []string{"https://app.example.com"}, Cookies: CookieConfig{Name: "invalid name"}}, "cookie name"},
		{"cookie misses routes", BrowserConfig{AllowedOrigins: []string{"https://app.example.com"}, Cookies: CookieConfig{Path: "/api"}}, "path"},
		{"cookie wrong domain", BrowserConfig{AllowedOrigins: []string{"https://app.example.com"}, Cookies: CookieConfig{Domain: "other.example"}}, "domain"},
		{"insecure production cookie", BrowserConfig{AllowedOrigins: []string{"https://app.example.com"}, Cookies: CookieConfig{Secure: SecureNever()}}, "EnvironmentDev"},
		{"cross-site secure", BrowserConfig{AllowedOrigins: []string{"https://app.example.com"}, Cookies: CookieConfig{SameSite: http.SameSiteNoneMode}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewConfig(minimalOpts(WithBrowser(tc.browser))...)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestBrowserDevelopmentAndAPIURLResolution(t *testing.T) {
	for _, sameSite := range []http.SameSite{http.SameSiteLaxMode, http.SameSiteNoneMode} {
		t.Run(map[http.SameSite]string{http.SameSiteLaxMode: "HTTP development", http.SameSiteNoneMode: "insecure cross-site rejected"}[sameSite], func(t *testing.T) {
			cfg, err := NewConfig(minimalOpts(WithApp(AppConfig{Name: "dev", BaseURL: "http://localhost:3000", Environment: EnvironmentDev, Database: validTestConfig().app.Database}), WithBrowser(BrowserConfig{APIURL: "http://localhost:8080", AllowedOrigins: []string{"http://localhost:3000"}, Cookies: CookieConfig{SameSite: sameSite, Secure: SecureNever()}}))...)
			if sameSite == http.SameSiteNoneMode {
				if err == nil {
					t.Fatal("None without Secure accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.resolved.cookieSecure {
				t.Fatal("HTTP dev cookie is secure")
			}
		})
	}
	cfg, err := NewConfig(minimalOpts()...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.browser.Cookies.AdminName != "goauth_admin_session" || cfg.browser.Cookies.AdminRefreshName != "goauth_admin_refresh" || cfg.browser.Cookies.AdminChallengeName != "_goauth_admin_2fa_challenge" {
		t.Fatal("unexpected admin cookie defaults")
	}
	WithApp(AppConfig{Name: "changed", BaseURL: "https://changed.example", Database: cfg.app.Database})(cfg)
	prepared, _, err := prepareConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.resolved.apiURL != "https://changed.example" {
		t.Fatal("derived API origin retained an old frontend value")
	}
}

func TestBrowserCopiesConsumerIntent(t *testing.T) {
	origins := []string{"https://app.example.com"}
	secure := true
	cfg, err := NewConfig(minimalOpts(WithBrowser(BrowserConfig{AllowedOrigins: origins, Cookies: CookieConfig{Secure: &secure}}))...)
	if err != nil {
		t.Fatal(err)
	}
	origins[0] = "https://changed.example"
	secure = false
	prepared, _, err := prepareConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.browser.AllowedOrigins[0] != "https://app.example.com" || !prepared.resolved.cookieSecure {
		t.Fatal("consumer mutation changed configuration")
	}
}
