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
	cors := CORSConfig{
		AllowedHeaders: []string{"Idempotency-Key"},
		ExposedHeaders: []string{"Content-Disposition"},
		AllowedMethods: []string{"PROPFIND"},
	}
	cfg, err := NewConfig(minimalOpts(WithBrowser(BrowserConfig{
		AllowedOrigins: origins, CORS: cors, Cookies: CookieConfig{Secure: &secure},
	}))...)
	if err != nil {
		t.Fatal(err)
	}
	origins[0] = "https://changed.example"
	secure = false
	cors.AllowedHeaders[0] = "X-Changed"
	cors.ExposedHeaders[0] = "X-Changed"
	cors.AllowedMethods[0] = "CHANGED"
	prepared, _, err := prepareConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.browser.AllowedOrigins[0] != "https://app.example.com" || !prepared.resolved.cookieSecure {
		t.Fatal("consumer mutation changed configuration")
	}
	if prepared.browser.CORS.AllowedHeaders[0] != "Idempotency-Key" || prepared.browser.CORS.ExposedHeaders[0] != "Content-Disposition" || prepared.browser.CORS.AllowedMethods[0] != "PROPFIND" {
		t.Fatal("consumer mutation changed CORS configuration")
	}
	prepared.browser.CORS.AllowedHeaders[0] = "X-Changed"
	prepared.browser.CORS.ExposedHeaders[0] = "X-Changed"
	prepared.browser.CORS.AllowedMethods[0] = "CHANGED"
	second, _, err := prepareConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if second.browser.CORS.AllowedHeaders[0] != "Idempotency-Key" || second.browser.CORS.ExposedHeaders[0] != "Content-Disposition" || second.browser.CORS.AllowedMethods[0] != "PROPFIND" {
		t.Fatal("prepared instance shares CORS slices with reusable configuration")
	}
}

func TestBrowserCORSValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		cors CORSConfig
		want string
	}{
		{name: "defaults"},
		{name: "application additions", cors: CORSConfig{AllowedHeaders: []string{"Idempotency-Key"}, ExposedHeaders: []string{"Content-Disposition"}, AllowedMethods: []string{"PROPFIND"}}},
		{name: "empty header", cors: CORSConfig{AllowedHeaders: []string{""}}, want: "allowed_headers"},
		{name: "header list", cors: CORSConfig{AllowedHeaders: []string{"X-One, X-Two"}}, want: "allowed_headers"},
		{name: "header whitespace", cors: CORSConfig{AllowedHeaders: []string{" X-One"}}, want: "allowed_headers"},
		{name: "header colon", cors: CORSConfig{AllowedHeaders: []string{"X-One:"}}, want: "allowed_headers"},
		{name: "header injection", cors: CORSConfig{AllowedHeaders: []string{"X-One\r\nInjected: true"}}, want: "allowed_headers"},
		{name: "header wildcard", cors: CORSConfig{AllowedHeaders: []string{"*"}}, want: "allowed_headers"},
		{name: "exposure wildcard", cors: CORSConfig{ExposedHeaders: []string{"*"}}, want: "exposed_headers"},
		{name: "exposure Unicode", cors: CORSConfig{ExposedHeaders: []string{"X-Café"}}, want: "exposed_headers"},
		{name: "exposure newline", cors: CORSConfig{ExposedHeaders: []string{"X-One\nX-Two"}}, want: "exposed_headers"},
		{name: "method wildcard", cors: CORSConfig{AllowedMethods: []string{"*"}}, want: "allowed_methods"},
		{name: "method list", cors: CORSConfig{AllowedMethods: []string{"POST, GET"}}, want: "allowed_methods"},
		{name: "method whitespace", cors: CORSConfig{AllowedMethods: []string{" PROPFIND"}}, want: "allowed_methods"},
		{name: "method separator", cors: CORSConfig{AllowedMethods: []string{"BAD/METHOD"}}, want: "allowed_methods"},
		{name: "forbidden CONNECT", cors: CORSConfig{AllowedMethods: []string{"CONNECT"}}, want: "browser-forbidden"},
		{name: "forbidden TRACE", cors: CORSConfig{AllowedMethods: []string{"trace"}}, want: "browser-forbidden"},
		{name: "forbidden TRACK", cors: CORSConfig{AllowedMethods: []string{"TRACK"}}, want: "browser-forbidden"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			browser := BrowserConfig{AllowedOrigins: []string{"https://app.example.com"}, CORS: tc.cors}
			cfg, err := NewConfig(minimalOpts(WithBrowser(browser))...)
			if tc.want == "" {
				if err != nil || cfg == nil {
					t.Fatalf("valid CORS rejected: %v", err)
				}
				return
			}
			if cfg != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("config present=%v, error=%v, want %q", cfg != nil, err, tc.want)
			}
			valid, err := NewConfig(minimalOpts()...)
			if err != nil {
				t.Fatal(err)
			}
			WithBrowser(browser)(valid)
			auth, err := New(valid)
			if auth != nil {
				auth.Close()
				t.Fatal("New accepted invalid late CORS options")
			}
			if err == nil || !strings.Contains(err.Error(), "goauth: invalid configuration: browser: cors:") {
				t.Fatalf("New error=%v, want early configuration rejection", err)
			}
		})
	}
}

func TestBrowserCORSSectionReplacement(t *testing.T) {
	cfg, err := NewConfig(minimalOpts(
		WithBrowser(BrowserConfig{
			AllowedOrigins: []string{"https://app.example.com"},
			CORS:           CORSConfig{AllowedHeaders: []string{"Idempotency-Key"}},
		}),
		WithBrowser(BrowserConfig{AllowedOrigins: []string{"https://other.example.com"}}),
	)...)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.browser.CORS.AllowedHeaders) != 0 {
		t.Fatal("replaced browser section retained previous CORS additions")
	}
}
