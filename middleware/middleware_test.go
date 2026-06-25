package middleware

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"github.com/nazimdjebloun/go-auth/ratelimit"
)

func TestExtractIP_RemoteAddr(t *testing.T) {
	cfg := &ratelimit.Config{IPv6Subnet: 64}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.1:34567"
	ip := extractIP(r, cfg)
	if ip != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", ip)
	}
}

func TestExtractIP_XForwardedFor(t *testing.T) {
	cfg := &ratelimit.Config{IPv6Subnet: 64}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	ip := extractIP(r, cfg)
	if ip != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", ip)
	}
}

func TestExtractIP_XRealIP(t *testing.T) {
	cfg := &ratelimit.Config{IPv6Subnet: 64}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Real-IP", "10.0.0.5")
	ip := extractIP(r, cfg)
	if ip != "10.0.0.5" {
		t.Errorf("expected 10.0.0.5, got %s", ip)
	}
}

func TestExtractIP_CustomHeader(t *testing.T) {
	cfg := &ratelimit.Config{IPv6Subnet: 64, IPAddressHeader: "CF-Connecting-IP"}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("CF-Connecting-IP", "203.0.113.1")
	ip := extractIP(r, cfg)
	if ip != "203.0.113.1" {
		t.Errorf("expected 203.0.113.1, got %s", ip)
	}
}

func TestExtractIP_PriorityCustomHeader(t *testing.T) {
	cfg := &ratelimit.Config{IPv6Subnet: 64, IPAddressHeader: "CF-Connecting-IP"}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("CF-Connecting-IP", "203.0.113.1")
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	r.RemoteAddr = "192.168.1.1:34567"
	ip := extractIP(r, cfg)
	if ip != "203.0.113.1" {
		t.Errorf("expected 203.0.113.1 (custom header), got %s", ip)
	}
}

func TestExtractIP_IPv6Subnet(t *testing.T) {
	cfg := &ratelimit.Config{IPv6Subnet: 64}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[2001:db8::1]:34567"
	ip := extractIP(r, cfg)
	// /64 mask of 2001:db8::1 should be 2001:db8:0:0:0:0:0:0
	if ip != "2001:db8::" {
		t.Errorf("expected 2001:db8::, got %s", ip)
	}
}

func TestExtractIP_IPv6NoPort(t *testing.T) {
	cfg := &ratelimit.Config{IPv6Subnet: 64}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "2001:db8::1"
	ip := extractIP(r, cfg)
	if ip != "2001:db8::" {
		t.Errorf("expected 2001:db8::, got %s", ip)
	}
}

func TestNormalizeOrigin_StandardPorts(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://example.com", "http://example.com:80"},
		{"https://example.com", "https://example.com:443"},
		{"http://example.com:80", "http://example.com:80"},
		{"https://example.com:443", "https://example.com:443"},
		{"http://example.com:8080", "http://example.com:8080"},
	}
	for _, tt := range tests {
		got := normalizeOrigin(tt.input)
		if got != tt.want {
			t.Errorf("normalizeOrigin(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeOrigin_TrailingSlash(t *testing.T) {
	got := normalizeOrigin("http://example.com/")
	want := "http://example.com:80"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestIsSameOrigin_Matching(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/path", nil)
	r.Host = "example.com"
	if !isSameOrigin("http://example.com", r) {
		t.Error("expected same origin match")
	}
}

func TestIsSameOrigin_DifferentScheme(t *testing.T) {
	r := httptest.NewRequest("GET", "https://example.com/path", nil)
	r.Host = "example.com"
	r.TLS = &tls.ConnectionState{}
	if isSameOrigin("http://example.com", r) {
		t.Error("expected different scheme to not match")
	}
}

func TestIsSameOrigin_DifferentHost(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/path", nil)
	r.Host = "example.com"
	if isSameOrigin("http://evil.com", r) {
		t.Error("expected different host to not match")
	}
}

func TestIsAllowed_Wildcard(t *testing.T) {
	origins := map[string]bool{"*": true}
	if !isAllowed("http://anything.com", origins) {
		t.Error("expected wildcard to allow everything")
	}
}

func TestIsAllowed_ExactMatch(t *testing.T) {
	origins := map[string]bool{"http://example.com:80": true}
	if !isAllowed("http://example.com", origins) {
		t.Error("expected matching origin to be allowed")
	}
}

func TestIsAllowed_NoMatch(t *testing.T) {
	origins := map[string]bool{"http://example.com:80": true}
	if isAllowed("http://evil.com", origins) {
		t.Error("expected non-matching origin to be blocked")
	}
}
