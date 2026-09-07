package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func ipReq(remoteAddr string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestClientIP_NoHeaderConfigured(t *testing.T) {
	// The default posture: a directly-exposed server records the peer, and a
	// forged header changes nothing.
	got := ClientIP(ipReq("203.0.113.9:51234", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
	}), ClientIPConfig{})
	if got != "203.0.113.9" {
		t.Errorf("got %q, want 203.0.113.9", got)
	}
}

func TestClientIP_HeaderIgnoredWhenPeerUntrusted(t *testing.T) {
	// Header configured, but the caller is not a proxy we trust: the header
	// is attacker-controlled and must not decide what we record.
	got := ClientIP(ipReq("203.0.113.9:51234", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
	}), ClientIPConfig{Header: "X-Forwarded-For", TrustedIPs: []string{"10.0.0.1"}})
	if got != "203.0.113.9" {
		t.Errorf("got %q, want 203.0.113.9", got)
	}
}

func TestClientIP_TrustedProxyHeaderHonored(t *testing.T) {
	got := ClientIP(ipReq("10.0.0.1:4444", map[string]string{
		"X-Forwarded-For": "198.51.100.7",
	}), ClientIPConfig{Header: "X-Forwarded-For", TrustedIPs: []string{"10.0.0.1"}})
	if got != "198.51.100.7" {
		t.Errorf("got %q, want 198.51.100.7", got)
	}
}

func TestClientIP_TakesRightmostUntrustedHop(t *testing.T) {
	// A client that prepends its own hop must not be able to pick what gets
	// recorded: 1.2.3.4 is the client's forgery, 198.51.100.7 is what our
	// own edge proxy appended.
	got := ClientIP(ipReq("10.0.0.1:4444", map[string]string{
		"X-Forwarded-For": "1.2.3.4, 198.51.100.7, 10.0.0.2",
	}), ClientIPConfig{Header: "X-Forwarded-For", TrustedIPs: []string{"10.0.0.1", "10.0.0.2"}})
	if got != "198.51.100.7" {
		t.Errorf("got %q, want 198.51.100.7", got)
	}
}

func TestClientIP_AllHopsTrustedFallsBackToPeer(t *testing.T) {
	got := ClientIP(ipReq("10.0.0.1:4444", map[string]string{
		"X-Forwarded-For": "10.0.0.2",
	}), ClientIPConfig{Header: "X-Forwarded-For", TrustedIPs: []string{"10.0.0.1", "10.0.0.2"}})
	if got != "10.0.0.1" {
		t.Errorf("got %q, want 10.0.0.1", got)
	}
}

func TestClientIP_GarbageHeaderFallsBackToPeer(t *testing.T) {
	got := ClientIP(ipReq("10.0.0.1:4444", map[string]string{
		"X-Forwarded-For": "not-an-ip",
	}), ClientIPConfig{Header: "X-Forwarded-For", TrustedIPs: []string{"10.0.0.1"}})
	if got != "10.0.0.1" {
		t.Errorf("got %q, want 10.0.0.1 (never the raw header value)", got)
	}
}

func TestClientIP_IPv6IsNotMasked(t *testing.T) {
	// The rate limiter masks IPv6 to a subnet so a /64 can't rotate for a
	// fresh counter. An audit record is the opposite need: the exact address
	// is the whole point.
	got := ClientIP(ipReq("[2001:db8::1]:51234", nil), ClientIPConfig{})
	if got != "2001:db8::1" {
		t.Errorf("got %q, want 2001:db8::1", got)
	}
}

func TestClientIP_TrustedCIDR(t *testing.T) {
	got := ClientIP(ipReq("10.0.5.7:4444", map[string]string{
		"X-Forwarded-For": "198.51.100.7",
	}), ClientIPConfig{Header: "X-Forwarded-For", TrustedIPs: []string{"10.0.0.0/8"}})
	if got != "198.51.100.7" {
		t.Errorf("got %q, want 198.51.100.7", got)
	}
}
