package domain

import (
	"strings"
	"testing"
)

// FuzzParseUserAgent drives the third-party user-agent parser with arbitrary
// strings. Session rows record the parsed result of a header the client
// controls verbatim, so garbage input must be handled without a panic and must
// still produce a structurally usable record — device type is a closed set and
// is what the admin UI groups sessions by.
func FuzzParseUserAgent(f *testing.F) {
	for _, s := range []string{
		"",
		"curl/8.5.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Twitterbot/1.0",
		"Mozilla/5.0 (iPad; CPU OS 16_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
		"\x00\xff\xfe\xfd",
		strings.Repeat("Mozilla", 100),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		info := ParseUserAgent(raw)
		if info == nil {
			t.Fatal("ParseUserAgent returned nil")
		}
		switch info.DeviceType {
		case "bot", "mobile", "tablet", "desktop":
		default:
			t.Errorf("unexpected device type %q for raw %q", info.DeviceType, raw)
		}
	})
}
