package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOriginCheck_CustomMethods(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "PROPFIND", "REPORT"} {
		t.Run(method, func(t *testing.T) {
			for _, tc := range []struct {
				name, origin, referer string
				want                  int
			}{
				{name: "allowed origin", origin: "https://app.example", want: http.StatusOK},
				{name: "allowed referer", referer: "https://app.example/page", want: http.StatusOK},
				{name: "foreign origin", origin: "https://evil.example", want: http.StatusForbidden},
				{name: "missing origin and referer", want: http.StatusForbidden},
			} {
				t.Run(tc.name, func(t *testing.T) {
					called := false
					h := OriginCheck([]string{"https://app.example"}, false, nil, logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						called = true
						w.WriteHeader(http.StatusOK)
					}))
					r := httptest.NewRequest(method, "https://api.example/resource", nil)
					r.Header.Set("Origin", tc.origin)
					r.Header.Set("Referer", tc.referer)
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					if w.Code != tc.want || called != (tc.want == http.StatusOK) {
						t.Fatalf("status=%d, handler called=%v, want status=%d", w.Code, called, tc.want)
					}
				})
			}
		})
	}
}

func TestOriginCheck_SafeMethods(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "OPTIONS"} {
		t.Run(method, func(t *testing.T) {
			h := OriginCheck([]string{"https://app.example"}, false, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(method, "https://api.example/resource", nil))
			if w.Code != http.StatusOK {
				t.Fatalf("safe method rejected: %d", w.Code)
			}
		})
	}
}
