package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nazimdjebloun/go-auth/internal/sessioncontext"
)

func TestBrowserSession_Selector(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		forced      bool
		status      int
		scope       sessioncontext.Scope
	}{
		{"default", "", false, 200, sessioncontext.App},
		{"app", "app", false, 200, sessioncontext.App},
		{"admin", "admin", false, 200, sessioncontext.Admin},
		{"unknown", "other", false, 400, ""},
		{"ambiguous", "app,admin", false, 400, ""},
		{"fixed admin", "", true, 200, sessioncontext.Admin},
		{"wrong fixed context", "app", true, 400, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("X-GoAuth-Session", tc.value)
			w := httptest.NewRecorder()
			ran := false
			BrowserSession(nil, tc.forced)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				ran = true
				if sessioncontext.Current(r.Context()) != tc.scope {
					t.Fatal("wrong context selected")
				}
			})).ServeHTTP(w, r)
			if w.Code != tc.status || ran != (tc.status == 200) {
				t.Fatalf("status=%d ran=%v", w.Code, ran)
			}
		})
	}
}

func TestBrowserSession_RejectsRepeatedSelector(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("X-GoAuth-Session", "admin")
	r.Header.Add("X-GoAuth-Session", "admin")
	w := httptest.NewRecorder()
	BrowserSession(nil, false)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("ambiguous selector reached handler")
	})).ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", w.Code)
	}
}
