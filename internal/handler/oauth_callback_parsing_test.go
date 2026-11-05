package handler

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/middleware"
)

type callbackBodyReader struct {
	io.Reader
	reads int
}

func (r *callbackBodyReader) Read(p []byte) (int, error) {
	r.reads++
	return r.Reader.Read(p)
}

func TestOAuthCallback_RejectsInvalidFormBeforeStateClaim(t *testing.T) {
	var multipartBody bytes.Buffer
	writer := multipart.NewWriter(&multipartBody)
	file, err := writer.CreateFormFile("unused", "dummy.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(file, "dummy file"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		contentType string
		body        string
		unread      bool
	}{
		{"multipart", writer.FormDataContentType(), multipartBody.String(), true},
		{"json", "application/json", `{}`, true},
		{"missing type", "", "", true},
		{"malformed type", "application/x-www-form-urlencoded; broken", "", true},
		{"malformed form", "application/x-www-form-urlencoded", "&broken=%zz", false},
		{"oversized form", "application/x-www-form-urlencoded", "&padding=" + strings.Repeat("x", maxBodySize), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			th := newOAuthTestHarness(t)
			values := url.Values{"code": {"dummy-code"}, "state": {th.stateToken}}
			body := tt.body
			if !tt.unread {
				body = values.Encode() + body
			}
			reader := &callbackBodyReader{Reader: strings.NewReader(body)}
			req := httptest.NewRequest(http.MethodPost, "/auth/oauth/test/callback?"+values.Encode(), reader)
			req.Header.Set("Content-Type", tt.contentType)
			req.SetPathValue("provider", "test")
			req.AddCookie(th.oauthHandlers.oauthStateCookie(th.stateToken, 600))
			w := httptest.NewRecorder()
			middleware.BrowserSession(nil, false)(http.HandlerFunc(th.oauthHandlers.Callback)).ServeHTTP(w, req)
			if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "error=invalid_request") {
				t.Fatalf("status=%d location=%q", w.Code, w.Header().Get("Location"))
			}
			if tt.unread && reader.reads != 0 {
				t.Fatalf("unsupported form read body %d times", reader.reads)
			}
			state, err := th.tokenRepo.GetByID(t.Context(), th.sid)
			if err != nil || state == nil || state.UsedAt != nil {
				t.Fatalf("invalid form consumed state: state=%+v err=%v", state, err)
			}
		})
	}
}

func TestOAuthCallback_ExplicitParsingAcceptsSupportedInputs(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			th := newOAuthTestHarness(t)
			values := url.Values{"code": {"dummy-code"}, "state": {th.stateToken}}
			target := "/auth/oauth/test/callback"
			body := values.Encode()
			if method == http.MethodGet {
				target += "?" + values.Encode()
				body = "ignored GET body"
			}
			reader := &callbackBodyReader{Reader: strings.NewReader(body)}
			req := httptest.NewRequest(method, target, reader)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			if method == http.MethodGet {
				req.Header.Set("Content-Type", "multipart/form-data; boundary=ignored")
			}
			req.SetPathValue("provider", "test")
			req.AddCookie(th.oauthHandlers.oauthStateCookie(th.stateToken, 600))
			w := httptest.NewRecorder()
			middleware.BrowserSession(nil, false)(http.HandlerFunc(th.oauthHandlers.Callback)).ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d location=%q", w.Code, w.Header().Get("Location"))
			}
			if method == http.MethodGet && reader.reads != 0 {
				t.Fatalf("GET parsed its body %d times", reader.reads)
			}
		})
	}
}
