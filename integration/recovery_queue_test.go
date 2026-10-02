package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
)

type blockedRecoveryDelivery struct {
	entered chan struct{}
	once    sync.Once
}

func (m *blockedRecoveryDelivery) Send(ctx context.Context, _, _, _, _ string) error {
	m.once.Do(func() { close(m.entered) })
	<-ctx.Done()
	return ctx.Err()
}

func TestPublicRecoveryHTTPReturnsWhileSMTPIsBlocked(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()
	mailer := &blockedRecoveryDelivery{entered: make(chan struct{})}
	a := openAuth(t, db, mailer)
	defer a.Close()
	ctx := context.Background()
	if _, err := a.Register(ctx, api.RegisterInput{Email: "recovery@test.com", Name: "Recovery", Password: validTestPassword()}); err != nil {
		t.Fatal(err)
	}
	if err := a.Services().Password.ForgotPassword(ctx, api.ForgotPasswordInput{Email: "recovery@test.com"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-mailer.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not enter SMTP delivery")
	}
	csrfHandler, ok := a.Handler("GET /auth/csrf-token")
	if !ok {
		t.Fatal("missing CSRF endpoint")
	}
	csrfResponse := httptest.NewRecorder()
	csrfHandler.ServeHTTP(csrfResponse, httptest.NewRequest(http.MethodGet, "/auth/csrf-token", nil))
	var csrfCookie *http.Cookie
	for _, cookie := range csrfResponse.Result().Cookies() {
		if cookie.Name == "_csrf" {
			csrfCookie = cookie
		}
	}
	if csrfCookie == nil {
		t.Fatal("CSRF cookie not issued")
	}
	clientIndex := 0
	post := func(path, email string) *httptest.ResponseRecorder {
		t.Helper()
		handler, ok := a.Handler("POST " + path)
		if !ok {
			t.Fatalf("missing recovery route %s", path)
		}
		body, err := json.Marshal(map[string]string{"email": email})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
		clientIndex++
		request.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", clientIndex)
		request.Header.Set("Origin", "http://localhost:8080")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", csrfCookie.Value)
		request.AddCookie(csrfCookie)
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			done <- recorder
		}()
		select {
		case response := <-done:
			return response
		case <-time.After(5 * time.Second):
			t.Fatal("public request waited on blocked SMTP")
			return nil
		}
	}
	for _, path := range []string{"/auth/forgot-password", "/auth/verify-email/resend"} {
		known := post(path, "recovery@test.com")
		unknown := post(path, "missing@test.com")
		if known.Code != http.StatusOK || unknown.Code != known.Code || unknown.Body.String() != known.Body.String() {
			t.Fatalf("%s leaked account state: known=%d %s unknown=%d %s", path, known.Code, known.Body, unknown.Code, unknown.Body)
		}
	}
	var count int
	if err := db.QueryRow(testdb.SQL(db, "SELECT COUNT(*) FROM recovery_requests")).Scan(&count); err != nil || count != 5 {
		t.Fatalf("recovery requests not durably queued: count=%d err=%v", count, err)
	}
	if _, err := db.Exec(testdb.SQL(db, "DROP TABLE recovery_requests")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/auth/forgot-password", "/auth/verify-email/resend"} {
		// Use different client addresses so the test probes queue failure rather
		// than exhausting the recovery route's per-IP request budget.
		known := post(path, "recovery@test.com")
		unknown := post(path, "missing@test.com")
		if known.Code != http.StatusInternalServerError || unknown.Code != known.Code || unknown.Body.String() != known.Body.String() {
			t.Fatalf("%s queue outage response differs: known=%d %s unknown=%d %s", path, known.Code, known.Body, unknown.Code, unknown.Body)
		}
	}
}
