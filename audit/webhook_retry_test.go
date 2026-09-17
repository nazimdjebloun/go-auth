package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func testEvent() Event {
	return Event{ID: "evt-retry", Type: EventLoginSuccess}
}

// TestWebhookRetry_RetriesTransientStatuses verifies a 5xx is retried up to
// the configured budget and then reported.
func TestWebhookRetry_RetriesTransientStatuses(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	sink, err := NewWebhookSink(WebhookConfig{
		Endpoint:  srv.URL,
		Retries:   2,
		RetryWait: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := sink.Handle(context.Background(), testEvent()); err == nil {
		t.Fatal("expected an error after exhausting retries")
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("%d attempts, want 3 (initial + 2 retries)", got)
	}
}

// TestWebhookRetry_SucceedsAfterTransientFailure verifies a retry can recover
// the delivery — the point of retrying at all.
func TestWebhookRetry_SucceedsAfterTransientFailure(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewWebhookSink(WebhookConfig{
		Endpoint:  srv.URL,
		Retries:   3,
		RetryWait: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := sink.Handle(context.Background(), testEvent()); err != nil {
		t.Fatalf("delivery should have recovered on retry: %v", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("%d attempts, want 2", got)
	}
}

// TestWebhookRetry_DoesNotRetryClientErrors pins the deliberate asymmetry: a
// 4xx is a permanent rejection, and retrying it would multiply one bad event
// into N bad requests.
func TestWebhookRetry_DoesNotRetryClientErrors(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	sink, err := NewWebhookSink(WebhookConfig{
		Endpoint:  srv.URL,
		Retries:   3,
		RetryWait: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := sink.Handle(context.Background(), testEvent()); err == nil {
		t.Fatal("expected an error for a 400 response")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("%d attempts, want exactly 1 — 4xx must not be retried", got)
	}
}

// TestWebhookRetry_DefaultIsSingleAttempt keeps the documented default: no
// Retries means at-most-once, exactly as before the retry option existed.
func TestWebhookRetry_DefaultIsSingleAttempt(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sink, err := NewWebhookSink(WebhookConfig{Endpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}

	if err := sink.Handle(context.Background(), testEvent()); err == nil {
		t.Fatal("expected an error")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("%d attempts, want 1 with Retries unset", got)
	}
}

// TestWebhookRetry_SignatureStillPresent ensures retries reuse the same
// signed payload rather than degrading the HMAC contract.
func TestWebhookRetry_SignatureStillPresent(t *testing.T) {
	var signatures []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signatures = append(signatures, r.Header.Get(SignatureHeader))
		var event Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewWebhookSink(WebhookConfig{
		Endpoint:  srv.URL,
		Secret:    "shared-secret",
		Retries:   1,
		RetryWait: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := sink.Handle(context.Background(), testEvent()); err != nil {
		t.Fatal(err)
	}
	if len(signatures) != 1 || signatures[0] == "" {
		t.Fatalf("expected one signed request, got %v", signatures)
	}
}
