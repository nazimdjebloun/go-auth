package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebhookSink_RequiresEndpoint(t *testing.T) {
	if _, err := NewWebhookSink(WebhookConfig{}); err == nil {
		t.Fatal("expected error for empty endpoint")
	}
}

func TestWebhookSink_PostsSignedEvent(t *testing.T) {
	var gotPath string
	var gotSig string
	var gotBody []byte
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotSig = r.Header.Get(SignatureHeader)
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = b
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewWebhookSink(WebhookConfig{Endpoint: srv.URL + "/hook", Secret: "top-secret"})
	if err != nil {
		t.Fatal(err)
	}
	event := NewLoginFailedEvent("a@b.com", nil, "TestAgent")
	if err := sink.Handle(context.Background(), event); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if gotPath != "/hook" {
		t.Errorf("path = %q, want /hook", gotPath)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type = %q", gotCT)
	}

	// Signature must be HMAC-SHA256 over the exact body bytes.
	mac := hmac.New(sha256.New, []byte("top-secret"))
	mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Errorf("signature = %q, want %q", gotSig, want)
	}

	// The body must round-trip to the same event identity.
	var decoded Event
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("body is not valid event JSON: %v", err)
	}
	if decoded.ID != event.ID || decoded.Type != event.Type {
		t.Errorf("decoded event = %+v, want id %s type %s", decoded, event.ID, event.Type)
	}
}

func TestWebhookSink_UnsignedWhenNoSecret(t *testing.T) {
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get(SignatureHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewWebhookSink(WebhookConfig{Endpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Handle(context.Background(), NewLoginFailedEvent("a@b.com", nil, "")); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if gotSig != "" {
		t.Errorf("expected no signature header, got %q", gotSig)
	}
}

func TestWebhookSink_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sink, err := NewWebhookSink(WebhookConfig{Endpoint: srv.URL, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Handle(context.Background(), NewLoginFailedEvent("a@b.com", nil, "")); err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestWebhookSink_BatchPostsEachEvent(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewWebhookSink(WebhookConfig{Endpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	batch := []Event{NewLoginFailedEvent("a@b.com", nil, ""), NewLoginFailedEvent("c@d.com", nil, "")}
	if err := sink.HandleBatch(context.Background(), batch); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}
	if got := count.Load(); got != 2 {
		t.Errorf("posts = %d, want 2", got)
	}
}

func TestWebhookSink_EmptyBatchNoPost(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewWebhookSink(WebhookConfig{Endpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.HandleBatch(context.Background(), nil); err != nil {
		t.Fatalf("HandleBatch: %v", err)
	}
	if got := count.Load(); got != 0 {
		t.Errorf("posts = %d, want 0", got)
	}
}

func TestWebhookSink_SinkInterfaceCompliance(t *testing.T) {
	var _ EventSink = (*WebhookSink)(nil)
}
