package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultWebhookTimeout bounds a single webhook POST when WebhookConfig does
// not set one (and no custom client is supplied).
const DefaultWebhookTimeout = 10 * time.Second

// WebhookConfig configures a WebhookSink.
//
// Secret is optional but strongly recommended: when set, every request
// carries an X-Signature header of the form "sha256=<hex>" whose value is
// HMAC-SHA256(secret, body). The receiving service recomputes it with the
// shared secret and rejects mismatches, so a discovered URL alone cannot
// inject forged events. Keep the secret per-environment, like any other
// credential — it is not derived from the app root secret.
type WebhookConfig struct {
	// Endpoint receives one POST per event with the JSON-serialized
	// audit.Event body. Required.
	Endpoint string
	// Secret signs each request body with HMAC-SHA256 in the X-Signature
	// header ("sha256=<hex>"). Optional; empty means unsigned.
	Secret string
	// Timeout bounds each POST when Client is nil. Zero means the
	// DefaultWebhookTimeout (10s).
	Timeout time.Duration
	// Retries is how many times a failed POST is retried. Only
	// transport errors and 5xx responses are retried — a 4xx is a
	// permanent rejection. 0 means a single attempt (at-most-once).
	Retries int
	// RetryWait is the base delay before the first retry; it doubles on
	// each subsequent attempt. 0 means 1s. Only used when Retries > 0.
	RetryWait time.Duration
	// Client replaces the default *http.Client entirely (its Timeout
	// wins; WebhookConfig.Timeout is ignored). Optional.
	Client *http.Client
}

// WebhookSink delivers audit events to an HTTP endpoint — one POST per
// event, JSON body, optionally HMAC-signed. It plugs into the existing
// EventSink seam via WithAudit/WithAuditSink; the AuditService's queue,
// batching, failure mode, and drop-on-full behavior apply unchanged.
//
// Delivery is best-effort: a failed or non-2xx POST returns an error that
// the AuditService logs according to the configured FailureMode — it never
// blocks or fails the request that triggered the event. Transport errors
// and 5xx responses are retried up to Retries times; 4xx responses are
// permanent and never retried. Point the sink at a receiver that tolerates
// at-most-once delivery, or run a durable intermediary (queue, collector)
// behind it.
type WebhookSink struct {
	cfg    WebhookConfig
	client *http.Client
}

// DefaultWebhookRetryWait is the delay before the first retry when
// WebhookConfig leaves RetryWait unset.
const DefaultWebhookRetryWait = time.Second

// NewWebhookSink validates the config and returns a ready sink.
func NewWebhookSink(cfg WebhookConfig) (*WebhookSink, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("webhook sink: endpoint is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultWebhookTimeout
	}
	if cfg.Retries < 0 {
		return nil, fmt.Errorf("webhook sink: retries must not be negative")
	}
	if cfg.RetryWait < 0 {
		return nil, fmt.Errorf("webhook sink: retry wait must not be negative")
	}
	if cfg.Retries > 0 && cfg.RetryWait == 0 {
		cfg.RetryWait = DefaultWebhookRetryWait
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	return &WebhookSink{cfg: cfg, client: client}, nil
}

// SignatureHeader is the header carrying the HMAC-SHA256 body signature.
const SignatureHeader = "X-Signature"

func (s *WebhookSink) Handle(ctx context.Context, event Event) error {
	return s.HandleBatch(ctx, []Event{event})
}

// HandleBatch posts each event individually. It stops at the first failure
// so fail-closed deployments don't hammer a broken endpoint with the rest of
// the batch; fail-open deployments log the error and continue with later
// batches. Individual events within one batch that already succeeded are not
// re-sent.
func (s *WebhookSink) HandleBatch(ctx context.Context, events []Event) error {
	for _, event := range events {
		if err := s.post(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

func (s *WebhookSink) post(ctx context.Context, event Event) error {
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("webhook sink: marshal event: %w", err)
	}

	var signature string
	if s.cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(s.cfg.Secret))
		mac.Write(body)
		signature = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}

	// The same signed payload is reused across attempts — a retry must
	// never degrade the HMAC contract.
	wait := s.cfg.RetryWait
	var lastErr error
	for attempt := 0; attempt <= s.cfg.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return lastErr
			case <-time.After(wait):
				wait *= 2
			}
		}
		retryable, err := s.postOnce(ctx, body, signature)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retryable {
			return err
		}
	}
	return lastErr
}

// postOnce sends one attempt. The second return value reports whether the
// failure is transient (transport error or 5xx) and worth retrying — a 4xx
// is a permanent rejection.
func (s *WebhookSink) postOnce(ctx context.Context, body []byte, signature string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("webhook sink: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "go-auth-audit-webhook")
	if signature != "" {
		req.Header.Set(SignatureHeader, signature)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return true, fmt.Errorf("webhook sink: post: %w", err)
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the connection is reusable; an unbounded
	// copy is unnecessary — we only care about the status code.
	_, _ = io.CopyN(io.Discard, resp.Body, 1<<16)

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode >= 500:
		return true, fmt.Errorf("webhook sink: unexpected status %d", resp.StatusCode)
	default:
		return false, fmt.Errorf("webhook sink: unexpected status %d", resp.StatusCode)
	}
}
