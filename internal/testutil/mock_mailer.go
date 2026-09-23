package testutil

import (
	"context"
	"sync"
)

// MockMailer records email sends and can override delivery behavior.
type MockMailer struct {
	// mu guards Calls: the bulk invite send fans out across a worker pool, so
	// Send is called concurrently.
	mu     sync.Mutex
	SendFn func(ctx context.Context, to, subject, html, text string) error
	Calls  []struct{ To, Subject, HTML, Text string }
}

// Send records the message before calling SendFn, when set.
func (m *MockMailer) Send(ctx context.Context, to, subject, html, text string) error {
	m.mu.Lock()
	m.Calls = append(m.Calls, struct{ To, Subject, HTML, Text string }{to, subject, html, text})
	m.mu.Unlock()
	if m.SendFn != nil {
		return m.SendFn(ctx, to, subject, html, text)
	}
	return nil
}

// SentCount returns how many sends were recorded, safe to call while workers
// are still running.
func (m *MockMailer) SentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.Calls)
}
