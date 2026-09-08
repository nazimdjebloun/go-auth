package mailer

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestLog_Send(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	m := NewLog(logger)

	if err := m.Send(context.Background(), "user@example.com", "subject line", "<p>html</p>", "text body"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"user@example.com", "subject line", "text body"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected log output to contain %q, got: %s", want, out)
		}
	}
	if strings.Contains(out, "<p>html</p>") {
		t.Errorf("expected log output to omit html body, got: %s", out)
	}
}

func TestLog_NilLoggerDefaultsToSlogDefault(t *testing.T) {
	m := NewLog(nil)
	if m.log == nil {
		t.Fatal("expected default logger to be set")
	}
}
