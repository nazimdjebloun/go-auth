package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteError_WrappedInfrastructureFailure(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	cause := errors.New("database unavailable")
	rec := httptest.NewRecorder()
	writeErrorTo(logger, rec, fmt.Errorf("admin target user lookup: %w", cause))
	if rec.Code != 500 {
		t.Fatalf("status=%d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 2 || body["error"] != "internal_error" || body["message"] != "Internal server error" {
		t.Fatalf("unsafe response: %v", body)
	}
	if strings.Contains(rec.Body.String(), cause.Error()) {
		t.Fatal("backend detail exposed")
	}
	if !strings.Contains(logs.String(), cause.Error()) || !strings.Contains(logs.String(), "level=ERROR") {
		t.Fatal("missing operational cause")
	}
}
