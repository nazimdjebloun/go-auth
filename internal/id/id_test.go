package id

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestNewIsCanonicalUUIDv4(t *testing.T) {
	got := New()
	if len(got) != 36 || strings.Count(got, "-") != 4 {
		t.Fatalf("New() = %q, want a canonical 36-char UUID", got)
	}
	parsed, err := uuid.Parse(got)
	if err != nil {
		t.Fatalf("New() = %q does not parse as a UUID: %v", got, err)
	}
	if parsed.Version() != uuid.Version(4) {
		t.Fatalf("New() version = %d, want 4 (random)", parsed.Version())
	}
	if parsed.Variant() != uuid.RFC4122 {
		t.Fatalf("New() variant = %v, want RFC4122", parsed.Variant())
	}
}

func TestNewIsUnique(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		id := New()
		if seen[id] {
			t.Fatalf("New() returned duplicate %q after %d calls", id, i+1)
		}
		seen[id] = true
	}
}

func TestNewIsRFC4122RandomNotNil(t *testing.T) {
	// The nil UUID (or any fixed placeholder) must never be returned.
	if New() == "00000000-0000-0000-0000-000000000000" {
		t.Fatal("New() returned the nil UUID")
	}
}
