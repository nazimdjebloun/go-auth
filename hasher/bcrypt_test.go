package hasher

import "testing"

func TestHashAndCompare_RoundTrip(t *testing.T) {
	h := New(4)
	password := "MySecureP@ss1"
	hash, err := h.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}
	if hash == password {
		t.Error("hash should not equal plaintext password")
	}
	if err := h.Compare(password, hash); err != nil {
		t.Errorf("compare should succeed: %v", err)
	}
}

func TestCompare_WrongPassword(t *testing.T) {
	h := New(4)
	hash, _ := h.Hash("correct-password")
	if err := h.Compare("wrong-password", hash); err == nil {
		t.Error("expected error for wrong password")
	}
}

func TestCompare_InvalidHash(t *testing.T) {
	h := New(4)
	if err := h.Compare("password", "not-a-bcrypt-hash"); err == nil {
		t.Error("expected error for invalid hash")
	}
}

func TestNew_MinCostClamp(t *testing.T) {
	h := New(0)
	if h.cost < 10 {
		t.Errorf("expected cost to be at least DefaultCost (10), got %d", h.cost)
	}
}
