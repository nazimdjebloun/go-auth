package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// FuzzPepperPassword pins the password-pepper HMAC: the output must be exactly
// the base64 encoding of a 32-byte HMAC-SHA256 over the password under the
// pepper key, for every password and every key (including empty ones). A
// single poisoned-length or non-deterministic output here would corrupt stored
// hashes credential-by-credential.
func FuzzPepperPassword(f *testing.F) {
	for _, s := range []string{"", "a", "password", strings.Repeat("x", 1000), "ünïcödé 密码"} {
		f.Add(s, []byte("pepper"))
		f.Add(s, []byte(nil))
	}
	f.Fuzz(func(t *testing.T, password string, pepper []byte) {
		out := pepperPassword(password, pepper)
		if len(out) != base64.StdEncoding.EncodedLen(32) {
			t.Errorf("pepperPassword output has length %d, want %d", len(out), base64.StdEncoding.EncodedLen(32))
		}
		if out != pepperPassword(password, pepper) {
			t.Errorf("pepperPassword is not deterministic")
		}
		mac := hmac.New(sha256.New, pepper)
		mac.Write([]byte(password))
		if want := base64.StdEncoding.EncodeToString(mac.Sum(nil)); out != want {
			t.Errorf("pepperPassword output %q does not match HMAC-SHA256 %q", out, want)
		}
	})
}

// FuzzStalePepper cross-checks the rotation helper against its definition: a
// stored code is stale exactly when both timestamps are non-zero and issued
// predates rotation. The zero handling is the subtle part — hand-built configs
// and legacy rows have zero timestamps, and those must never be judged stale.
func FuzzStalePepper(f *testing.F) {
	for _, p := range [][2]int64{
		{0, 0}, {1, 2}, {2, 1}, {-1, 1}, {0, 5}, {5, 0}, {-1, -2},
	} {
		f.Add(p[0], p[1])
	}
	f.Fuzz(func(t *testing.T, issuedNanos, rotatedNanos int64) {
		issued := time.Unix(0, issuedNanos)
		rotated := time.Unix(0, rotatedNanos)
		got := stalePepper(issued, rotated)
		want := !issued.IsZero() && !rotated.IsZero() && issued.Before(rotated)
		if got != want {
			t.Errorf("stalePepper(%v, %v) = %v, want %v", issued, rotated, got, want)
		}
	})
}
