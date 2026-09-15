package argon2id

import (
	"bytes"
	"testing"
)

// FuzzParse exercises the PHC-string decoder against arbitrary input. The
// contract is fail-closed: parse must never panic, must reject every
// malformed, unsupported, or unsafe encoding, and — when it does accept a
// string — must round-trip through encode without changing the parameters or
// material. The successful-parse bounds (memory <= 2 GiB, iterations <= 1000,
// etc.) are checked again here because they are the load-bearing memory-safety
// gate that keeps a corrupted database row from allocating gigabytes at login.
func FuzzParse(f *testing.F) {
	salt := []byte("0123456789abcdef")
	key := []byte("0123456789abcdef0123456789abcdef")
	f.Add(encode(DefaultOptions(), salt, key))
	f.Add(encode(Options{Memory: 8, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16}, salt[:8], key[:16]))
	f.Add("")
	f.Add("$argon2id$")
	f.Add("$argon2id$v=19$m=65536,t=3,p=4$")
	f.Add("$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$")
	f.Add("$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$a2V5aW5mbw==")
	f.Add("$argon2id$v=999$m=8,t=1,p=1$c2FsdHNhbHQ$a2V5aW5mb2ZvcnNvbWVrZXk")
	f.Add("$argon2id$v=19$m=0,t=0,p=0$c2FsdHNhbHQ$a2V5aW5mb2ZvcnNvbWVrZXk")
	f.Add("$argon2id$v=19$m=4294967295,t=1001,p=1$c2FsdHNhbHQ$a2V5aW5mb2ZvcnNvbWVrZXk")
	f.Add("$2a$12$abcdefghijklmnopqrstuv")
	f.Add("pbkdf2_sha256$150000$aabbccdd")
	f.Add("argon2:$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$a2V5aW5mb2ZvcnNvbWVrZXk")

	f.Fuzz(func(t *testing.T, stored string) {
		opts, salt, key, err := parse(stored)
		if err != nil {
			return
		}
		if verr := validateOptions(opts); verr != nil {
			t.Errorf("parse accepted options that fail validateOptions: %v", verr)
		}
		if len(salt) != int(opts.SaltLength) || len(key) != int(opts.KeyLength) {
			t.Errorf("decoded material lengths mismatch options: salt %d != %d, key %d != %d",
				len(salt), opts.SaltLength, len(key), opts.KeyLength)
		}
		reencoded := encode(opts, salt, key)
		opts2, salt2, key2, err2 := parse(reencoded)
		if err2 != nil {
			t.Fatalf("re-encoded string rejected: %v", err2)
		}
		if opts2 != opts {
			t.Errorf("reparse options differ: %+v != %+v", opts2, opts)
		}
		if !bytes.Equal(salt2, salt) || !bytes.Equal(key2, key) {
			t.Errorf("reparse material differs from what was parsed")
		}
	})
}
