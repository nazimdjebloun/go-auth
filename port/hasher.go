package port

// Hasher hashes and verifies passwords. The built-in implementation
// (hasher.BcryptHasher) is bcrypt, always used unless you override it —
// there is no WithHasher option, so implementing this interface is only
// useful if you're constructing services directly rather than through
// goauth.New.
//
// Hash must be a one-way, salted hash safe to store (bcrypt, scrypt, argon2
// — never a fast general-purpose hash like SHA-256). Compare must run in
// time independent of where the mismatch occurs (bcrypt's own comparison
// already does this) and return nil only on a genuine match — any other
// outcome, including a malformed hash, is a non-nil error, never a panic.
type Hasher interface {
	Hash(password string) (string, error)
	Compare(password, hash string) error
}
