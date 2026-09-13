package port

// Hasher hashes and verifies passwords. The default implementation is bcrypt;
// the optional hasher/argon2id package is also built in. WithPasswordHasher
// replaces the current implementation for new hashes while the service
// registry keeps legacy bcrypt and Argon2id hashes verifiable by prefix.
//
// Hash must be a one-way, salted hash safe to store (bcrypt, scrypt, argon2
// — never a fast general-purpose hash like SHA-256). Compare must run in
// time independent of where the mismatch occurs (bcrypt's own comparison
// already does this) and return nil only on a genuine match — any other
// outcome, including a malformed hash, is a non-nil error, never a panic.
// Hash output must self-identify its format with a stable prefix such as
// "$argon2id$" so verification can dispatch without adding algorithm methods
// to this interface.
type Hasher interface {
	Hash(password string) (string, error)
	Compare(password, hash string) error
}
