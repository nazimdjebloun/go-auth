package port

// TokenGenerator creates cryptographically random opaque tokens.
type TokenGenerator interface {
	Generate() (string, error) // 32 random bytes → hex, crypto/rand only
}
