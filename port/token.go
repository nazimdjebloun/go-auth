package port

type TokenGenerator interface {
	Generate() (string, error) // 32 random bytes → hex, crypto/rand only
}
