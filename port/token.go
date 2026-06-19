package port

type TokenGenerator interface {
	Generate() (raw string, hash string, err error)
	Hash(raw string) string
}
