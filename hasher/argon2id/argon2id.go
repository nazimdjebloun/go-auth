// Package argon2id provides an Argon2id implementation of port.Hasher.
package argon2id

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/nazimdjebloun/go-auth/port"
	"golang.org/x/crypto/argon2"
)

const (
	minimumSaltLength = 8
	minimumKeyLength  = 16
	maximumSaltLength = 1024
	maximumKeyLength  = 1024

	// Bound parameters parsed from database strings before IDKey allocates.
	// The memory ceiling includes RFC 9106's 2 GiB recommendation while
	// rejecting corrupted uint32-scale values that would certainly exhaust a
	// normal process. Deployments must still size concurrency and rate limits
	// for their chosen memory cost.
	maximumMemoryKiB  = 2 * 1024 * 1024
	maximumIterations = 1000
)

var (
	// ErrInvalidHash reports a malformed, unsupported, or unsafe Argon2id
	// encoded string.
	ErrInvalidHash = errors.New("argon2id: invalid hash")
	// ErrPasswordMismatch reports a well-formed hash that the password does
	// not match.
	ErrPasswordMismatch = errors.New("argon2id: password does not match hash")
)

// Options controls Argon2id hashing. Memory is measured in KiB.
type Options struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultOptions returns RFC 9106 section 4's second, memory-constrained
// Argon2id profile: 64 MiB, three iterations, four lanes, a 16-byte salt, and
// a 32-byte key. Applications should still capacity-plan concurrent attempts
// for their own hardware before enabling Argon2id in production.
func DefaultOptions() Options {
	return Options{
		Memory:      65536,
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

type argon2idHasher struct {
	options Options
}

// New returns an Argon2id password hasher. Invalid options are reported by
// Hash; Compare always uses parameters embedded in the stored hash rather
// than these options, so older parameter sets remain verifiable.
func New(opts Options) port.Hasher {
	return &argon2idHasher{options: opts}
}

func (h *argon2idHasher) Hash(password string) (string, error) {
	if err := validateOptions(h.options); err != nil {
		return "", err
	}
	salt := make([]byte, h.options.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("argon2id: generate salt: %w", err)
	}
	key := argon2.IDKey(
		[]byte(password), salt,
		h.options.Iterations, h.options.Memory, h.options.Parallelism, h.options.KeyLength,
	)
	return encode(h.options, salt, key), nil
}

func (h *argon2idHasher) Compare(password, stored string) error {
	opts, salt, expected, err := parse(stored)
	if err != nil {
		return err
	}
	actual := argon2.IDKey(
		[]byte(password), salt,
		opts.Iterations, opts.Memory, opts.Parallelism, opts.KeyLength,
	)
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

func encode(opts Options, salt, key []byte) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		opts.Memory,
		opts.Iterations,
		opts.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

func parse(stored string) (Options, []byte, []byte, error) {
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return Options{}, nil, nil, fmt.Errorf("%w: expected argon2id PHC string", ErrInvalidHash)
	}
	version, err := parseUintField(parts[2], "v=", 32)
	if err != nil || version != argon2.Version {
		return Options{}, nil, nil, fmt.Errorf("%w: unsupported version", ErrInvalidHash)
	}

	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return Options{}, nil, nil, fmt.Errorf("%w: expected m, t, and p parameters", ErrInvalidHash)
	}
	memory, err := parseUintField(params[0], "m=", 32)
	if err != nil {
		return Options{}, nil, nil, fmt.Errorf("%w: invalid memory parameter", ErrInvalidHash)
	}
	iterations, err := parseUintField(params[1], "t=", 32)
	if err != nil {
		return Options{}, nil, nil, fmt.Errorf("%w: invalid iteration parameter", ErrInvalidHash)
	}
	parallelism, err := parseUintField(params[2], "p=", 8)
	if err != nil {
		return Options{}, nil, nil, fmt.Errorf("%w: invalid parallelism parameter", ErrInvalidHash)
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return Options{}, nil, nil, fmt.Errorf("%w: invalid salt encoding", ErrInvalidHash)
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return Options{}, nil, nil, fmt.Errorf("%w: invalid key encoding", ErrInvalidHash)
	}
	if memory > math.MaxUint32 || iterations > math.MaxUint32 || parallelism > math.MaxUint8 ||
		uint64(len(salt)) > math.MaxUint32 || uint64(len(key)) > math.MaxUint32 {
		return Options{}, nil, nil, fmt.Errorf("%w: parameter overflows supported range", ErrInvalidHash)
	}
	saltLength, err := lengthAsUint32(len(salt))
	if err != nil {
		return Options{}, nil, nil, fmt.Errorf("%w: invalid salt length", ErrInvalidHash)
	}
	keyLength, err := lengthAsUint32(len(key))
	if err != nil {
		return Options{}, nil, nil, fmt.Errorf("%w: invalid key length", ErrInvalidHash)
	}
	opts := Options{
		Memory:      uint32(memory),
		Iterations:  uint32(iterations),
		Parallelism: uint8(parallelism),
		SaltLength:  saltLength,
		KeyLength:   keyLength,
	}
	if err := validateOptions(opts); err != nil {
		return Options{}, nil, nil, fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}
	return opts, salt, key, nil
}

func lengthAsUint32(length int) (uint32, error) {
	if length < 0 || uint64(length) > math.MaxUint32 {
		return 0, ErrInvalidHash
	}
	return uint32(length), nil
}

func parseUintField(field, prefix string, bitSize int) (uint64, error) {
	value, ok := strings.CutPrefix(field, prefix)
	if !ok || value == "" {
		return 0, ErrInvalidHash
	}
	return strconv.ParseUint(value, 10, bitSize)
}

func validateOptions(opts Options) error {
	if opts.Iterations == 0 || opts.Iterations > maximumIterations {
		return fmt.Errorf("argon2id: iterations must be between 1 and %d", maximumIterations)
	}
	if opts.Parallelism == 0 {
		return errors.New("argon2id: parallelism must be positive")
	}
	minimumMemory := uint32(8) * uint32(opts.Parallelism)
	if opts.Memory < minimumMemory || opts.Memory > maximumMemoryKiB {
		return fmt.Errorf("argon2id: memory must be between %d and %d KiB", minimumMemory, maximumMemoryKiB)
	}
	if opts.SaltLength < minimumSaltLength || opts.SaltLength > maximumSaltLength {
		return fmt.Errorf("argon2id: salt length must be between %d and %d bytes", minimumSaltLength, maximumSaltLength)
	}
	if opts.KeyLength < minimumKeyLength || opts.KeyLength > maximumKeyLength {
		return fmt.Errorf("argon2id: key length must be between %d and %d bytes", minimumKeyLength, maximumKeyLength)
	}
	return nil
}

var _ port.Hasher = (*argon2idHasher)(nil)
