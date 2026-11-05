package goauth

import (
	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/port"
)

// PasswordHashingConfig groups password algorithms, optional peppering and
// resource limits. Its zero value selects bcrypt cost 12, no password pepper,
// and a private limiter allowing four active operations per Auth instance.
// Password policy remains in SecurityConfig.
type PasswordHashingConfig struct {
	// Hasher selects the algorithm for new writes and rehash-on-login. Nil
	// selects bcrypt. Stored hashes always select their verifier by prefix.
	// Custom hashers must produce self-identifying hashes and verify their
	// own output; built-in bcrypt and Argon2id remain legacy verifiers.
	// Supply argon2id.New(argon2id.Options{...}) to configure Argon2id.
	Hasher port.Hasher

	// BcryptCost applies only when Hasher is nil. Zero selects cost 12.
	BcryptCost int

	// Pepper configures an independent versioned keyring. Zero disables
	// peppering for new writes; historical keys may remain available.
	// Each key must contain at least 32 bytes of independent secret material.
	Pepper PasswordPepperConfig

	// Concurrency caps active hashing and verification per Auth. Zero selects
	// four; negative values fail validation, even with a shared WorkLimiter.
	Concurrency int

	// WorkLimiter optionally shares capacity across Auth instances. A non-nil
	// limiter takes precedence over Concurrency. Construct it with
	// hasher.NewWorkLimiter; Auth.Close does not close it.
	WorkLimiter *hasher.WorkLimiter
}

// WithPasswordHashing replaces the entire password-hashing configuration.
// Include all intended hashing settings in one call; omitted fields return to
// their defaults. The pepper key map is copied whenever the option is applied;
// the live Hasher and WorkLimiter are shared with the caller.
func WithPasswordHashing(cfg PasswordHashingConfig) Option {
	return func(c *Config) {
		c.passwordHasher = cfg.Hasher
		c.bcryptCost = cfg.BcryptCost
		c.passwordPepper = cfg.Pepper
		if cfg.Pepper.Keys != nil {
			c.passwordPepper.Keys = make(map[uint32]string, len(cfg.Pepper.Keys))
			for version, secret := range cfg.Pepper.Keys {
				c.passwordPepper.Keys[version] = secret
			}
		}
		c.passwordConcurrency = cfg.Concurrency
		c.passwordWorkLimiter = cfg.WorkLimiter
	}
}
