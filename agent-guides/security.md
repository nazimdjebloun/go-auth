# Security-Sensitive Changes

Read the implementation, tests, and [`docs/security.mdx`](../docs/security.mdx)
before changing passwords, codes, tokens, sessions, OAuth credentials, CSRF,
rate limits, or account-enumeration behavior.

## General rules

- Use standard cryptographic packages and existing adapters. Do not design a new
  primitive when the repository already has one.
- Fail closed on malformed, missing, unknown-version, or unsupported security
  data. Preserve the public error shape so failure details do not become an
  enumeration oracle.
- Secrets and raw tokens must not be logged or persisted in plaintext.
- Keep purpose-derived keys separate. The application root secret, OTP pepper,
  OAuth encryption key, CSRF key, and optional password-pepper keys are not
  interchangeable.
- Rate limiting protects only routes that are actually wrapped by the
  rate-limit middleware.

## Password pipeline

- bcrypt at cost 12 is the zero-configuration default. Argon2id and custom
  hashers are opt-in through `WithPasswordHasher`; `WithBcryptCost` only changes
  bcrypt's work factor.
- Stored hashes select a verifier by their self-identifying prefix. Unknown
  prefixes fail closed and must never fall back to the current hasher.
- Verification uses parameters embedded in the stored hash. Successful login
  may rehash through the current algorithm and parameters.
- Password peppering is off unless `WithPasswordPepper` is configured. An
  unpeppered write must bypass HMAC entirely.
- A peppered row selects exactly one persisted version. Never try every key.
  Rotation adds a version; it never replaces key material under an existing
  version.
- Keep all still-referenced pepper keys available. Startup validation must reject
  a configured keyring that cannot verify a stored version.
- Password replacement paths must use the shared guarded hash-and-version update.
  Preserve monotonic pepper versions and compare-and-swap protection so an older
  node cannot overwrite a concurrent or newer credential.

## Tokens and transactions

- Reset and verification tokens are one-time credentials. Consumption must be
  atomic with the state change it authorizes when retry or concurrency could
  otherwise reuse a token.
- Password reset/change and associated session revocation must preserve their
  current transaction boundary.
- Audit delivery is currently asynchronous and best-effort. `FailureMode`
  controls continuation to later sinks; it does not roll back or fail the
  triggering request. Do not claim durable credential-event delivery without an
  outbox written in the credential transaction.

## Timing and enumeration

- Unknown-email and OAuth-only password login paths must use the shared real-KDF
  dummy verification mechanism.
- Forgot-password responses must remain account-independent. The missing-user
  path mirrors token generation, template rendering, and a realistic database
  write that is deliberately rolled back.
- Test which collaborators and branches execute; avoid brittle wall-clock timing
  assertions in ordinary CI.
