# go-auth

A self-hosted authentication and session library for Go. It runs inside your
application, stores data in your database, and exposes both an HTTP surface and
direct service APIs.

> **Pre-1.0:** Public Go APIs, route paths, configuration options, and JSON
> response shapes may change without a deprecation period until v1 is released.

## What it includes

- Email/password and OAuth registration and login
- Session and refresh-token rotation, idle expiry, and absolute lifetime limits
- Password recovery for accounts with an existing password, password changes,
  email verification, and OAuth-only account password setup after sign-in
- Optional email 2FA and mandatory admin-login 2FA by default
- Multi-tenant organizations, roles, invitations, and active-organization
  sessions whose scope stays synchronized with membership changes
- Administrative user, session, organization, invitation, and audit-log APIs
- CSRF protection, route-specific rate limiting, and enumeration-resistant
  credential flows
- PostgreSQL, MySQL, and SQLite schemas embedded in the library
- Durable audit pipeline with a transactional outbox, retry + dead-letter delivery, and custom sink support
- Replaceable mailer, templates, OAuth providers, password hasher, rate-limit
  store, and audit sinks

## Install

go-auth requires Go 1.26 or later.

```bash
go get github.com/nazimdjebloun/go-auth
```

## Local quick start

This example uses SQLite and `EnvironmentDev`. Development mode supplies a
log-only mailer when no mailer is configured, so verification codes and emails
are written to the application log instead of being delivered.

```go
package main

import (
	"log"
	"net/http"
	"os"

	goauth "github.com/nazimdjebloun/go-auth"
	_ "modernc.org/sqlite"
)

func main() {
	cfg, err := goauth.NewConfig(
		goauth.WithApp(goauth.AppConfig{
			Name:        "MyApp",
			BaseURL:     "http://localhost:3000",
			Environment: goauth.EnvironmentDev,
			Database: goauth.DatabaseConfig{
				URL:    "file:goauth.db",
				Driver: goauth.DriverSQLite,
			},
		}),
		goauth.WithSecret(os.Getenv("AUTH_SECRET")), // at least 32 bytes
		goauth.WithSecurity(goauth.SecurityConfig{
			AllowedOrigins: []string{"http://localhost:3000"},
		}),
	)
	if err != nil {
		log.Fatal(err)
	}

	auth, err := goauth.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer auth.Close()

	mux := http.NewServeMux()
	auth.Mount(mux)
	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

Generate a development secret and apply the embedded schema before starting the
application:

```bash
export AUTH_SECRET="$(openssl rand -base64 32)"

go run github.com/nazimdjebloun/go-auth/cmd/goauth@latest migrate \
  --driver sqlite --dsn "file:goauth.db"
```

`cmd/goauth` is part of the root library module. The version suffix in the
command above runs a published release independently of the `go-auth` version
your application's `go.mod` pins; from a source checkout, use
`go run ./cmd/goauth` instead.

Email verification marks the address verified and then requires a separate
sign-in; it does not issue session cookies. OAuth initiation sets a short-lived
browser state cookie that must return on the callback. Provider linking also
requires the same live session at the callback. If you call `auth.Services().OAuth`
directly, use the `State` field of the returned `api.OAuthInitiation` to bind
the flow to the initiating browser and pass that value to `Callback`.
OAuth rejects failed profile requests and missing or mismatched provider
identities before looking up or linking an account.

For production, configure SMTP with `WithEmail` or provide a custom
`port.Mailer`. A mailer is required whenever an enabled feature sends email;
admin-login 2FA is one such feature and is enabled by default. PostgreSQL support
is built on pgx. SQLite and MySQL applications must blank-import their selected
`database/sql` driver.

## Password security

`New` revalidates the complete configuration before deriving secrets or
starting services, including options applied after `NewConfig`.

Password login and 2FA session issuance serialize with password replacement.
A reset or change revokes pending challenges and prevents an in-flight login
from issuing a session using the old password.

The zero-configuration password KDF is bcrypt at cost 12. Existing hashes select
their verifier from their own format prefix, and a successful login upgrades a
stale algorithm or parameter set through a guarded rehash.

Argon2id is available but is not the default:

```go
import "github.com/nazimdjebloun/go-auth/hasher/argon2id"

goauth.WithPasswordHasher(argon2id.New(argon2id.DefaultOptions()))
```

`argon2id.DefaultOptions()` uses RFC 9106's memory-constrained profile: 64 MiB,
three iterations, and parallelism four. Its memory cost applies to every
concurrent hash or comparison, so benchmark it on the deployment hardware.

Password peppering is also opt-in. Omitting `WithPasswordPepper` skips HMAC and
stores an ordinary bcrypt or Argon2id hash. To enable independently versioned
pepper keys:

```go
goauth.WithPasswordPepper(goauth.PasswordPepperConfig{
	CurrentVersion: 1,
	Keys: map[uint32]string{
		1: os.Getenv("AUTH_PASSWORD_PEPPER_V1"), // at least 32 bytes
	},
})
```

All instances must receive the same version-to-secret mapping. Add a new version
for rotation, preload it on every instance, then make it current while retaining
every key still referenced by the database. Missing or empty configured keys
fail startup; the library never silently falls back to unpeppered verification
for a versioned row. See [Password hashing and pepper
rotation](docs/security.mdx#password-hashing-and-hasher-migration) for the full
rollout procedure and failure model.

## Using the library without HTTP

`Auth` exposes facade methods for core operations:

Import the operation types from `github.com/nazimdjebloun/go-auth/api`.

```go
result, err := auth.Login(ctx, api.LoginInput{
	Email:     email,
	Password:  password,
	IP:        clientIP,
	UserAgent: userAgent,
})
```

The complete service surface is available under `auth.Services()` for applications
that provide their own transport. The returned bundle is a value, so reassigning
one of its fields does not change the instance's wiring. `Auth.Mount` remains
the simplest way to use the built-in handlers, cookies, CSRF checks, and route
middleware.

For a custom router, use `handler, ok := auth.Handler("POST /auth/login")`.
The returned handler has its middleware already applied and sets the canonical
request pattern for rate limiting. For routes with `{parameter}` path segments,
your router must populate the corresponding `PathValue`s. Disabled and unknown
routes return `ok == false`.

## Documentation

- [Installation](docs/installation.mdx) — prerequisites, drivers, CLI, and setup
- [Configuration](docs/configuration.mdx) — every option, default, and validation
  rule
- [Security](docs/security.mdx) — password migration, peppers, tokens, CSRF, 2FA,
  and enumeration protection
- [Routes](docs/routes/) — HTTP methods, paths, authentication, and bodies
- [Schemas](docs/schemas.mdx) — tables, indexes, migrations, and driver differences
- [Guides](docs/guides/) — authentication, sessions, organizations, OAuth,
  administration, rate limiting, and audit logs
- [Architecture](docs/architecture.mdx) — package boundaries, middleware, and
  transaction behavior
- [Error handling](docs/error-handling.mdx) — public error codes and statuses

The documentation is also published at
[go-auth.nimirixlabs.com](https://go-auth.nimirixlabs.com).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and verification steps.

## License

[MIT](LICENSE)
