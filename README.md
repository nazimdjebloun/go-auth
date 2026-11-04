# go-auth

A self-hosted authentication and session library for Go. It runs inside your
application, stores data in your database, and exposes both an HTTP surface and
direct service APIs.

> **Pre-1.0:** Public Go APIs, route paths, configuration options, and JSON
> response shapes may change without a deprecation period until v1 is released.

## How it works

Configure go-auth in your Go backend, apply its database migrations, and mount
its authentication routes alongside your application routes. Your frontend
calls that backend for signup, login, verification, and session management.
Session credentials stay in HttpOnly cookies; HTTP responses tell the frontend
its next authentication `step`.

Use `Auth.Protect` on application endpoints, then add your ownership, role, or
permission checks. Applications with their own transport can call the same
operations through Go service APIs.

## What it includes

- Email/password and OAuth login, public or invited signup, and email verification
- Session and refresh-token rotation, idle expiry, and absolute lifetime limits
- Password recovery for accounts with an existing password, password changes,
  and OAuth-only account password setup after sign-in
- Optional [email-address changes](docs/guides/email-changes.mdx) with dual-mailbox
  confirmation, enabled through `WithSecurity(SecurityConfig{AllowEmailChange: true})`
- Optional email 2FA and mandatory admin-account 2FA by default
- Multi-tenant organizations, roles, invitations, and active-organization sessions
- Administrative user, session, organization, invitation, and audit-log APIs
- Opt-in [application roles and granular permissions](docs/guides/app-permissions.mdx),
  with one role per account and selective delegation of library actions
- Opt-in [organization roles and granular permissions](docs/guides/org-permissions.mdx),
  with custom roles, custom business permissions and one role per membership
- CSRF protection, route-specific rate limiting, and enumeration-resistant
  credential flows
- PostgreSQL, MySQL, and SQLite schemas embedded in the library
- Durable audit logs with a transactional outbox, retries, and dead-letter delivery
- Replaceable mailer, templates, OAuth providers, password hasher, rate-limit
  store, and audit sinks

## Install

go-auth requires Go 1.26.10 or later.

```bash
go get github.com/nazimdjebloun/go-auth
```

## Local quick start

Run the complete browser example from a source checkout. These commands use
Bash and OpenSSL; the [onboarding guide](docs/guides/onboarding.mdx) also covers
PowerShell and running from your own Go module.

```bash
git clone https://github.com/nazimdjebloun/go-auth.git
cd go-auth

export DATABASE_URL='file:onboarding.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)'
export GOAUTH_SECRET="$(openssl rand -hex 32)"
go run ./cmd/goauth migrate --driver sqlite --dsn "$DATABASE_URL"
go run ./examples/onboarding
```

Open **http://localhost:8080**. Create an account, enter the eight-character
verification code printed by the development mailer, then enter its six-digit
2FA code. Choose **Make protected request**, then **Sign out**. The page handles
CSRF bootstrap/replacement and the explicit authentication `step`; session
credentials stay in HttpOnly cookies.

The example explicitly opens signup and enables verification and 2FA. Library
signup remains closed by default. `New` always checks connectivity and recorded
migration compatibility before workers start; it never applies migrations.
Keep the generated secret for later restarts of that database.

[First working application](docs/guides/onboarding.mdx) includes consuming-module
commands, PowerShell setup, the complete flow and first-admin setup for closed
installations. The [example source](examples/onboarding/main.go) is the complete
configuration and HTTP integration, including graceful shutdown.

## Use it in your backend

Build a configuration with `NewConfig`, create an instance with `New`, and call
`Auth.Close` after your HTTP server shuts down. The
[example source](examples/onboarding/main.go) includes configuration, a database
driver import, and graceful shutdown. The main configuration sections are:

- `WithApp`: application name, frontend base URL, environment, and database.
- `WithSecret`: your persistent application secret, with at least 32 random bytes.
- `WithAuthentication`: whether password and OAuth authentication are allowed.
- `WithRegistration`: signup methods, public or invited signup, and email verification.
- `WithBrowser`: public API origin, exact frontend origins, and cookie delivery.
- `WithTwoFactor`: optional or required email 2FA.

Mount built-in routes and protect your own routes on the same server:

```go
// auth is a configured *goauth.Auth.
mux := http.NewServeMux()
auth.Mount(mux)

pattern := "GET /app/me"
mux.Handle(pattern, auth.Protect(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    user := middleware.GetUserFromContext(r.Context())
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]string{"userId": user.ID})
})))

// CORS handles preflight before the mux selects a method-specific route.
handler := auth.CORS(mux)
```

This snippet uses `net/http`, `encoding/json`, and
`github.com/nazimdjebloun/go-auth/middleware`. Pass `handler` to your HTTP server.
`Protect` combines rate limiting, browser CSRF checks, session authentication,
and email-verification enforcement. Add ownership or permission checks inside
it before accessing application data. See [application routes](docs/guides/application-routes.mdx).

For a custom router, use `handler, ok := auth.Handler("POST /auth/login")`.
The returned handler includes its middleware. Your router must populate
`PathValue` for built-in routes with parameters. See the
[integration contract](docs/guides/integration.mdx) for details.

An app and admin panel can call the same backend directly with independent
logins. The app uses the default context; the panel sends
`X-GoAuth-Session: admin` on every request. Configure both frontend origins and
the public API origin in `WithBrowser`. See [deployment](docs/guides/deployment.mdx).

## Security and defaults

- Signup is closed by default. Enable the signup methods you need separately
  from the methods allowed for login.
- Browser routes require signed double-submit CSRF protection and origin checks.
  Clients obtain a token from `GET /auth/csrf-token` and send it on mutations.
- HTTPS and secure cookies are required outside development. HTTP is supported
  in `EnvironmentDev`; use a real mailer for deployed applications.
- Password hashing defaults to bcrypt at cost 12. Argon2id and versioned password
  peppering are opt-in. Passwords default to 8–128 Unicode code points with a
  letter and a digit; the selected algorithm's input limit also applies.
- Password changes invalidate outstanding reset links. Reset completion also
  invalidates any other outstanding reset links for that account.
- Password-confirmed account deletion rechecks the verified credential inside
  its transaction before removing account data.
- Password setup rechecks the exact code's purpose, ownership, hash, expiry and
  unused state when claiming it, after password hashing and database lock waits.
- Admin accounts require email 2FA by default. User 2FA can be optional or required.
- When email verification is required, unverified accounts must verify before
  accessing protected routes, including through an existing session.
- Fixed-role invitations recheck the issuer's current authority at acceptance
  and renewal. Only an Owner can renew an Owner invitation.

See [configuration](docs/configuration.mdx) for every default and
[security](docs/security.mdx) for the guarantees and deployment requirements.

## Using the library without HTTP

`Auth` exposes facade methods for core operations. Import their input types from
`github.com/nazimdjebloun/go-auth/api`:

```go
result, err := auth.Login(ctx, api.LoginInput{
	Email:     email,
	Password:  password,
	IP:        clientIP,
	UserAgent: userAgent,
})
```

The complete service surface is available under `auth.Services()` for applications
that provide their own transport. Direct calls execute business rules; your
transport supplies authentication, authorization, rate limits, and browser
protections where applicable. See the [integration contract](docs/guides/integration.mdx).

Repository test doubles implementing `port.UserRepository` must use the
`SetPasswordAndVerify(ctx, port.SetPasswordAndVerifyInput)` contract, which carries
the validated token hash and email as well as the new credential.

## Documentation

- [Installation](docs/installation.mdx) — prerequisites, drivers, CLI, and setup
- [Configuration](docs/configuration.mdx) — every option, default, and validation
  rule
- [Security](docs/security.mdx) — password hashing, peppers, tokens, CSRF, 2FA,
  and enumeration protection
- [Routes](docs/routes/) — HTTP methods, paths, authentication, and bodies
- [Schemas](docs/schemas.mdx) — tables, indexes, and driver differences
- [Migrations](docs/migrations.mdx) — separate auth history, adoption, exports, and recovery
- [Guides](docs/guides/) — authentication, sessions, organizations, OAuth,
  administration, rate limiting, and audit logs
- [Architecture](docs/architecture.mdx) — package boundaries, middleware, and
  transaction behavior
- [Error handling](docs/error-handling.mdx) — public error codes and statuses
- [Changelog](docs/changelog/index.mdx) — release history and upgrade instructions

The documentation is also published at
[go-auth.nimirixlabs.com](https://go-auth.nimirixlabs.com).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and verification steps.
See [TESTING.md](TESTING.md) for the full SQLite, PostgreSQL, and MySQL suites.

## License

[MIT](LICENSE)
