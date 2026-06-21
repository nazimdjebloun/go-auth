# go-auth

Authentication Go library with session management, email verification, password reset, invite-only signup, admin user management, and rate limiting.

## Commands

```sh
go build ./...                  # build library
go vet ./...                    # typecheck + lint
go test ./...                   # all tests (SQLite in-memory, no external services)
go test ./service               # unit tests only
go test ./integration           # integration tests (SQLite: no setup; Postgres: needs env vars)
go test -run TestName ./service
go vet ./... && go build ./... && go test ./...  # preferred full check order

# CLI is a separate module
cd cmd/go-auth && go build .    # build CLI binary
cd cmd/go-auth && go vet .      # vet CLI
```

## Architecture

- `auth.go` — `New(Config)` creates the `Auth` struct, opens DB, runs migrations, wires all services, handlers, and middleware
- `auth.config.go` — `Config`, `DefaultConfig()`, `NewConfig(opts...)`, `validate()`. Use `NewConfig` for validation; direct `Config{}` skips it
- `schema.go` — embedded SQL schemas for postgres, mysql, sqlite. Get via `GetSchema(driver)`, which also powers `cmd/go-auth`
- `split.go` — `SplitSQL(sql)` splits semicolon-delimited SQL, used internally by `runMigrations` and by the CLI
- `email.go` — unexported `SMTPMailer` implementing `port.Mailer` via `go-mail` with `TLSOpportunistic`
- `port/` — interfaces: `Mailer`, `Hasher`, `TokenGenerator`, `UserRepository`, `SessionRepository`, `TokenRepository`, `InviteRepository`
- `service/` — business logic: `AuthService`, `SessionService`, `PasswordService`, `VerificationService`, `InviteService`, `AdminService`. All accept `port.*` interfaces.
- `handler/` — HTTP handlers, JSON response helpers. `handler.Services` groups all services.
- `middleware/` — `AuthMiddleware` (cookie → session → user → context), `RequireRole`, `CSRF`, `RateLimit`
- `ratelimit/` — config with per-route limits, in-memory store, IPv6 /64 subnet masking
- `sqlstore/` — Postgres-backed repositories. `DB` wraps `*sql.DB` with `$N → ?` rebind for MySQL/SQLite compatibility.
- `domain/` — `User`, `Session`, `VerificationToken`, `Invite`, `PasswordPolicy`, `AuthError` (typed errors with HTTP status)

## Key conventions

- **Consumer-owned drivers**: only `pgx/v5` is in the library's `go.mod`. SQLite/MySQL consumers add `_ "modernc.org/sqlite"` or `_ "github.com/go-sql-driver/mysql"` in their own `main` package. `New()` validates driver registration at runtime with actionable error messages. Exception: the CLI (`cmd/go-auth/`) is a separate module that owns all three drivers.
- **Rate limiting disabled by default**: set `RateLimit.Enabled = true` in production. Default has route-specific limits (login: 5/min, register: 3/min, etc.).
- **Postgres pool**: `Auth.Pool` (`*pgxpool.Pool`) is exported for consumer access. Only created when `DriverPostgres` and `URL` is used.
- **Session idle TTL**: `SessionIdleTTL` (default 7d) enforced via `SessionService.Touch()` which updates `last_active_at`.
- **Config.Mailer priority**: custom `port.Mailer` takes precedence over `EmailConfig` SMTP settings.
- **AuthService.Register** sends verification email via `VerificationService.SendVerification()` when `RequireEmailVerification` is true.
- **Middleware order**: `authMW(adminMW(handler))` — auth runs first, then role check.
- **Module path**: `github.com/nazimdjebloun/go-auth`. All internal imports use `go-auth/...` (not `go-auth`).

## Notable types

- `Config` (root package) — top-level config with `NewConfig(opts...)` functional options + `validate()`
- `Auth` — main struct: `New(Config) (*Auth, error)`, `Mount(*http.ServeMux)`, `Close()`
- `RegisterInput`/`RegisterResult`/`LoginInput`/`LoginResult` — re-exported in root package for consumer convenience
- `domain.AuthError` — `{Code, Message, HTTPStatus}`. Predefined errors in `domain/errors.go`.

## Integration tests

- `./integration/integration_test.go` — SQLite-based. Runs without setup (uses `modernc.org/sqlite`).
- `./integration/postgres_test.go` — requires `AUTH_DSN` env pointing to a real Postgres. Skipped if unset.

## Package boundaries

| Directory | Responsibility |
|---|---|
| `domain/` | data types, errors, password policy |
| `port/` | repository & service interfaces |
| `sqlstore/` | Postgres/SQLite/MySQL repository implementations |
| `service/` | business logic (auth, sessions, passwords, verification, invites, admin) |
| `handler/` | HTTP handler layer |
| `middleware/` | auth, CSRF, rate limit middleware |
| `ratelimit/` | rate limit config, in-memory store |
| `hasher/` | bcrypt password hashing |
| `token/` | crypto/rand token generation |
| `cmd/go-auth/` | CLI binary (separate module) for running migrations |

## CLI module

`cmd/go-auth/` is a **separate Go module** (`go.mod` lives there) so it can own all three driver imports without polluting the library. Supports postgres, mysql, and sqlite3. Build with `cd cmd/go-auth && go build .`.

```sh
# Examples
go-auth --cmd init-schema --driver sqlite3
go-auth --cmd migrate --driver postgres --dsn "postgres://..."
AUTH_DSN="mysql://..." go-auth --cmd migrate --driver mysql
```
