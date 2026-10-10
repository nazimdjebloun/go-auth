# Contributing to go-auth

This project is pre-1.0 and solo-maintained. For anything beyond a small,
obvious fix, please open an issue first to align on approach before
writing code — it saves both of us a rejected PR.

## Dev setup

    go build ./...
    go vet ./...
    go test ./...
    golangci-lint run ./...

`cmd/goauth` is an executable package in the root module. The commands above
build, vet, and test both the library and CLI. For a focused CLI check:

    go test ./cmd/goauth/...
    go run ./cmd/goauth --help

No external services are required for the default test run. PostgreSQL tests
skip unless `GOAUTH_POSTGRES_DSN` is set; the CLI MySQL bootstrap test skips
unless `GOAUTH_MYSQL_TEST_DSN` is set (see [Testing](#testing) below).

The library and CLI share one root release tag. There is no nested CLI module
or checkout-relative dependency replacement.

## Architecture

go-auth follows a ports-and-adapters (hexagonal) layout. Read
[`docs/architecture.mdx`](docs/architecture.mdx) for the full picture —
this section is the short version so you know where a change actually
belongs before you start writing it.

**Dependencies point toward shared types and capability interfaces:**

    domain <- api <- port
    internal/service -> api, domain, port, internal helpers
    internal/sqlstore, provider -> port
    internal/handler, middleware -> service capabilities, api, domain, port

- **`domain`** — core types (`User`, `Session`, `Organization`, ...) and
  every `AuthError`. Depends on nothing else in the module.
- **`api`** — transport-neutral operation inputs, results, and sort types;
  imports `domain`.
- **`port`** — the interfaces `internal/service` depends on: `Mailer`, `Hasher`,
  `TokenGenerator`, `TemplateProvider`, `OAuthProvider`, `TxManager`, and
  narrow repository capabilities (readers, writers, counters, and related
  operations) plus composed repository interfaces per aggregate. Imports
  `api` and `domain` for shared types.
- **`internal/service`** — the actual business logic, one file per concern
  (`auth.go`, `password.go`, `admin.go`, `oauth.go`, `org.go`, ...).
  Uses `api`, `domain`, `port`, and shared helpers such as token hashing,
  templates, and audit delivery. SQL persistence stays in `internal/sqlstore`.
  Some service code uses `net/http` cookie constants; HTTP request decoding
  and response writing belong in handlers.
- **`internal/sqlstore`** — `port` repository interfaces implemented over
  `database/sql`/`pgx`, one `_repo.go` per aggregate.
- **`internal/handler`** — HTTP adapters: decode a request, call a
  service method, write JSON or set a cookie. Never contains business
  logic itself.
- **`internal/routes`** — canonical `"METHOD /path"` constants shared by
  route wiring and rate limit configuration.
- **`internal/httproutes`** — pairs enabled route patterns with handlers and
  their exact middleware chains.
- **`middleware`** — cross-cutting HTTP concerns (auth/role gating,
  CSRF, CORS, rate limiting, org access control), constructed in
  `wire_http.go` and composed per route in `internal/httproutes`.
- **`provider`** — built-in OAuth adapters (`provider/google`,
  `provider/github`), each implementing `port.OAuthProvider`.

`auth.go`'s `New()` is the composition root and delegates construction to
`wire_*.go`: database setup, adapter resolution, services, and HTTP wiring.
Add new dependencies through these wiring functions and the existing
configuration hooks.

**Where a given kind of change goes:**

- New business rule on an existing aggregate → add/edit a method in the
  matching `internal/service/*.go` file. If it needs new data access, add the
  method to the relevant narrow `port` capability first, then
  implement it in `internal/sqlstore`.
- New HTTP-reachable operation → service method (above), then a handler
  in `internal/handler`, a pattern constant in `internal/routes`, and an
  entry in `internal/httproutes` (the entry exposes the handler).
- New OAuth provider → a new package under `provider/`, implementing
  `port.OAuthProvider` (`Name()`, `AuthURL()`, `Exchange()`).
- New middleware / cross-cutting HTTP concern → `middleware/`, then construct
  it in `wire_http.go` and apply it to the relevant `internal/httproutes` entries.
- Schema change → `internal/schema` (embedded SQL, one file per driver)
  — every `CREATE` statement must stay `IF NOT EXISTS`; `goauth migrate`
  has to stay idempotent on an already-migrated database.

Core operations can be called programmatically or through optional HTTP
routes. For example, `auth.Services().Auth.Register(...)` and the registration
route mounted by `auth.Mount(mux)` share the same service logic. The HTTP
handler adds transport behavior such as JSON encoding and cookie delivery.
See the "Two ways to drive it" section of `docs/architecture.mdx`.

## Testing

Tests live next to the code they test (`internal/service/*_test.go`,
`internal/handler/*_test.go`, ...) and in `integration/`. Unit tests use
hand-written `port` fakes from `internal/testutil`. Transaction, concurrency,
repository, integration, and CLI tests also use real databases through
`internal/testdb`.

Shared fixtures default to SQLite, so `go test ./...` needs no external
database. Selecting PostgreSQL or MySQL with `GOAUTH_TEST_DRIVER` requires
`GOAUTH_POSTGRES_DSN` or `GOAUTH_MYSQL_TEST_DSN`, respectively; missing
configuration fails these fixtures. Some standalone server tests skip when
their DSNs are absent. Use the backend runner in [TESTING.md](TESTING.md) to
require the full suites and detect unexpected skips. If you touch
`internal/sqlstore` or the embedded schema, update the matching database tests;
SQLite alone doesn't prove PostgreSQL/MySQL-specific SQL is still correct.

## Workflow

Fork the repo, branch off `main`, open a PR against `main`. Small,
single-concern PRs over large ones — this repo's own history commits in
fairly fine-grained chunks (see [Commit messages](#commit-messages)
below); match that rather than bundling unrelated changes.

## Commit messages

    <type>[(scope)]: <imperative, lowercase summary>

Examples from the existing history:

    fix(config): make SessionConfig.GraceWindow/TouchDebounce *time.Duration
    feat(api): unify error returns to plain error across the public surface
    docs: reorder sidebar and drop the custom provider page

Types in use: feat, fix, refactor, test, docs, security, chore, style.

## Review

CI must pass. Changes touching auth, sessions, tokens, CSRF, or OAuth get
closer scrutiny — see `docs/security.mdx` for the guarantees this library
states publicly.

## License

By contributing, you agree your changes are licensed under this repo's
MIT license.
