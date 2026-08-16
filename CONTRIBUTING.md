# Contributing to go-auth

This project is pre-1.0 and solo-maintained. For anything beyond a small,
obvious fix, please open an issue first to align on approach before
writing code — it saves both of us a rejected PR.

## Dev setup

    go build ./...
    go vet ./...
    go test ./...

`cmd/goauth` is a **separate module** (its own `go.mod`) — the commands
above from the repo root don't touch it. Run them again from inside
`cmd/goauth` for any change to the CLI:

    cd cmd/goauth
    go build ./...
    go vet ./...
    go test ./...

No external services required for either module — the `integration`
suite skips its Postgres-backed tests unless `GOAUTH_POSTGRES_DSN` is
set (see [Testing](#testing) below).

## Architecture

go-auth follows a ports-and-adapters (hexagonal) layout. Read
[`docs/architecture.mdx`](docs/architecture.mdx) for the full picture —
this section is the short version so you know where a change actually
belongs before you start writing it.

**Dependency direction is strict, in this order:**

    domain  <-  port  <-  service  <-  internal/sqlstore, internal/handler, middleware, provider

- **`domain`** — core types (`User`, `Session`, `Organization`, ...) and
  every `AuthError`. Depends on nothing else in the module.
- **`port`** — the interfaces `service` depends on: `Mailer`, `Hasher`,
  `TokenGenerator`, `TemplateProvider`, `OAuthProvider`, `TxManager`, and
  one repository interface per aggregate (`UserRepository`,
  `SessionRepository`, `OrgRepository`, ...).
- **`service`** — the actual business logic, one file per concern
  (`auth.go`, `password.go`, `admin.go`, `oauth.go`, `org.go`, ...).
  Depends only on `domain` and `port` — **never** on `database/sql`,
  `net/http`, or anything under `internal/`.
- **`internal/sqlstore`** — `port` repository interfaces implemented over
  `database/sql`/`pgx`, one `_repo.go` per aggregate.
- **`internal/handler`** — HTTP adapters: decode a request, call a
  service method, write JSON or set a cookie. Never contains business
  logic itself.
- **`internal/routes`** — the single source of truth mapping every
  `"METHOD /path"` to a `HandlerGroup` entry and its rate limit.
- **`middleware`** — cross-cutting HTTP concerns (auth/role gating,
  CSRF, CORS, rate limiting, org access control), composed per-route in
  `auth.go`'s `New()`.
- **`provider`** — built-in OAuth adapters (`provider/google`,
  `provider/github`), each implementing `port.OAuthProvider`.

`auth.go`'s `New()` is the composition root: it's the one place every
adapter gets constructed and wired into a service. If you're adding a
new adapter (a repository, a mailer, an OAuth provider), it gets
constructed there and nowhere else.

**Where a given kind of change goes:**

- New business rule on an existing aggregate → add/edit a method in the
  matching `service/*.go` file. If it needs new data access, add the
  method to the relevant `port.*Repository` interface first, then
  implement it in `internal/sqlstore`.
- New HTTP-reachable operation → service method (above), then a handler
  in `internal/handler`, then an entry in `internal/routes` (this is
  what actually exposes it — a handler with no route entry is dead
  code).
- New OAuth provider → a new package under `provider/`, implementing
  `port.OAuthProvider` (`Name()`, `AuthURL()`, `Exchange()`).
- New middleware / cross-cutting HTTP concern → `middleware/`, then wire
  it into the relevant chain in `auth.go`'s `New()`.
- Schema change → `internal/schema` (embedded SQL, one file per driver)
  — every `CREATE` statement must stay `IF NOT EXISTS`; `goauth migrate`
  has to stay idempotent on an already-migrated database.

Every operation is reachable two ways — see the "Two ways to drive it"
section of `docs/architecture.mdx` for why `service` never imports
`net/http`: it means `auth.Services.Auth.Register(...)` and
`auth.Mount(mux)`'s HTTP route both call the exact same code path, so a
bug fixed once is fixed in both.

## Testing

Unit tests live next to the code they test (`service/*_test.go`,
`internal/handler/*_test.go`, ...) and use hand-written fakes for the
`port` interfaces (`internal/testutil`) — they run with no database, no
network, no external services, and should stay that way for anything
you add in `service`.

The `integration` package runs the same flows against real Postgres,
MySQL, and SQLite. Each `_test.go` there checks its own env var
(e.g. `GOAUTH_POSTGRES_DSN`) and calls `t.Skip` — not fail — if it's
unset, so `go test ./...` stays green without any database running
locally. If you touch `internal/sqlstore` or the embedded schema, add or
update the matching integration test; SQLite alone doesn't prove
Postgres/MySQL-specific SQL is still correct.

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
