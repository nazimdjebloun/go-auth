# go-auth — Agent Guide

## CRITICAL RULES

- **NEVER commit or push anything without explicit user approval.** Not even once.
- **Breaking changes are welcome pre-launch** — the API isn't frozen yet. The goal is a clean, solid public API before v1. When you make one, update `docs/` and the README in the same pass so the docs never lag the code.
- **Never write docs from memory** — verify each claim against the code before putting it in a doc.
- **NEVER run gofmt on files you didn't touch** — ~25 legacy files (`audit/event.go`, `auth.go`, etc.) are intentionally left non-formatted.

## Environment rule (WSL)

This repo is on a Windows drive but builds and tests **only inside WSL** (Linux toolchain). Run every Go command through WSL:

```powershell
wsl -e bash -lc "cd /mnt/d/files/desktop/go-auth && go build ./..."
```

- WSL does **not** have `rg` — use `grep`/`grep -rn` for searches.
- Paths: `D:\files\desktop\go-auth` ↔ `/mnt/d/files/desktop/go-auth`.
- `cmd/goauth` is a **separate Go module** — build/test it separately.

## Commands (run inside WSL)

```sh
go vet ./... && go build ./... && go test ./... -count=1   # full check, root module
go test ./service            # service unit tests only
go test ./integration        # SQLite e2e (no setup); Postgres needs AUTH_DSN, else skipped
go test -run TestName ./service
go test ./cmd/goauth/...     # CLI module (separate go.mod)
gofmt -l <edited files>      # confirm your files are clean
```

Preferred order after any change: `go vet`, `go build`, `go test -count=1` — root **and** `cmd/goauth`.

## Architecture (current)

| Layer | Location | Responsibility |
|---|---|---|
| Config | `auth.config.go` | unexported `config`, `Option` funcs, `NewConfig(opts...)` → `applyDefaults()` → `validate()` |
| Wiring | `auth.go` | `New(config)` builds DB + services + handlers; `Mount(*http.ServeMux)` registers routes |
| Routes | `internal/routes/routes.go` | path/method/route metadata + the `Route` list the mux is built from |
| Handlers | `internal/handler/` | HTTP layer: JSON decode/encode, cookie handling, thin service calls |
| Services | `service/` | business logic: Auth, Session, Password, Verification, Invite, Admin, OAuth, Org, OrgInvite, TwoFactor |
| Interfaces | `port/` | `UserRepository`, `SessionRepository`, `TokenRepository`, `InviteRepository`, `OrgRepository`, `OrgInviteRepository`, `ProviderAccountRepository`, `AuditLogRepository`, `Mailer`, `Hasher`, `TokenGenerator`, `TemplateProvider`, `TxManager`, `URLValidator`, `OAuthProvider` |
| Repositories | `internal/sqlstore/` | Postgres/SQLite/MySQL impls; `DB` wraps `*sql.DB` with `$N → ?` rebind |
| Middleware | `middleware/` | auth (`cors.go`, `auth.go`, `csrf.go`, `csrf_token.go`, `ratelimit.go`, `org.go`, `cookies.go`) |
| Support | `domain/` (types+`AuthError`), `audit/`, `ratelimit/`, `emailtemplate/`, `hasher/`, `token/`, `provider/`, `internal/{otp,keyring,crypto,schema,testutil,httperr}` | |
| CLI | `cmd/goauth/` | separate module; owns all three driver blank-imports |

Middleware chain (outer → inner), used verbatim in `auth.go`'s `HandlerGroup` wiring (`auth.go:540-624`):

```
corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(handler)))))
```

Public endpoints drop `authMW`; state-changing ones keep `csrfTokenMW(csrfMW(...))`; CORS is always outermost (preflight short-circuits before rate-limit accounting).

## Feature workflow (do this in order)

1. **Explore first.** Read the analogous existing feature end-to-end: `internal/routes/routes.go` → `auth.go` wiring → `internal/handler` → `service` → `port` → `internal/sqlstore`. Mirror its shape.
2. **Port interface first** (`port/repository.go`): name methods for what they do, keep them small — `SessionRepository`/`OrgRepository` are themselves compositions of narrower interfaces (`SessionReader`/`Writer`/`Revoker`/`ActiveOrgSessionStore`, `OrgCRUD`/`OrgLimitCounters`); a service that only needs a slice should depend on that slice's interface, not the composed one. `TxManager`/`Tx` is available if the feature needs multi-statement atomicity — prefer it over hand-rolled transactions.
3. **Service layer** (`service/<feature>.go`):
   - Take a **per-method input struct** carrying the actor ID (e.g. `BanUserInput{AdminID, ...}`), return `(Result, error)` — **not** positional args, **not** `*domain.AuthError` returns.
   - User-facing failures return the `*domain.AuthError` **sentinels** from `domain/errors.go` (`NewError(code, msg)` — no status; `domain` is transport-agnostic, usable from `Auth.Register`/`Auth.Login` directly with no HTTP concept at all). Add a new sentinel there if none fits — pick a stable code — **and** add its code→status mapping to `internal/httperr`'s table, or it silently falls back to 500. `internal/httperr.StatusFor(code)` is the one place that mapping lives, used by both `internal/handler` and `middleware`; `internal/httperr/httperr_test.go` walks the repo for every `NewError(...)` call and fails the build if one isn't mapped, so a forgotten entry is caught in CI, not production.
   - Repository/infra failures: wrap with `fmt.Errorf(...)` (internal detail), **never** conflate them with "not found" — a repo error must surface as `internal_error` 500, not a 404 (see `middleware/org.go:59-66`).
4. **Handler** (`internal/handler/`): thin. Decode JSON (camelCase tags), call the service, `writeError(w, err)` for errors, set cookies via `middleware.SetSessionCookie/SetRefreshCookie` when a session is issued.
5. **Wire it** in `auth.go`: add the route to `internal/routes/routes.go`, then the handler entry in the `HandlerGroup` with the **exact** middleware chain it needs. If it's a rate-limited public endpoint, wrap it in `rateLimitMW` — a `ratelimit/config.go` entry alone does nothing unless the wiring uses it.
6. **SQL + repository**: add/alter the migration in `internal/schema/{postgres,mysql,sqlite}.sql` (keep all three in sync; types differ per dialect — UUID / VARCHAR(36) / TEXT). Implement in `internal/sqlstore/`.
7. **Tests** (required, alongside code):
   - Unit tests next to the service file (`service/*_test.go`).
   - Handler tests in `internal/handler/`.
   - For anything with real HTTP shape: an end-to-end test in `integration/` (SQLite, real `http.ServeMux`, real cookies + CSRF header) — see `integration/org_test.go` (`TestActiveOrg_RoundTripThroughHTTP`) as the template.
   - Cover the error paths, not just the happy path.
8. **Docs** (after code is green — never before):
   - `docs/routes.mdx` — route, auth level, body shape, cookies.
   - `docs/error-handling.mdx` — every new error code with status + message.
   - `docs/configuration.mdx` / relevant guide under `docs/guides/` — config options, Go/curl/client examples with **actual** signatures.
   - README — any public API change it mentions.
9. **Full check**: `go vet ./... && go build ./... && go test ./... -count=1` in root **and** `cmd/goauth`, in WSL. Then `gofmt -l` your edited files (they must be clean; do not reformat untouched files).

## Conventions checklist

- JSON is **camelCase** everywhere (`sessionIds`, `currentSessionId`, `avatarUrl`, `expiresAt`). Snake_case in docs/API is always a bug.
- Error contract: `{"error": code, "message": ...}` envelope (see `domain.AuthError`), except the middleware-auth layer's `session_expired`/`unauthorized` responses which are also `{"error","message"}`.
- Config: never seed defaults before options run — `applyDefaults` runs after all `Option`s; zero means "unset" (this is why `RetentionDays` has no applied default and effectively defaults to `0` = keep forever).
- Sessions: raw tokens exist only at creation/refresh time; only hashes are persisted. `SessionResult{Session, SessionToken, RefreshToken}` is the bundle services return.
- 2FA: challenge + binding token + code → `TwoFactorVerifyResult{User, Session, SessionToken, RefreshToken}`.
- Orgs: `RequireOrgMember` returns `404 org_member_not_found` (never 403) so membership can't be probed; `RequireOrgRole` returns `403 org_forbidden`.
- Invites: a revoked invite redeems as `invite_already_used` (410), never `invite_revoked`.
- Module path is `github.com/nazimdjebloun/go-auth`; internal packages live under `internal/`.

## Safety rules for agents

- Read-only exploration until you know exactly what to change.
- One feature per pass; verify each step before moving on.
- If a doc claims something the code doesn't do, **fix the doc** — but only after confirming the code behavior directly.
- If a test fails after your change, fix the cause — never delete or weaken the test to pass it.
- Breaking changes and renames are fine pre-launch — but keep the API internally consistent (per-method input structs, `error` returns, camelCase JSON) and update `docs/` + README in the same pass.
- Ask before: committing, pushing, reformatting legacy files, or editing `AGENTS.md` itself.
