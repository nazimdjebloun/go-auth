# Architecture

## Layers

| Layer | Location | Responsibility |
|---|---|---|
| Public configuration | `config.go`, `config_*.go` | `Config` coordinates section files that own their types, options, defaults, and validation; cross-section checks stay in `config_validate.go` |
| Construction and wiring | `auth.go`, `wire_*.go` | Build repositories, services, middleware, handlers, and adapters |
| Public facade | `facade_services.go`, `facade_http.go`, `facade_org.go`, `facade_app_permissions.go` | Direct-use methods, app-permission initialization, and middleware helpers on `*Auth` |
| Public operation types | `api/` | Transport-neutral inputs, results, and sort types; imports `domain` |
| Public service capabilities | `services.go` | Interfaces returned by `Auth.Services()`, backed by private concrete service references |
| Route registration | `internal/routes/`, `internal/httproutes/`, `mount.go` | Canonical patterns, wrapped route entries, public lookup, and `http.ServeMux` registration |
| HTTP handlers | `internal/handler/` | Decode/encode HTTP, cookies, and thin service calls |
| Business logic | `internal/service/` | Authentication, sessions, passwords, verification, invites, admin, OAuth, organizations, 2FA, and app permissions |
| Interfaces | `port/` | Narrow dependencies for repositories and adapters |
| SQL repositories | `internal/sqlstore/` | PostgreSQL, MySQL, and SQLite persistence behind `port` interfaces |
| Schema | `internal/schema/` | Embedded schemas for all three SQL dialects |
| Middleware | `middleware/` | Authentication, CSRF, CORS, rate limiting, cookies, organization checks, and live app-permission checks |
| Adapters and support | `audit/`, `domain/`, `emailtemplate/`, `hasher/`, `mailer/`, `provider/`, `ratelimit/`, `token/`, `internal/{crypto,keyring,otp,httperr}` | Domain types and built-in implementations |
| CLI | `cmd/goauth/` | Schema migration, generation, initial-admin seeding, and `permissions catalog/seed/update` (part of the root module) |

## Request flow

Canonical patterns live in `internal/routes`. `wire_http.go` builds handlers
and middleware; `internal/httproutes` pairs enabled patterns with their exact
wrapped handlers. `Mount` registers them on a Go 1.22+ `*http.ServeMux`. Handlers
stay transport-focused and delegate business behavior to `internal/service`.
Services use `api` inputs and results and depend on narrow `port` interfaces;
SQL details stay in `internal/sqlstore`. `port` imports `api` for shared sort and
result shapes, while `api` never imports `port` or `internal/service`.

When present, middleware is ordered outer to inner:

```text
CORS → rate limit → CSRF token → CSRF origin check → authentication → handler
```

Public routes omit authentication. Admin and organization routes add their
role/membership checks at the appropriate inner boundary. CORS remains
outermost so preflight requests short-circuit before rate-limit accounting.

With app permissions enabled, admin operations use live app-permission checks
instead of the legacy `user.Role` gate. Protected app-admin checks guard
non-delegable administration. Follow the existing route policies in
`internal/httproutes` and the checks in `middleware/app_permissions.go` when
adding an operation; a cached user role is insufficient in this mode.

## Public use

Core operations have facade methods such as `Auth.Register` and `Auth.Login`.
The programmatic service surface is exposed through `Auth.Services()`, which
returns a value of root-owned capability interfaces. Disabled optional
capabilities are nil. HTTP integration uses `Auth.Mount`; custom
routers can call `Auth.Handler(pattern)` for an enabled wrapped route and must
populate `PathValue` for parameterized routes. The handler lookup sets
`Request.Pattern` for route-aware rate limiting. Applications can also use the
public middleware and service methods for their own routes.

`Auth.InitializeAppPermissions` initializes protected app roles and the first
app-admin assignment for a trusted installation flow; it has no HTTP route.
Permission records are managed through the permissions CLI. Custom application
routes can use `Auth.RequireAppPermission` with a catalog permission key; the
permission middleware must run after `Auth.RequireAuth`. It checks the current
assignment and grant in the database and fails closed when app permissions are
disabled.

## Transactions

Use `port.TxManager` for multi-statement atomic behavior. Keep transaction
boundaries in the service layer and persistence mechanics in repositories.
Credential and token operations may require guarded compare-and-swap or atomic
claim semantics; read `security.md` before changing them.
