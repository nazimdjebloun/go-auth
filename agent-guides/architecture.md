# Architecture

## Layers

| Layer | Location | Responsibility |
|---|---|---|
| Public configuration | `config*.go`, `options.go` | `Config`, section types, defaults, validation, and functional options |
| Construction and wiring | `auth.go`, `wire.go`, `handlers.go` | Build repositories, services, middleware, handlers, and adapters |
| Public facade | `facade_services.go`, `facade_middleware.go` | Stable direct-use methods and middleware helpers on `*Auth` |
| Route registration | `internal/routes/routes.go`, `mount.go` | Canonical route metadata and `http.ServeMux` registration |
| HTTP handlers | `internal/handler/` | Decode/encode HTTP, cookies, and thin service calls |
| Business logic | `internal/service/` | Authentication, sessions, passwords, verification, invites, admin, OAuth, organizations, and 2FA |
| Interfaces | `port/` | Narrow dependencies for repositories and adapters |
| SQL repositories | `internal/sqlstore/` | PostgreSQL, MySQL, and SQLite persistence behind `port` interfaces |
| Schema | `internal/schema/` | Embedded schemas for all three SQL dialects |
| Middleware | `middleware/` | Authentication, CSRF, CORS, rate limiting, cookies, and organization checks |
| Adapters and support | `audit/`, `domain/`, `emailtemplate/`, `hasher/`, `mailer/`, `provider/`, `ratelimit/`, `token/`, `internal/{crypto,keyring,otp,httperr}` | Domain types and built-in implementations |
| CLI | `cmd/goauth/` | Schema migration, generation, and initial-admin seeding (part of the root module) |

## Request flow

Routes are declared in `internal/routes`, wired to already-wrapped handlers in
`auth.go`, and registered on a Go 1.22+ `*http.ServeMux` by `Mount`. Handlers
stay transport-focused and delegate business behavior to `internal/service`.
Services depend on narrow `port` interfaces; SQL details stay in
`internal/sqlstore`.

The middleware order is outer to inner:

```text
CORS → rate limit → CSRF token → CSRF origin check → authentication → handler
```

Public routes omit authentication. Admin and organization routes add their
role/membership checks at the appropriate inner boundary. CORS remains
outermost so preflight requests short-circuit before rate-limit accounting.

## Public use

Core operations have facade methods such as `Auth.Register` and `Auth.Login`.
The full service surface is exposed through `Auth.Services`. HTTP integration
uses `Auth.Mount`; custom routers can use the public middleware/service surface
instead of duplicating internal handlers.

## Transactions

Use `port.TxManager` for multi-statement atomic behavior. Keep transaction
boundaries in the service layer and persistence mechanics in repositories.
Credential and token operations may require guarded compare-and-swap or atomic
claim semantics; read `security.md` before changing them.
