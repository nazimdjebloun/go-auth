# go-auth

A self-hosted authentication and session library for Go. Configure it in your own process, point it at your own database, and get registration, login, sessions, password recovery, email verification, invite-only signup, OAuth, multi-tenant organizations, an admin surface, CSRF protection, rate limiting, and audit logging — as a package you import, not a service you depend on.

> **Pre-1.0** — the public API (types, `With*` options, route paths, JSON response shapes) can change without a deprecation period until a 1.0 release is tagged.

## Features

- **Authentication** — email/password and OAuth registration and login, invite-only signup, optional required email verification, admin login separate from regular login
- **Sessions** — dual-token (session + refresh) with rotation, idle timeout, absolute max lifetime, and a grace window for racing refresh requests
- **Account lifecycle** — forgot/reset password, change password, set password for OAuth-only accounts, change name, self-service and admin-initiated account deletion
- **Organizations** — multi-tenant orgs with owner/admin/member roles, invites, and a per-session active org
- **Admin** — list/ban/unban/role-change/delete users, per-user session management, platform invites, all behind a role check
- **Security** — CSRF origin checking with an optional double-submit cookie, per-route rate limiting on by default, configurable password policy
- **Audit logging** — async, non-blocking event pipeline with a built-in database sink; plug in Kafka, NATS, a webhook, or your own
- **Extensible by interface** — swap the mailer, OAuth providers, email templates, rate-limit store, or audit sink without forking
- **Storage** — PostgreSQL, MySQL, or SQLite, schema embedded in the library

## Quick Start

```bash
go get github.com/nazimdjebloun/go-auth
```

```go
package main

import (
    "log"
    "net/http"
    "os"

    "github.com/nazimdjebloun/go-auth"

    // Blank-import the driver you use — go-auth's own go.mod only pulls in pgx.
    _ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
    cfg, err := goauth.NewConfig(
        goauth.WithApp(goauth.AppConfig{
            Name:    "MyApp",
            BaseURL: "https://myapp.com",
            Database: goauth.DatabaseConfig{
                URL:    os.Getenv("DATABASE_URL"),
                Driver: goauth.DriverPostgres,
            },
            Environment: goauth.EnvironmentProd,
        }),

        // 32+ bytes. Every other key the library needs is derived from this one.
        goauth.WithSecret(os.Getenv("AUTH_SECRET")),

        goauth.WithSecurity(goauth.SecurityConfig{
            AllowedOrigins: []string{"https://myapp.com"},
        }),
    )
    if err != nil {
        log.Fatal(err)
    }

    auth, err := goauth.New(cfg)
    if err != nil {
        log.Fatal(err)
    }

    mux := http.NewServeMux()
    auth.Mount(mux)
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

Apply the schema for your database before starting the app for the first time:

```bash
psql "$DATABASE_URL" -f schema/postgres.sql   # or schema/sqlite.sql / schema/mysql.sql
```

Every operation is also reachable without HTTP — `auth.Services.Auth.Register(ctx, ...)`, `auth.Services.Admin.BanUser(ctx, ...)`, and so on — since the service layer never imports `net/http`.

## Documentation

Full documentation, including every route, config option, and error code, is in [`docs/`](./docs/) in this repo, and rendered as a browsable site at [go-auth-docs](https://github.com/nazimdjebloun/go-auth-docs).

- [Installation](docs/installation.mdx) — prerequisites and setup
- [Configuration](docs/configuration.mdx) — every `With*` option, field by field
- [Schemas](docs/schemas.mdx) — the database tables and driver differences
- [Routes](docs/routes.mdx) — every HTTP route, params, and request bodies
- [Guides](docs/guides/) — Authentication, Sessions, Organizations, Security, Admin, Audit Logs, OAuth linking, Rate Limiting — each with curl, Go, and browser-client examples
- [Architecture](docs/architecture.mdx) — package layout and the middleware chain
- [Error Handling](docs/error-handling.mdx) — every error code, grouped by area

## License

MIT
