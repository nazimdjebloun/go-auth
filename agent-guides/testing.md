# Testing and Verification

Run all Go commands inside WSL. Start in the repository root unless a section
says otherwise.

## Root module

```sh
go vet ./...
go build ./...
go test ./... -count=1
```

Useful focused commands:

```sh
go test ./internal/service -count=1
go test ./integration -count=1
go test -run TestName ./internal/service -count=1
```

The CLI in `cmd/goauth` shares the root module and is covered by these commands.

## Expectations

- Add tests with the implementation; do not weaken or delete a failing test to
  make a change pass.
- Cover failure, concurrency, malformed-input, and rollback paths, not only the
  happy path.
- Shared real-database fixtures default to SQLite. Use SQLite integration tests
  for real HTTP shape when no external service is required. Explicitly selecting
  PostgreSQL or MySQL with `GOAUTH_TEST_DRIVER` requires `GOAUTH_POSTGRES_DSN` or
  `GOAUTH_MYSQL_TEST_DSN`, respectively; missing configuration fails those
  fixtures. Some standalone server tests skip without their DSN. Use the
  backend runner in [TESTING.md](../TESTING.md) for required live-backend suites
  and unexpected-skip detection.
- Run `go test -race` for packages changed in concurrency-sensitive work.
- Run `gofmt` only on edited Go files, then verify the explicit list with
  `gofmt -l`.
- Report commands that were not run or environmental skips; do not imply a
  broader verification result than was actually obtained.
