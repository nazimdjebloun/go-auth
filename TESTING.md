# Database testing

Run Go commands inside WSL when developing on Windows. CI runs on Linux.

## Full backend suites

The same integration tests run against SQLite, PostgreSQL, and MySQL. The
backend runner also runs service, repository, and CLI tests, including credential
rollback, controlled login races, one-time token claims, organization guards,
recovery workers, and audit delivery. Existing unit tests remain part of these
packages; selecting a backend changes the shared real-database fixtures.
CI tests PostgreSQL 18 and MySQL 8.4; SQLite uses the driver pinned in `go.mod`.

```sh
python3 .github/scripts/test_backends.py sqlite

export GOAUTH_POSTGRES_DSN='postgres://goauth:goauth@localhost:5432/goauth?sslmode=disable'
python3 .github/scripts/test_backends.py postgres

export GOAUTH_MYSQL_TEST_DSN='root:goauth-test@tcp(127.0.0.1:3306)/?parseTime=true&timeout=10s'
python3 .github/scripts/test_backends.py mysql
```

Use dedicated test servers. PostgreSQL credentials need database creation and
extension privileges; MySQL credentials need database creation and deletion
privileges. Fixtures create unique databases and remove them after each test.
They do not write test data into the database named by the DSN. SQLite fixtures
use separate files with foreign keys enabled and a bounded busy timeout.
Server fixtures use UTC when reading and grouping timestamps.

Each run uses race detection, randomized test order, and uncached execution.
Missing backend configuration, unexpected skipped tests, and required tests
that did not run all fail the runner. Results, shuffle seeds, invocation details,
and coverage are written under `.test-results/<backend>/full/`.

The schema suite applies the complete canonical SQL after simulated interruption,
then reapplies it. It checks all 11 tables, column types/nullability/default
values and explicit collations, named-index columns, sort order, collations,
access methods, operator classes and partial predicates, primary/unique keys,
foreign-key targets/deletion actions, and declared CHECK expressions. Expectations
account for intentional differences between dialects.

## Repeated security and concurrency tests

```sh
python3 .github/scripts/test_backends.py sqlite --stress --count 25
python3 .github/scripts/test_backends.py postgres --stress --count 25
python3 .github/scripts/test_backends.py mysql --stress --count 25
```

External backends use the same DSNs as full runs. Each selected test repeats
at `GOMAXPROCS=1` and `4`; count 25 therefore runs each case 50 times. The count
accepts 1–100. This suite targets concurrent mutations, transaction rollback,
credential replacement, token claims, worker leases, and authorization changes.
Database race tests use real transactions and independent pools; Go's race
detector separately checks memory access.

Every CI push/PR runs all three full backend suites. Nightly CI additionally
runs stress tests with count 25 and fuzzes each existing target for 30 seconds.
Manual CI runs can enable stress tests and change their count and fuzz budget.
Backend artifacts are retained for 14 days. An ordinary assertion failure is
never retried into success.

## Repository checks

```sh
go vet ./...
go build ./...
go test -count=1 ./...
golangci-lint run ./...
python3 -m unittest discover -s .github/scripts -p '*_test.py'
```

Plain `go test` defaults shared fixtures to SQLite. Existing standalone server
tests may skip when their DSNs are absent; use the backend runner for mandatory
live-server verification and evidence that every required suite executed.
