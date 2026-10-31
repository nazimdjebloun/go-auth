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

The schema suite installs the published baseline, validates explicit adoption
of the complete canonical SQL, and repeats tracked execution. The required
`TestSelectedBackendPublishedCatalogUpgradePrefixes` installs every prefix of
the real embedded catalog in a separate fresh selected-backend database,
including the bootstrap and latest revisions. A test manifest selects each
prefix while preserving the published SQL, snapshots and checksums. The actual
Go runner installs that prefix, upgrades it through public `Apply`, verifies
the current target with `Verify`, and repeats `Apply` without changing completed
journal records. Each result must have no pending or dirty state. This test runs
in all three full backend suites and is excluded from stress runs.

The migration package separately uses bootstrap-isolated synthetic histories
to cover populated multi-step upgrades from executed and adopted
baselines, skipped releases, password verification and token lookup after upgrades,
incomplete MySQL backfills, verified repair, concurrent runners, and rollback
versus durable dirty state. SQLite rebuild fixtures include host-owned foreign
keys, indexes and triggers, and reject orphaned host references before committing.
Retry fixtures verify failed prerequisites without a started record, refusal of
partial DDL and unpublished policies, retained dirty state after another failure,
and serialized PostgreSQL/MySQL retries that preserve the original journal row.
Ownership fixtures reject incomplete drops/renames and partial additions before
retry, retain retired names across later revisions, and check host-object
namespaces and intentional name reuse. SQLite recovery states are simulated;
its starting-schema checks run directly because retry requires nontransactional DDL.
SQLite name fixtures cover ASCII case variants of reserved table/index/view names
and distinct non-ASCII names, preserve triggers on host tables sharing reserved
names, and reject triggers on auth tables.
The historical provenance fixture records the exact v0.3.0 schema checksums
matching baseline 000001. It checks all 15 tables, column types/nullability/default
values and explicit collations, named-index columns, sort order, collations,
access methods, operator classes and partial predicates, primary/unique keys,
foreign-key targets/deletion actions, and declared CHECK expressions. Expectations
account for intentional differences between dialects.

The CI `migration-catalog` job separately guards published migration identities
and release labels, then replays all dialect histories through checksum-verified,
pinned Atlas in disposable databases. Atlas replay checks structural results
from an empty database; it does not run the Go runner's preconditions or data
postconditions. The every-prefix Go test exercises actual execution metadata,
runtime checks and journal transitions, starting without application data.
Each published schema or data change must also add populated upgrade fixtures
for its supported starting revisions and relevant failure/recovery paths.
The synthetic fixtures above exercise runner behavior and do not replace that
per-change data-preservation coverage.

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

Every CI branch push/PR runs all three full backend suites and stress tests with
count 3 at both CPU settings. A manual run's stress input enables a larger repeat
count (25 by default); otherwise its stress count remains 3. Pushes to `main`
fuzz each existing target for 5 seconds. Manual runs also fuzz, with a
configurable budget of 15 seconds per target by default. There is no scheduled
nightly workflow.

Tag pushes do not start CI. Release metadata is checked against the newest
changelog version on the branch commit. Tag the exact SHA whose CI passed;
after publishing the tag, run `bash tools/check-published-release.sh v0.5.1`
locally to verify installation and schema exports from the published module.

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
