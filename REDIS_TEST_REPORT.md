# Redis implementation and verification

Date: 2026-11-06. Branch: `feat/redis-support`. No push or release was performed.

## Delivered behavior

- Optional `WithRedis(RedisConfig{Client: client, ...})` enables encrypted session
  and workflow-token snapshots, shared route/IP rate limits, and shared 2FA
  suspicious-activity counters. Each capability can be disabled independently.
- Caller-owned standalone, Sentinel failover and Cluster clients are supported.
  Commands have bounded deadlines, namespaces are isolated, and startup probes
  exercise the required commands. `Auth.RedisStats()` exposes aggregate activity.
- SQL remains authoritative. Cached reads resolve the current SQL ID/version;
  transactions and locking reads bypass Redis. Current user and permission state
  remains live in SQL. Redis snapshot failures fall back to SQL; rate-limit
  failures fail closed; notification-counter failures are best-effort.
- Revision 5 adds `cache_version VARCHAR(36) NOT NULL DEFAULT 'legacy'` as the
  last column before table constraints in `sessions` and `verification_tokens`
  for PostgreSQL, MySQL and SQLite. `legacy` is a migration backfill marker:
  existing records bypass caching until a normal mutation assigns a fresh UUID.
  It is not a credential or a schema version. Existing sessions are preserved.
- Every library insert/update assigns a fresh cache identity atomically. Deletes,
  credential revocation, token consumption, refresh rotation and organization
  deletion cannot make obsolete snapshots current. All SQL writers must run
  version-aware code before caches are enabled.
- Public setup/configuration/security/deployment documentation, migration
  metadata, an executable Redis example and required Redis CI jobs are included.

Implementation commits: `33235cd` and `71e88d2`; final hardening and this report
are recorded in the subsequent commit.

## Environment and commands

All Go commands used the Linux toolchain in WSL (`go1.26.10`, linux/amd64).
Docker Desktop supplied PostgreSQL 18, MySQL 8.4 and Redis 8. Redis was pinned to
`redis:8@sha256:f245f4c83b84a9e9a0588da1c9456e579455310f0945d5db52cd2ba27f2000cc`.
The QA application used its PostgreSQL database and the local library checkout.
Credentials and generated proofs are excluded from this report.

| Check | Result | Local artifact |
| --- | --- | --- |
| `go test ./... -count=1 -timeout=15m` with live Redis | PASS | `.test-results/redis/root-tests-last.log` |
| `go build ./...`, `go vet ./...` | PASS | `.test-results/redis/build-last.log`, `vet-last.log` |
| `golangci-lint run ./...` | PASS, 0 issues | `.test-results/redis/lint-last.log` |
| `gopls check` on authored Go files | PASS, no diagnostics | `.test-results/redis/gopls-final.log`, `gopls-last.log` |
| `govulncheck ./...` | PASS, no vulnerabilities found | `.test-results/redis/vulnerabilities.log` |
| Python CI-runner unit tests; CI YAML parse | PASS, 10 tests; valid YAML | `.test-results/redis/python-tests-last.log` |
| Full SQLite backend runner | PASS, 25,549 distinct passing cases | `.test-results/redis/sqlite-runner.log` |
| Full PostgreSQL backend runner | PASS, 25,573 distinct passing cases | `.test-results/redis/postgres-final-runner.log` |
| Full MySQL backend runner | PASS, 25,563 distinct passing cases | `.test-results/redis/mysql-runner.log` |
| Standalone Redis race runner | PASS | `.test-results/redis/redis-race-last.log` |
| Real Cluster, Sentinel promotion and noeviction/OOM | PASS | `.test-results/redis/topologies-final.log` |
| Published migration catalog and Atlas replay, all dialects | PASS | `.test-results/redis/migration-replay.log` |

Full backend commands were `python3 .github/scripts/test_backends.py DRIVER`
with their real-server DSNs configured. They run race detection, shuffled order,
uncached execution, atomic coverage and unexpected-skip detection across the
root, integration, service, repository, migration and CLI packages. PostgreSQL
also selected the live Redis fixtures. SQLite/MySQL explicitly exclude only
unselected external Redis/server fixtures; Redis schema-upgrade tests remain
required. Passing-case totals include subtests and are not unique feature counts.
All three full backend runners exited successfully with no unexpected skips.
Formatting checks on all authored Go files and `git diff --check` also passed.

Focused repository stress passed on all three SQL backends:

```sh
go test -race ./internal/sqlstore \
  -run 'TestSnapshot|TestCacheVersion|TestBackendTokenClaimConcurrentAcrossPools' \
  -count=3 -cpu=1,4 -timeout=10m
```

Artifacts: `.test-results/redis/{sqlite,postgres,mysql}-cache-stress.log`.
The later revoked-organization-scope case also passed separately on MySQL
(`mysql-fk-scope.log`) and in the final SQLite/Redis run. This was the focused
Redis stress selection, not the separate repository-wide stress runner.

Standalone integration command: `GOAUTH_REDIS_TEST_ADDR=... bash
.github/scripts/test_redis.sh`. Topology commands: `CGO_ENABLED=0 go test -c
./redisstore -o .test-results/redis/redisstore.test`, then
`python .github/scripts/test_redis_topologies.py`. The latter creates and removes
only its uniquely named containers/network.

The migration check used `go run ./tools/migrations check --base-ref c23b226
--published --release v0.6.0 --replay --atlas /home/nazim/.local/bin/atlas
--diagnostics`. Migration catalogs/snapshots were sealed through the existing
tooling; historical migration files were preserved. Populated upgrade fixtures
verify existing rows and the `legacy` defaults on all three backends.

## Security and failure coverage

- Revocation/recreation, refresh rotation and replay, live user changes, token
  resend/attempt/claim updates, failed claims preserving versions, and concurrent
  single-winner claims across independent SQL pools.
- Late cache fills after mutation, SQL transaction bypass/rollback, legacy rows,
  organization FK-related changes including revoked sessions, and maintenance.
- Ciphertext corruption, envelope identity substitution, oversized snapshots and
  warm-cache SQL outage. No raw session/refresh tokens or entered codes are cached.
- Shared fixed-window budgets, expiry, millisecond rounding, invalid/no-TTL
  counters, cancellation, stalled sockets, denied ACLs, lost successful replies,
  script-cache misses and actual Redis memory exhaustion. No application retry
  repeats an ambiguous increment. Infrastructure errors preserve their causes
  without exposing them in ordinary adapter error messages.
- Shared 2FA notification counters across instances; wrong proofs never issue
  sessions. Client ownership, disabled capabilities and configuration conflicts.
- Actual Cluster slot routing and Sentinel primary promotion. Asynchronous Redis
  failover can still lose recent counters; this is documented rather than
  represented as a durable global quota guarantee.

## QA application acceptance

Application: `D:\files\desktop\nextjs-org-permissions-qa`. This directory has
no Git repository, so its integration edits could not be committed there.
Added optional `QA_REDIS_ADDR`, optional `QA_API_ADDR` for a second node,
protected Redis statistics/limit probes, a two-node script and setup notes.
The default application still starts without Redis configured.

All suites below ran with Redis enabled:

| Suite | Passing checks |
| --- | ---: |
| `python scripts/qa_api.py` | 184 / 184 |
| `python scripts/qa_edges.py` | 42 / 42 |
| `python scripts/qa_email_change.py` | 89 / 89 |
| `python scripts/qa_email_change_mfa.py` | 19 / 19 |
| `python scripts/qa_email_change_data.py` | 24 / 24 |
| `node qa-browser.mjs` (desktop/mobile) | 19 / 19 |
| `node qa-email-change.mjs` (desktop/mobile) | 21 / 21 |
| `python scripts/qa_redis.py` (two API nodes) | 10 / 10 |
| **Total** | **408 / 408** |

The two-node test verified a real cache hit on the other node, one combined
two-request budget, refresh on node two accepted on node one, and stolen-cookie
replay rejected on node one after logout on node two. Frontend typecheck, lint
and production build passed. The API's `go vet ./...` and ordinary
`go test ./... -count=1` passed. Legacy integration-tag application tests were
not part of this run. Artifacts are in the application's `qa-results/redis/`.

Mail delivery used the existing local QA mailbox; external SMTP was not tested.
The general browser run recorded five expected failed network responses
(four 401 responses and one denied 403), with all behavioral checks passing.
The email browser suite's JavaScript-error check also passed.

## Benchmark and interpretation

PASS: ten samples per mode, run after all heavy backend tests finished:

```sh
GOMAXPROCS=2 GOAUTH_REDIS_TEST_ADDR=127.0.0.1:6387 \
  go test . -run '^$' -bench '^BenchmarkRedisValidation$' \
  -benchmem -benchtime=500ms -count=10
```

Raw results: `.test-results/redis/benchmark-final.log` (linux/amd64, Ryzen 7 7700).
The fixture compares warm validation against fast local SQLite with and without
a real Redis connection. The Redis path was slower in this fixture: it adds a
network operation and snapshot decoding while still querying SQL for current
identity. This is a diagnostic of local overhead, not a production speedup or
throughput claim. Measure the actual database/network workload before choosing
session/token caching for performance; shared counters have a separate purpose.

## Resolved verification issues and limits

An initial Cluster test started before the cluster became ready; the topology
runner now waits explicitly and the complete rerun passed. An initial PostgreSQL
runner flagged unselected optional Redis fixtures as unexpected skips; selection
was narrowed and the full PostgreSQL run was repeated successfully with Redis.
The QA demo setup initially reached the existing admin-route quota; it passed
after the real rate-limit window elapsed. Assertions were not disabled or retried
silently into success.

This verifies local functionality and failure handling, not production throughput
or external SMTP/TLS deployment. Deployment requires real ACL/TLS settings,
counter capacity/noeviction policy and coordinated version-aware SQL writers;
see `docs/guides/redis.mdx`. No push, tag or published release was performed.
Disposable PostgreSQL/MySQL verification containers and the optional second API
were stopped after verification. The primary QA API, web app, QA database and
Redis remain available for local use.
