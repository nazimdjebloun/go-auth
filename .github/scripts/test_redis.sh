#!/usr/bin/env bash
set -euo pipefail
: "${GOAUTH_REDIS_TEST_ADDR:?set GOAUTH_REDIS_TEST_ADDR to a disposable Redis 8 server}"
go test -count=1 -race -shuffle=on -timeout=10m ./redisstore ./internal/sqlstore . -run 'Redis|Snapshot|CacheVersion'
