# Redis example

Run Go commands through WSL on Windows. Start a local Redis 8 server, then:

```sh
export GOAUTH_SECRET="$(openssl rand -hex 32)"
export DATABASE_URL='file:redis-example.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)'
export REDIS_ADDR='127.0.0.1:6379'
go run ./cmd/goauth migrate --driver sqlite --dsn "$DATABASE_URL"
go run ./examples/redis
```

Keep the secret for later restarts. The API listens on 127.0.0.1:8083 and mounts
auth routes plus `GET /app/me`. Use the normal CSRF bootstrap, cookie and Origin
contract described in the [onboarding guide](../../docs/guides/onboarding.mdx).
This local demo opens password signup and disables admin-specific email MFA
because it has no mail delivery. Use the default MFA policy and a real mailer
for a deployed application.

The complete Redis integration enables encrypted version-validated session/token
snapshots and shared route/2FA notification counters. SQL remains authoritative.
The caller owns the Redis connection; shutdown drains HTTP, closes Auth, then
closes Redis. See the [Redis guide](../../docs/guides/redis.mdx) for production
TLS/ACL, namespace, failure and rollout requirements.
