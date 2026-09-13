# Repository Conventions

## API and data

- JSON fields are camelCase: `sessionIds`, `currentSessionId`, `avatarUrl`,
  `expiresAt`. Snake_case in the public JSON API or its documentation is a bug.
- The error envelope is `{"error": code, "message": message}`. Authentication
  middleware uses the same two-field shape for `session_expired` and
  `unauthorized`.
- Functional options use `With*`. `NewConfig(opts...)` applies options, then
  defaults, then validation.
- Zero means unset unless a field explicitly documents zero as meaningful. Use
  pointer intent fields where the configuration must distinguish unset from an
  explicit zero or false value.
- Public service methods use specific input structs rather than growing long
  positional parameter lists.

## Domain invariants

- Raw session and refresh tokens exist only at creation or rotation time; only
  hashes are persisted.
- Session creation returns the session plus the one-time raw session and refresh
  tokens.
- 2FA login uses a challenge, binding token, and code before issuing a session.
- Organization membership checks return `org_member_not_found` rather than a
  permission error when exposing membership would permit probing.
- Organization role failures return `org_forbidden`.
- A revoked signup invite redeems as `invite_already_used`, not
  `invite_revoked`.
- The module path is `github.com/nazimdjebloun/go-auth`; implementation-only
  packages belong under `internal/`.

## Naming and structure

- Follow idiomatic Go names and preserve established terminology. Do not switch
  between user/account/person or session/token when the concepts differ.
- Keep transport logic in handlers, business rules in services, and SQL in
  repositories.
- Prefer small interfaces named for the capability they provide.
- Comments should explain intent, constraints, or non-obvious failure behavior;
  do not merely paraphrase the code.
