# go-auth — Agent Guide

This file is the entry point for coding agents working in this repository. The
detailed instructions live in [`agent-guides/`](./agent-guides/); the applicable
files are mandatory reading, not optional background material.

## Critical rules

- **Never commit or push without explicit user approval.** Approval to edit is
  not approval to commit, amend, tag, or push.
- **Breaking changes are welcome before v1**, but update the README and public
  documentation in the same change.
- **Never document behavior from memory.** Verify every claim against the
  current code and tests first.
- **Never run `gofmt` on files you did not edit.** Several legacy files are
  intentionally not fully formatted.
- Preserve unrelated user changes in a dirty worktree. Do not reset, discard,
  or rewrite them.
- Ask before editing this file or any file under `agent-guides/` unless the user
  explicitly requested an agent-instruction change.

Before any Go coding, review, debugging, troubleshooting, or setup task, load
the `samber/cc-skills-golang@golang-how-to` skill first — it routes to whichever
other Go skills the task needs.

## Required reading

Read each applicable file completely before making changes.

| Task | Required files |
|---|---|
| Any repository work | [`environment.md`](./agent-guides/environment.md), [`conventions.md`](./agent-guides/conventions.md) |
| Go implementation or refactoring | [`architecture.md`](./agent-guides/architecture.md), [`implementation-workflow.md`](./agent-guides/implementation-workflow.md), [`testing.md`](./agent-guides/testing.md) |
| Passwords, tokens, sessions, OAuth, CSRF, or other security-sensitive work | [`security.md`](./agent-guides/security.md) |
| Public API, behavior, README, or documentation changes | [`documentation.md`](./agent-guides/documentation.md) |
| Database schema, repositories, or transactions | [`architecture.md`](./agent-guides/architecture.md), [`implementation-workflow.md`](./agent-guides/implementation-workflow.md), [`testing.md`](./agent-guides/testing.md), [`security.md`](./agent-guides/security.md) when credentials or tokens are involved |

## Repository at a glance

go-auth is an importable authentication library with an optional HTTP surface
and a schema/bootstrap CLI. The library and `cmd/goauth` share the root Go
module; `go build ./...` and `go test ./...` verify both together.

The usual request path is:

```text
internal/routes (patterns) → internal/httproutes ← wire_http.go (middleware)
Auth.Mount/Handler → internal/httproutes → internal/handler
                   → internal/service → port interfaces → internal/sqlstore
```

Start with the analogous existing feature and follow that path end to end. Do
not invent a parallel architecture when an established extension point already
exists.
