# Development Environment

## WSL is required for Go commands

The repository builds and tests with the Linux toolchain in WSL. Run every
`go`, `gofmt`, `go vet`, and related Go command through WSL.

WSL does not have `rg`. Use `grep` or `grep -rn` inside WSL. Read-only searches
from PowerShell may use `rg`.

## One Go module

- The repository root is a single module containing the library and the
  `cmd/goauth` CLI.

`go build ./...` and `go test ./...` build and test both together; a successful
root-module run covers the CLI too.

## Worktree safety

- Inspect `git status --short` before editing.
- Existing changes belong to the user unless proven otherwise.
- Keep unrelated changes intact and out of the task's patch.
- Do not use destructive Git commands to clean the worktree.
- Do not commit, amend, tag, or push without explicit approval for that action.

## Formatting

Run `gofmt` only on Go files changed by the current task. Never bulk-format the
repository. Use `gofmt -l` on the explicit edited-file list as the final check.
