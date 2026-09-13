# Development Environment

## WSL is required for Go commands

The repository builds and tests with the Linux toolchain in WSL. Run every
`go`, `gofmt`, `go vet`, and related Go command through WSL.

WSL does not have `rg`. Use `grep` or `grep -rn` inside WSL. Read-only searches
from PowerShell may use `rg`.

## Two Go modules

- The repository root is the library module.
- `cmd/goauth` is a separate module with its own `go.mod`.

Build and test both modules. A successful root-module check does not verify the
CLI module.

## Worktree safety

- Inspect `git status --short` before editing.
- Existing changes belong to the user unless proven otherwise.
- Keep unrelated changes intact and out of the task's patch.
- Do not use destructive Git commands to clean the worktree.
- Do not commit, amend, tag, or push without explicit approval for that action.

## Formatting

Run `gofmt` only on Go files changed by the current task. Never bulk-format the
repository. Use `gofmt -l` on the explicit edited-file list as the final check.
