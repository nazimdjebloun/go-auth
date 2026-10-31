#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! "${1:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Usage: bash tools/check-published-release.sh vMAJOR.MINOR.PATCH" >&2
  exit 2
fi
release="$1"

# Check the published module outside this checkout, with an isolated module cache.
# The tag must already be available to the Go module proxy or VCS resolver.
check_dir="$(mktemp -d "${TMPDIR:-/tmp}/goauth-published.XXXXXXXX")"
trap 'rm -rf -- "$check_dir"' EXIT
cd "$check_dir"
export GOBIN="$check_dir/bin"
export GOMODCACHE="$check_dir/mod"
export GOWORK=off
# Keep this disposable cache removable by the EXIT trap.
export GOFLAGS="${GOFLAGS:+$GOFLAGS }-modcacherw"

go install "github.com/nazimdjebloun/go-auth/cmd/goauth@${release}"
"$GOBIN/goauth" --help >/dev/null
for dialect in postgres mysql sqlite; do
  "$GOBIN/goauth" generate --driver "$dialect" --out "goauth/$dialect"
  test -f "goauth/$dialect/auth.schema.sql"
  test -f "goauth/$dialect/reference.md"
  test -f "goauth/$dialect/migrations/catalog.json"
done
printf 'Published CLI installation and schema exports passed for %s.\n' "$release"
