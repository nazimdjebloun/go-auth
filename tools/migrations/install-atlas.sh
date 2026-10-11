#!/usr/bin/env bash
# Install the repository's pinned community Atlas build on Linux/WSL amd64.
set -euo pipefail

if (( $# > 1 )); then
  printf '%s\n' 'Usage: bash tools/migrations/install-atlas.sh [unused-target-path]' >&2
  exit 1
fi
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  printf '%s\n' 'This installer supports Linux/WSL amd64. Download the pinned build for your platform from Atlas and select it with --atlas.' >&2
  exit 1
fi

atlas_repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
atlas_version="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["atlasVersion"])' "$atlas_repo/internal/migrationtool/toolchain.json")"
if [[ ! "$atlas_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf '%s\n' 'Invalid pinned Atlas version' >&2
  exit 1
fi
atlas_destination="${1:-$HOME/.local/bin/atlas}"
atlas_url="https://release.ariga.io/atlas/atlas-community-linux-amd64-$atlas_version"
atlas_stage="$(mktemp -d /tmp/goauth-atlas-install.XXXXXX)"
trap 'rm -rf -- "$atlas_stage"' EXIT

curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --max-time 120 "$atlas_url" -o "$atlas_stage/atlas"
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --max-time 30 "$atlas_url.sha256" -o "$atlas_stage/checksum"
atlas_expected="$(tr -d '\r\n' < "$atlas_stage/checksum")"
atlas_actual="$(sha256sum "$atlas_stage/atlas" | cut -d ' ' -f 1)"
if [[ ! "$atlas_expected" =~ ^[a-f0-9]{64}$ || "$atlas_expected" != "$atlas_actual" ]]; then
  printf '%s\n' 'Atlas download checksum mismatch' >&2
  exit 1
fi
if [[ -e "$atlas_destination" || -L "$atlas_destination" ]]; then
  if [[ -f "$atlas_destination" && "$(sha256sum "$atlas_destination" | cut -d ' ' -f 1)" == "$atlas_expected" ]]; then
    printf 'Pinned Atlas %s is already installed at %s\n' "$atlas_version" "$atlas_destination"
    exit 0
  fi
  printf 'Refusing to replace an existing different file: %s; choose an unused target path\n' "$atlas_destination" >&2
  exit 1
fi
mkdir -p -- "$(dirname -- "$atlas_destination")"
install -m 0755 -- "$atlas_stage/atlas" "$atlas_destination"
printf 'Installed Atlas %s at %s\n' "$atlas_version" "$atlas_destination"
