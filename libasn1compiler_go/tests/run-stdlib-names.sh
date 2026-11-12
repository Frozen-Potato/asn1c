#!/bin/sh
# The hard-coded stdlib top-level table in go_names.c (go_stdlib_top) must
# match `go list std` of the local toolchain (first path elements, minus
# vendor/internal, plus the reserved patterns std, cmd, all).
# Exit codes: 0 pass, 77 skipped (no go), anything else failure.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
src="$here/../go_names.c"
if ! command -v go >/dev/null 2>&1; then
    echo "run-stdlib-names: SKIP: 'go' not found" >&2
    exit 77
fi
tmp=$(mktemp -d)
trap 'rm -rf "${tmp:?}"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
sed -n 's/^ *STDLIB_ROW("\([^"]*\)")$/\1/p' "$src" | LC_ALL=C sort >"$tmp/have"
{ go list std | awk -F/ '{print $1}' | grep -vx -e vendor -e internal
  printf '%s\n' std cmd all; } | LC_ALL=C sort -u >"$tmp/want"
if [ ! -s "$tmp/have" ]; then
    echo "run-stdlib-names: no STDLIB_ROW entries parsed from $src" >&2
    exit 1
fi
# Names the toolchain has but the table lacks always fail. Names the table has
# but the toolchain lacks fail only on a toolchain at least as new as the one
# the table was taken from (go1.27): an older one (the go1.21 floor run) lacks
# packages such as cmp/iter by design.
table_minor=27
minor=$(go env GOVERSION | sed -n 's/^go1\.\([0-9][0-9]*\).*/\1/p')
comm -13 "$tmp/have" "$tmp/want" >"$tmp/missing"
comm -23 "$tmp/have" "$tmp/want" >"$tmp/extra"
rc=0
if [ -s "$tmp/missing" ]; then
    echo "run-stdlib-names: in 'go list std' but not in go_stdlib_top:" >&2
    cat "$tmp/missing" >&2; rc=1
fi
if [ -s "$tmp/extra" ] && [ "${minor:-0}" -ge "$table_minor" ]; then
    echo "run-stdlib-names: in go_stdlib_top but not in 'go list std':" >&2
    cat "$tmp/extra" >&2; rc=1
fi
if [ "$rc" != 0 ]; then
    echo "run-stdlib-names: go_stdlib_top drifted ($(go env GOVERSION)); update go_names.c and the Go version in its comment" >&2
    exit 1
fi
echo "run-stdlib-names: PASS ($(wc -l <"$tmp/have" | tr -d ' ') names, $(go env GOVERSION))"
