#!/bin/sh
# Fetch-mode test for the Go runtime module, with no network and no real tag.
# Builds a file:// GOPROXY holding the rt module (from this source tree) as
# v0.3.2, generates tests/e2e/ex.asn in the DEFAULT mode (no
# ASN1CGO_RT_LOCAL: go.mod only `require`s the rt, no replace, go.work does
# not list it), and checks that
#   1. before `go mod tidy` a build (GOWORK=off: in workspace mode the go
#      command may fetch and record the hash itself) fails with the ordinary
#      "missing go.sum entry" error (no panic);
#   2. after `go mod tidy` the tree builds and tests in workspace mode;
#   3. a fresh tree builds and tests with GOWORK=off GOFLAGS=-mod=mod.
# Exit codes: 0 pass, 77 skipped (automake SKIP), anything else failure.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
asn1c="$repo/asn1c/asn1c"
rtsrc="$repo/libasn1compiler_go/rt/go"
modpath=github.com/Frozen-Potato/asn1c/libasn1compiler_go/rt/go
escpath=github.com/!frozen-!potato/asn1c/libasn1compiler_go/rt/go
ver=v0.3.2

if ! command -v go >/dev/null 2>&1; then
    echo "run-rt-fetch: SKIP: 'go' not found" >&2
    exit 77
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "run-rt-fetch: SKIP: 'python3' not found (builds the module zip)" >&2
    exit 77
fi
if [ "$(go env CGO_ENABLED)" != 1 ]; then
    echo "run-rt-fetch: SKIP: CGO_ENABLED is not 1" >&2
    exit 77
fi
if [ ! -x "$asn1c" ]; then
    echo "run-rt-fetch: $asn1c not found; build the repo first (make)" >&2
    exit 1
fi
want=$(sed -n 's/^#define ASN1CGO_RT_VERSION "\(.*\)"/\1/p' "$repo/libasn1compiler_go/go_entry.c")
if [ "$want" != "$ver" ]; then
    echo "run-rt-fetch: go_entry.c ASN1CGO_RT_VERSION is '$want', test expects $ver" >&2
    exit 1
fi

tmp=$(mktemp -d)
cleanup() { chmod -R u+w "$tmp" 2>/dev/null || true; rm -rf "${tmp:?}"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --- the file:// proxy -------------------------------------------------------
pd="$tmp/proxy/$escpath/@v"
mkdir -p "$pd"
printf '%s\n' "$ver" >"$pd/list"
printf '{"Version":"%s","Time":"2026-01-01T00:00:00Z"}\n' "$ver" >"$pd/$ver.info"
cp "$rtsrc/go.mod" "$pd/$ver.mod"
python3 -I - "$rtsrc" "$pd/$ver.zip" "$modpath@$ver" <<'PY'
import os, sys, zipfile
src, out, prefix = sys.argv[1:4]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(src):
        dirs.sort()
        for f in sorted(files):
            full = os.path.join(root, f)
            z.write(full, prefix + "/" + os.path.relpath(full, src).replace(os.sep, "/"))
PY

export GOPROXY="file://$tmp/proxy"
export GOSUMDB=off
export GOTOOLCHAIN=local
export GOMODCACHE="$tmp/modcache"
export GOFLAGS=-modcacherw
export GOWORK=
export CGO_CFLAGS="-O2 -g -Werror=incompatible-pointer-types"
unset ASN1CGO_RT_LOCAL ASN1CGO_RT_SRC || true

gen() {   # gen <workdir>
    mkdir -p "$1/c"
    (
        cd "$here/e2e"
        ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test \
        "$asn1c" -S "$repo/skeletons" -fincludes-quoted -fcompound-names \
            -findirect-choice -fno-include-deps -gen-PER -no-gen-OER \
            -pdu=auto -D "$1/c" -Fgo="$1/go" ex.asn
    ) >"$1/asn1c.log" 2>&1 || { cat "$1/asn1c.log" >&2; echo "run-rt-fetch: asn1c failed" >&2; return 1; }
    mkdir -p "$1/go/smoke"
    cat >"$1/go/smoke/smoke_test.go" <<GO
package smoke

import (
	"testing"

	rt "$modpath/rt"
)

func TestRuntimeLinked(t *testing.T) {
	if rt.ArenaBalance() != 0 {
		t.Fatalf("arena balance %d, want 0", rt.ArenaBalance())
	}
}
GO
}

# --- 1+2: workspace mode, go.sum recorded by `go mod tidy` --------------------
w1="$tmp/w1"
echo "== run-rt-fetch: generate (fetch mode) =="
gen "$w1"
grep -qx "require $modpath $ver" "$w1/go/go.mod" \
    || { cat "$w1/go/go.mod" >&2; echo "run-rt-fetch: go.mod lacks the rt require" >&2; exit 1; }
if grep -q '^replace' "$w1/go/go.mod"; then
    cat "$w1/go/go.mod" >&2; echo "run-rt-fetch: fetch mode go.mod has a replace" >&2; exit 1
fi
if grep -q 'asn1cgo-rt\|rt/go' "$w1/go.work"; then
    cat "$w1/go.work" >&2; echo "run-rt-fetch: go.work lists the rt in fetch mode" >&2; exit 1
fi

echo "== run-rt-fetch: build before go mod tidy (expect missing go.sum entry) =="
rc=0
( cd "$w1/go" && GOWORK=off go build ./... ) >"$w1/pre.log" 2>&1 || rc=$?
if [ "$rc" = 0 ] || ! grep -q 'missing go.sum entry' "$w1/pre.log" || grep -q 'panic' "$w1/pre.log"; then
    cat "$w1/pre.log" >&2
    echo "run-rt-fetch: pre-tidy build: exit $rc, want failure with 'missing go.sum entry'" >&2
    exit 1
fi
head -3 "$w1/pre.log" | sed 's/^/   /'

echo "== run-rt-fetch: go mod tidy, then go test (workspace mode) =="
( cd "$w1/go" && go mod tidy && go test -count=1 ./... )
grep -q "^$modpath $ver h1:" "$w1/go/go.sum" \
    || { cat "$w1/go/go.sum" >&2; echo "run-rt-fetch: go.sum lacks the rt hash" >&2; exit 1; }

# --- 3: the single-command form ----------------------------------------------
w2="$tmp/w2"
echo "== run-rt-fetch: GOWORK=off GOFLAGS=-mod=mod go test ./... =="
gen "$w2"
( cd "$w2/go" && GOWORK=off GOFLAGS="-mod=mod -modcacherw" go test -count=1 ./... )

echo "run-rt-fetch: PASS"
