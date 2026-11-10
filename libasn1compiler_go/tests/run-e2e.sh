#!/bin/sh
# End-to-end test of the Go backend: generate Go from tests/e2e/ex.asn and
# tests/e2e/ioc.asn, build it with cgo (no manual CGO_CFLAGS), check an APER
# round-trip, every reachable error code, and an allocation-fault sweep.
# Runs twice: with -no-gen-OER and with OER enabled.
# Exit codes: 0 pass, 77 skipped (automake SKIP), anything else failure.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
asn1c="$repo/asn1c/asn1c"

if [ ! -x "$asn1c" ]; then
    echo "run-e2e: $asn1c not found; build the repo first (make)" >&2
    exit 1
fi
if ! command -v go >/dev/null 2>&1; then
    echo "run-e2e: SKIP: 'go' not found" >&2
    exit 77
fi
if [ "$(go env CGO_ENABLED)" != 1 ]; then
    echo "run-e2e: SKIP: CGO_ENABLED is not 1" >&2
    exit 77
fi
if [ "$(go env GOARCH)" != amd64 ]; then
    echo "run-e2e: SKIP: GOARCH is not amd64" >&2
    exit 77
fi

tmp=$(mktemp -d)
cleanup() { rm -rf "${tmp:?}"; }
trap cleanup EXIT
mkdir "$tmp/bin" && ln -s "$asn1c" "$tmp/bin/asn1c"
trap 'exit 130' INT
trap 'exit 143' TERM

run_one() {
    label=$1; shift   # remaining args: extra asn1c flags
    work="$tmp/$label"
    mkdir -p "$work/c"
    echo "== run-e2e: $label =="
    (
        cd "$here/e2e"
        env ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test \
        "$tmp/bin/asn1c" \
            -S "$repo/skeletons" -fincludes-quoted -fcompound-names \
            -findirect-choice -fno-include-deps -gen-PER "$@" \
            -pdu=auto -D "$work/c" -Fgo="$work/go" ex.asn ioc.asn
    ) >"$work/asn1c.log" 2>&1 || { cat "$work/asn1c.log" >&2; echo "run-e2e: asn1c failed" >&2; return 1; }

    cp -R "$repo/libasn1compiler_go/rt/go" "$work/asn1cgo-rt"
    sed 's|^module .*|module asn1cgo.test/asn1cgo-rt|' "$work/asn1cgo-rt/go.mod" >"$work/go.mod.new"
    mv "$work/go.mod.new" "$work/asn1cgo-rt/go.mod"

    cp "$here/e2e/main_test.go" "$here/e2e/faults_test.go" "$work/go/"
    (
        cd "$work/go"
        unset CGO_CFLAGS
        go test -count=1 ./...
        # Allocation-fault sweep (needs the injection hooks compiled in).
        # -v so the per-direction N and the "no injectable allocations" note
        # for encode are visible.
        go test -count=1 -v -tags asn1cgo_faults -run TestAllocFaultSweep .
    )
}

run_one aper-no-oer -no-gen-OER
run_one aper-oer
# Two modules importing each other must be rejected before any Go is written.
run_cycle() {
    work="$tmp/cycle"
    mkdir -p "$work/c"
    echo "== run-e2e: import cycle (expect exit 70) =="
    rc=0
    (
        cd "$here/e2e/cycle"
        "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
            -fcompound-names -findirect-choice -fno-include-deps -gen-PER \
            -pdu=auto -D "$work/c" -Fgo="$work/go" mod-a.asn mod-b.asn
    ) >"$work/asn1c.log" 2>&1 || rc=$?
    if [ "$rc" != 70 ]; then
        cat "$work/asn1c.log" >&2
        echo "run-e2e: cycle case exited $rc, want 70" >&2
        return 1
    fi
    if ! grep -q 'asn1cgo: Go package import cycle: mod_a -> mod_b -> mod_a' "$work/asn1c.log"; then
        cat "$work/asn1c.log" >&2
        echo "run-e2e: cycle message missing" >&2
        return 1
    fi
    if [ -e "$work/go" ]; then
        echo "run-e2e: cycle case wrote Go output" >&2
        return 1
    fi
}

# A one-way import between two modules still generates and builds.
run_oneway() {
    work="$tmp/oneway"
    mkdir -p "$work/c"
    echo "== run-e2e: one-way import =="
    (
        cd "$here/e2e/oneway"
        ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test \
        "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
            -fcompound-names -findirect-choice -fno-include-deps -gen-PER \
            -pdu=auto -D "$work/c" -Fgo="$work/go" mod-a.asn mod-b.asn
    ) >"$work/asn1c.log" 2>&1 || { cat "$work/asn1c.log" >&2; echo "run-e2e: asn1c failed" >&2; return 1; }
    cp -R "$repo/libasn1compiler_go/rt/go" "$work/asn1cgo-rt"
    sed 's|^module .*|module asn1cgo.test/asn1cgo-rt|' "$work/asn1cgo-rt/go.mod" >"$work/go.mod.new"
    mv "$work/go.mod.new" "$work/asn1cgo-rt/go.mod"
    (
        cd "$work/go"
        unset CGO_CFLAGS
        go build ./...
    )
}

run_cycle
run_oneway
echo "run-e2e: PASS"
