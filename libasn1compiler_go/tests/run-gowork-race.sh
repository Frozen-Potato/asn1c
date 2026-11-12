#!/bin/sh
# Concurrent generators into sibling -Fgo dirs under one parent must all end
# up in the shared go.work `use` block (the go.work read-modify-write is
# serialised by flock on <parent>/.go.work.lock). N generators in parallel,
# repeated ROUNDS times, each round in a fresh parent.
# Env: N (default 8), ROUNDS (default 20), ASN1C (default repo asn1c).
# Exit codes: 0 pass, 77 skipped (automake SKIP), anything else failure.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
asn1c=${ASN1C:-$repo/asn1c/asn1c}
N=${N:-8}
ROUNDS=${ROUNDS:-20}

if [ ! -x "$asn1c" ]; then
    echo "run-gowork-race: SKIP: $asn1c not found" >&2
    exit 77
fi
if [ ! -d "$repo/skeletons" ]; then
    echo "run-gowork-race: SKIP: skeletons dir not found" >&2
    exit 77
fi

tmp=$(mktemp -d)
cleanup() { rm -rf "${tmp:?}"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cat >"$tmp/t.asn" <<'ASN'
T DEFINITIONS AUTOMATIC TAGS ::= BEGIN
  Msg ::= SEQUENCE { a INTEGER (0..255), b OCTET STRING (SIZE(1..8)) }
END
ASN

fail=0
r=1
while [ "$r" -le "$ROUNDS" ]; do
    parent="$tmp/r$r"
    mkdir -p "$parent"
    i=1
    pids=""
    while [ "$i" -le "$N" ]; do
        (
            mkdir -p "$parent/c$i"
            ASN1CGO_RT_LOCAL="$repo/libasn1compiler_go/rt/go" \
            "$asn1c" -S "$repo/skeletons" -fincludes-quoted -fcompound-names \
                -fno-include-deps -gen-PER -pdu=auto -D "$parent/c$i" \
                -Fgo="$parent/g$i" "$tmp/t.asn"
        ) >"$parent/log$i" 2>&1 &
        pids="$pids $!"
        i=$((i + 1))
    done
    for p in $pids; do
        wait "$p" || { echo "run-gowork-race: round $r: generator failed" >&2; fail=1; }
    done
    i=1
    while [ "$i" -le "$N" ]; do
        if ! grep -qx "[[:space:]]*\./g$i" "$parent/go.work" 2>/dev/null; then
            echo "run-gowork-race: round $r: ./g$i missing from go.work" >&2
            fail=1
        fi
        i=$((i + 1))
    done
    if [ "$fail" -ne 0 ]; then
        echo "--- go.work (round $r) ---" >&2
        cat "$parent/go.work" >&2 || true
        for l in "$parent"/log*; do [ -s "$l" ] && { echo "--- $l"; cat "$l"; } >&2; done
        echo "run-gowork-race: FAIL" >&2
        exit 1
    fi
    r=$((r + 1))
done
echo "run-gowork-race: PASS ($ROUNDS rounds x $N generators)"
