#!/bin/sh
# Adding -Fgo=<dir> must not change the C that asn1c writes. For each spec,
# run asn1c twice into fresh -D dirs (second run adds -Fgo) and compare the
# two trees file by file. Only the stamped command line is normalised: the
# "-Fgo=<anything>" word is dropped from the " * \t`asn1c ..." header lines of
# generated .c/.h files and from Makefile.am.asn1convert / converter-example.mk.
# Exit codes: 0 pass, 77 skipped (automake SKIP), anything else failure.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
asn1c="$repo/asn1c/asn1c"

if [ ! -x "$asn1c" ]; then
    echo "run-c-invariance: SKIP: $asn1c not found" >&2
    exit 77
fi

tmp=$(mktemp -d)
cleanup() { rm -rf "${tmp:?}"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# normalise <file>: print the file with "-Fgo=<anything>" dropped from the
# stamped asn1c command lines (and from nothing else).
normalise() {
    case $1 in
    */Makefile.am.asn1convert|*/converter-example.mk)
        sed -e '/asn1c /s/ -Fgo=[^ `]*//' "$1" ;;
    *.c|*.h)
        sed -e "/^ \\* "'	`asn1c /s/ -Fgo=[^ `]*//' "$1" ;;
    *)
        cat "$1" ;;
    esac
}

# check <label> <expected-go-exit> <spec-path>...
check() {
    label=$1; want_rc=$2; shift 2
    work="$tmp/$label"
    mkdir -p "$work"
    echo "== run-c-invariance: $label =="
    flags="-S $repo/skeletons -fincludes-quoted -fcompound-names -findirect-choice -fno-include-deps -gen-PER -no-gen-OER -pdu=auto"
    # Both runs use the same -D path (the path is stamped into the generated
    # Makefiles), one after the other; the first tree is moved aside.
    mkdir "$work/c"
    rc=0
    # shellcheck disable=SC2086
    "$asn1c" $flags -D "$work/c" "$@" >"$work/plain.log" 2>&1 || rc=$?
    if [ "$rc" != 0 ]; then
        cat "$work/plain.log" >&2
        echo "run-c-invariance: $label: plain run exited $rc" >&2
        return 1
    fi
    mv "$work/c" "$work/plain"
    mkdir "$work/c"
    rc=0
    # shellcheck disable=SC2086
    "$asn1c" $flags -D "$work/c" -Fgo="$work/gen" "$@" >"$work/withgo.log" 2>&1 || rc=$?
    if [ "$rc" != "$want_rc" ]; then
        cat "$work/withgo.log" >&2
        echo "run-c-invariance: $label: -Fgo run exited $rc, want $want_rc" >&2
        return 1
    fi

    mv "$work/c" "$work/withgo"
    fail=0
    list_a="$work/list.a"; list_b="$work/list.b"
    (cd "$work/plain" && find . -type f | LC_ALL=C sort) >"$list_a"
    (cd "$work/withgo" && find . -type f | LC_ALL=C sort) >"$list_b"
    if ! diff "$list_a" "$list_b" >&2; then
        echo "run-c-invariance: $label: file lists differ" >&2
        fail=1
    fi
    while IFS= read -r f; do
        [ -f "$work/withgo/$f" ] || continue
        normalise "$work/plain/$f" >"$work/n.a"
        normalise "$work/withgo/$f" >"$work/n.b"
        if ! cmp -s "$work/n.a" "$work/n.b"; then
            echo "run-c-invariance: $label: $f differs:" >&2
            diff -u "$work/n.a" "$work/n.b" >&2 || true
            fail=1
        fi
    done <"$list_a"
    if [ "$fail" != 0 ]; then
        return 1
    fi
    echo "   $(wc -l <"$list_a" | tr -d ' ') files identical"
}

e2e="$here/e2e"
check ex 0 "$e2e/ex.asn"
check ioc 0 "$e2e/ioc.asn"
check default 0 "$e2e/default.asn"
check nsmall 0 "$e2e/nsmall.asn"

# A spec the Go pass rejects (default-unsupported.asn: a SEQUENCE-valued
# DEFAULT, which the C generator gives no default callbacks for) must be
# refused by the pre-flight BEFORE the C pass: exit non-zero and -D untouched.
reject_untouched() {
    work="$tmp/reject"
    mkdir -p "$work/c"
    echo "== run-c-invariance: reject-leaves-D-untouched =="
    printf 'sentinel\n' >"$work/c/keep.c"
    touch -d '2001-01-01 00:00:00' "$work/c/keep.c"
    m0=$(stat -c %Y "$work/c/keep.c")
    rc=0
    "$asn1c" -S "$repo/skeletons" -fincludes-quoted -fcompound-names \
        -findirect-choice -fno-include-deps -gen-PER -no-gen-OER -pdu=auto \
        -D "$work/c" -Fgo="$work/gen" "$e2e/default-unsupported.asn" \
        >"$work/log" 2>&1 || rc=$?
    if [ "$rc" = 0 ]; then
        echo "run-c-invariance: reject: expected non-zero exit" >&2; return 1
    fi
    if [ "$(ls -A "$work/c" | tr '\n' ' ')" != "keep.c " ] \
       || [ "$(cat "$work/c/keep.c")" != sentinel ] \
       || [ "$(stat -c %Y "$work/c/keep.c")" != "$m0" ]; then
        cat "$work/log" >&2
        echo "run-c-invariance: reject: -D was modified" >&2; return 1
    fi
    if [ -e "$work/gen" ]; then
        echo "run-c-invariance: reject: Go tree was created" >&2; return 1
    fi
    grep -q "DEFAULT member" "$work/log" || {
        cat "$work/log" >&2
        echo "run-c-invariance: reject: no DEFAULT diagnostic" >&2; return 1; }
    echo "   exit $rc, -D untouched"
}
reject_untouched

# A -Fgo basename equal to a standard-library top-level element, with no
# ASN1CGO_GO_MODULE_PREFIX, is refused by the same pre-flight: exit 70, -D
# untouched, no Go tree.
reject_stdlib_name() {
    work="$tmp/reject-stdlib"
    mkdir -p "$work/c"
    echo "== run-c-invariance: reject-stdlib-module-name =="
    printf 'sentinel\n' >"$work/c/keep.c"
    touch -d '2001-01-01 00:00:00' "$work/c/keep.c"
    m0=$(stat -c %Y "$work/c/keep.c")
    rc=0
    env -u ASN1CGO_GO_MODULE_PREFIX "$asn1c" -S "$repo/skeletons" \
        -fincludes-quoted -fcompound-names -findirect-choice \
        -fno-include-deps -gen-PER -no-gen-OER -pdu=auto \
        -D "$work/c" -Fgo="$work/go" "$e2e/ex.asn" >"$work/log" 2>&1 || rc=$?
    if [ "$rc" != 70 ]; then
        cat "$work/log" >&2
        echo "run-c-invariance: reject-stdlib: exit $rc, want 70" >&2; return 1
    fi
    grep -q "collides with the Go standard library" "$work/log" || {
        cat "$work/log" >&2
        echo "run-c-invariance: reject-stdlib: no diagnostic" >&2; return 1; }
    if [ "$(ls -A "$work/c" | tr '\n' ' ')" != "keep.c " ] \
       || [ "$(cat "$work/c/keep.c")" != sentinel ] \
       || [ "$(stat -c %Y "$work/c/keep.c")" != "$m0" ]; then
        echo "run-c-invariance: reject-stdlib: -D was modified" >&2; return 1
    fi
    if [ -e "$work/go" ]; then
        echo "run-c-invariance: reject-stdlib: Go tree was created" >&2; return 1
    fi
    echo "   exit $rc, -D untouched"
}
reject_stdlib_name
echo "run-c-invariance: PASS"
