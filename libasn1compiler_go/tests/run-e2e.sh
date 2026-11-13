#!/bin/sh
# End-to-end test of the Go backend: generate Go from tests/e2e/ex.asn and
# tests/e2e/ioc.asn, build it with cgo (CGO_CFLAGS with -Werror=incompatible-pointer-types), check an APER
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
    oerdef=
    case " $* " in *" -no-gen-OER "*) oerdef=-DASN_DISABLE_OER_SUPPORT ;; esac
    work="$tmp/$label"
    mkdir -p "$work/c"
    echo "== run-e2e: $label =="
    (
        cd "$here/e2e"
        env ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test ASN1CGO_RT_LOCAL="$repo/libasn1compiler_go/rt/go" \
        "$tmp/bin/asn1c" \
            -S "$repo/skeletons" -fincludes-quoted -fcompound-names \
            -findirect-choice -fno-include-deps -gen-PER "$@" \
            -pdu=auto -D "$work/c" -Fgo="$work/go" ex.asn ioc.asn default.asn nsmall.asn namedbit.asn bitstr.asn seqofinline.asn inlconstr.asn padalloc.asn extwide.asn strings.asn oids.asn extgroup.asn shadow.asn
    ) >"$work/asn1c.log" 2>&1 || { cat "$work/asn1c.log" >&2; echo "run-e2e: asn1c failed" >&2; return 1; }


    # The generated bit-position constants must be gofmt-clean byte for byte.
    if [ -n "$(gofmt -l "$work/go/namedbit/types.go")" ]; then
        echo "run-e2e: namedbit/types.go is not gofmt-clean" >&2
        return 1
    fi
    # namedbit.asn and bitstr.asn (four modules, each owning BIT STRING
    # members) share this one -Fgo run with default.asn.
    cp "$here/e2e/main_test.go" "$here/e2e/default_test.go" "$here/e2e/nsmall_test.go" "$here/e2e/faults_test.go" \
       "$here/e2e/namedbit_test.go" "$here/e2e/bitstr_test.go" \
       "$here/e2e/seqofinline_test.go" "$here/e2e/inlconstr_test.go" \
       "$here/e2e/extwide_test.go" "$here/e2e/extgroup_test.go" "$here/e2e/strings_test.go" "$here/e2e/oids_test.go" "$here/e2e/shadow_test.go" \
       "$here/e2e/randenc_test.go" "$work/go/"
    # The BMPString / UniversalString helpers are unexported: their test lives
    # in the generated strs package.
    cp "$here/e2e/strs_internal_test.go" "$work/go/strs/"
    # Likewise the OBJECT IDENTIFIER / RELATIVE-OID helpers and XER entry
    # points of the generated oids package.
    cp "$here/e2e/oids_internal_test.go" "$work/go/oids/"
    # randenc_test.go drives every PDU type: list them from the generated
    # Encode methods (package dir = module package; type = receiver).
    {
        echo "package e2e"
        echo "import ("
        echo '	"reflect"'
        for d in "$work"/go/*/; do
            n=$(basename "$d")
            [ -f "$d/glue.go" ] && grep -q '^func (p \*[A-Za-z0-9_]*) Encode()' "$d/glue.go" || continue
            echo "	p_$n \"asn1cgo.test/go/$n\""
        done
        echo ")"
        echo "func init() {"
        for d in "$work"/go/*/; do
            n=$(basename "$d")
            [ -f "$d/glue.go" ] || continue
            for ty in $(sed -n 's/^func (p \*\([A-Za-z0-9_]*\)) Encode().*/\1/p' "$d/glue.go"); do
                echo "	randPDUs = append(randPDUs, randPDU{\"$n.$ty\", reflect.TypeOf((*p_$n.$ty)(nil)).Elem()})"
            done
        done
        echo "}"
    } >"$work/go/randreg_test.go"
    # The C converter built from the same C tree: the cross-check oracle for
    # APER/UPER/XER in default_test.go.
    (
        cd "$work/c"
        # shellcheck disable=SC2046
        ${CC:-cc} -O1 -w -DASN_PDU_COLLECTION $oerdef -I. -o "$work/converter" \
            $(ls ./*.c | grep -v '/converter-example.c$') ./converter-example.c -lm
    ) >"$work/converter.log" 2>&1 || { cat "$work/converter.log" >&2; echo "run-e2e: converter build failed" >&2; return 1; }
    (
        cd "$work/go"
        export ASN1CGO_C_CONVERTER="$work/converter"
        export CGO_CFLAGS="-O2 -g -Werror=incompatible-pointer-types"
        go test -count=1 ./...
        # The SEQUENCE OF inline-element, inline SEQUENCE/CHOICE and
        # extension-addition / wide-INTEGER / `present`-alt / restricted string
        # cases under the race detector.
        go test -race -count=1 -run 'SeqofInline|InlConstr|ExtWide|ExtNil|ExtOld|ExtGroup|Strings|Oids' .
        go test -race -count=1 ./strs/ ./oids/
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
            -pdu=auto -D "$work/c" -Fgo="$work/gen" mod-a.asn mod-b.asn
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
    if [ -e "$work/gen" ]; then
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
        ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test ASN1CGO_RT_LOCAL="$repo/libasn1compiler_go/rt/go" \
        "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
            -fcompound-names -findirect-choice -fno-include-deps -gen-PER \
            -pdu=auto -D "$work/c" -Fgo="$work/go" mod-a.asn mod-b.asn
    ) >"$work/asn1c.log" 2>&1 || { cat "$work/asn1c.log" >&2; echo "run-e2e: asn1c failed" >&2; return 1; }
    (
        cd "$work/go"
        export CGO_CFLAGS="-O2 -g -Werror=incompatible-pointer-types"
        go build ./...
    )
}

# A DEFAULT form the C generator gives no default callbacks for (a
# SEQUENCE-valued DEFAULT) is rejected by the pre-flight: exit 70, the reason
# named, and neither the C tree nor the Go tree written.
run_unsupported_default() {
    work="$tmp/unsupported-default"
    mkdir -p "$work/c"
    echo "== run-e2e: unsupported DEFAULT (expect exit 70, before the C pass) =="
    rc=0
    (
        cd "$here/e2e"
        "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
            -fcompound-names -findirect-choice -fno-include-deps -gen-PER \
            -pdu=auto -D "$work/c" -Fgo="$work/gen" default-unsupported.asn
    ) >"$work/asn1c.log" 2>&1 || rc=$?
    if [ "$rc" != 70 ]; then
        cat "$work/asn1c.log" >&2
        echo "run-e2e: unsupported-DEFAULT case exited $rc, want 70" >&2
        return 1
    fi
    if ! grep -q 'asn1cgo: DEFAULT member Holder.p is out of model' "$work/asn1c.log"; then
        cat "$work/asn1c.log" >&2
        echo "run-e2e: unsupported-DEFAULT diagnostic missing" >&2
        return 1
    fi
    if [ -n "$(ls -A "$work/c")" ] || [ -e "$work/gen" ]; then
        echo "run-e2e: unsupported-DEFAULT case wrote output" >&2
        return 1
    fi
}

# A bare -Fgo basename that is a standard-library top-level element (and no
# ASN1CGO_GO_MODULE_PREFIX) would put the generated imports inside the stdlib
# tree: rejected by the pre-flight, exit 70, -D untouched, no Go tree. With a
# prefix the same directory is fine and builds; a non-colliding basename needs
# no prefix.
run_stdlib_collision() {
    echo "== run-e2e: stdlib module-path collision =="
    for b in go net; do
        work="$tmp/collide-$b"
        mkdir -p "$work/c"
        printf 'sentinel\n' >"$work/c/keep.c"
        touch -d '2001-01-01 00:00:00' "$work/c/keep.c"
        m0=$(stat -c %Y "$work/c/keep.c")
        rc=0
        (
            cd "$here/e2e"
            env -u ASN1CGO_GO_MODULE_PREFIX \
            "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
                -fcompound-names -findirect-choice -fno-include-deps -gen-PER \
                -pdu=auto -D "$work/c" -Fgo="$work/$b" ex.asn
        ) >"$work/asn1c.log" 2>&1 || rc=$?
        if [ "$rc" != 70 ]; then
            cat "$work/asn1c.log" >&2
            echo "run-e2e: collision '$b' exited $rc, want 70" >&2
            return 1
        fi
        if ! grep -q "asn1cgo: go module path '$b' collides with the Go standard library; set ASN1CGO_GO_MODULE_PREFIX or rename the -Fgo directory" "$work/asn1c.log"; then
            cat "$work/asn1c.log" >&2
            echo "run-e2e: collision '$b' message missing" >&2
            return 1
        fi
        if [ "$(ls -A "$work/c" | tr '\n' ' ')" != "keep.c " ] \
           || [ "$(cat "$work/c/keep.c")" != sentinel ] \
           || [ "$(stat -c %Y "$work/c/keep.c")" != "$m0" ]; then
            echo "run-e2e: collision '$b': -D was modified" >&2
            return 1
        fi
        if [ -e "$work/$b" ]; then
            echo "run-e2e: collision '$b': Go tree was created" >&2
            return 1
        fi
    done

    # With a prefix: -Fgo=.../go is accepted and builds.
    work="$tmp/collide-prefixed"
    mkdir -p "$work/c"
    (
        cd "$here/e2e"
        ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test ASN1CGO_RT_LOCAL="$repo/libasn1compiler_go/rt/go" \
        "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
            -fcompound-names -findirect-choice -fno-include-deps -gen-PER \
            -pdu=auto -D "$work/c" -Fgo="$work/go" ex.asn
    ) >"$work/asn1c.log" 2>&1 || { cat "$work/asn1c.log" >&2; echo "run-e2e: prefixed go dir rejected" >&2; return 1; }
    (
        cd "$work/go"
        export CGO_CFLAGS="-O2 -g -Werror=incompatible-pointer-types"
        go build ./...
    )

    # No prefix, non-colliding basename: accepted (the module is just "e2ap").
    work="$tmp/collide-ok"
    mkdir -p "$work/c"
    (
        cd "$here/e2e"
        env -u ASN1CGO_GO_MODULE_PREFIX \
        "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
            -fcompound-names -findirect-choice -fno-include-deps -gen-PER \
            -pdu=auto -D "$work/c" -Fgo="$work/e2ap" ex.asn
    ) >"$work/asn1c.log" 2>&1 || { cat "$work/asn1c.log" >&2; echo "run-e2e: -Fgo=e2ap rejected" >&2; return 1; }
    [ -f "$work/e2ap/go.mod" ] || { echo "run-e2e: -Fgo=e2ap wrote no go.mod" >&2; return 1; }
}

# The hard-coded stdlib name table must match the local toolchain.
run_stdlib_names_drift() {
    rc=0
    sh "$here/run-stdlib-names.sh" || rc=$?
    [ "$rc" = 0 ] || [ "$rc" = 77 ] || { echo "run-e2e: stdlib name table drift" >&2; return 1; }
}

# Fetch mode (default go.mod, no replace) against a file:// GOPROXY.
run_rt_fetch() {
    rc=0
    sh "$here/run-rt-fetch.sh" || rc=$?
    [ "$rc" = 0 ] || [ "$rc" = 77 ] || { echo "run-e2e: rt fetch-mode test failed" >&2; return 1; }
}

# rt C files must match skeletons/ and compile warning-free under -pthread.
run_rt_skeleton_sync() {
    rc=0
    sh "$here/run-rt-skeleton-sync.sh" || rc=$?
    [ "$rc" = 0 ] || [ "$rc" = 77 ] || { echo "run-e2e: rt/skeleton sync check failed" >&2; return 1; }
}

run_cycle
run_oneway
run_unsupported_default
run_stdlib_collision
run_stdlib_names_drift
run_rt_fetch
run_rt_skeleton_sync
echo "run-e2e: PASS"
