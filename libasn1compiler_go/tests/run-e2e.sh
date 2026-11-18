#!/bin/sh
# End-to-end test of the Go backend: generate Go from tests/e2e/ex.asn and
# tests/e2e/ioc.asn, build it with cgo (CGO_CFLAGS with -Werror=incompatible-pointer-types), check an APER
# round-trip, every reachable error code, and an allocation-fault sweep.
# Runs three times: with -no-gen-OER, with OER enabled, and with -no-gen-OER
# -gen-JER (which adds EncodeJER / DecodeJER<T> and their tests).
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

# AddressSanitizer pass of the Go tests (go test -asan). ASN1CGO_E2E_ASAN
# unset: run it when the C compiler cgo uses can link -fsanitize=address,
# else skip it with a note; =1: required, fail when it cannot link; =0: skip.
asan=0
if [ "${ASN1CGO_E2E_ASAN:-}" = 0 ]; then
    echo "run-e2e: go test -asan pass off (ASN1CGO_E2E_ASAN=0)"
else
    printf 'int main(void) { return 0; }\n' >"$tmp/asanprobe.c"
    if $(go env CC) -fsanitize=address -o "$tmp/asanprobe" "$tmp/asanprobe.c" >/dev/null 2>&1; then
        asan=1
        echo "run-e2e: go test -asan pass on ($(go env CC))"
    elif [ "${ASN1CGO_E2E_ASAN:-}" = 1 ]; then
        echo "run-e2e: ASN1CGO_E2E_ASAN=1 but $(go env CC) cannot link -fsanitize=address" >&2
        exit 1
    else
        echo "run-e2e: $(go env CC) cannot link -fsanitize=address; skipping the go test -asan runs"
    fi
fi

run_one() {
    label=$1; shift   # remaining args: extra asn1c flags
    oerdef=
    case " $* " in *" -no-gen-OER "*) oerdef=-DASN_DISABLE_OER_SUPPORT ;; esac
    jer=0
    jerdef=
    case " $* " in *" -gen-JER "*) jer=1; jerdef=-DASN_ENABLE_JER_SUPPORT ;; esac
    work="$tmp/$label"
    mkdir -p "$work/c"
    echo "== run-e2e: $label =="
    (
        cd "$here/e2e"
        env ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test ASN1CGO_RT_LOCAL="$repo/libasn1compiler_go/rt/go" \
        "$tmp/bin/asn1c" \
            -S "$repo/skeletons" -fincludes-quoted -fcompound-names \
            -findirect-choice -fno-include-deps -gen-PER "$@" \
            -pdu=auto -D "$work/c" -Fgo="$work/go" \
            ex.asn ioc.asn default.asn nsmall.asn bits.asn seqof.asn \
            inlconstr.asn padalloc.asn extwide.asn strings.asn oids.asn \
            extgroup.asn names.asn xmod.asn choice.asn set.asn real32.asn \
            iocforms.asn iocinline.asn
    ) >"$work/asn1c.log" 2>&1 || { cat "$work/asn1c.log" >&2; echo "run-e2e: asn1c failed" >&2; return 1; }


    # The generated bit-position constants must be gofmt-clean byte for byte.
    if [ -n "$(gofmt -l "$work/go/namedbit/types.go")" ]; then
        echo "run-e2e: namedbit/types.go is not gofmt-clean" >&2
        return 1
    fi
    # bits.asn (four modules, each owning BIT STRING members) shares this one
    # -Fgo run with default.asn.
    cp "$here/e2e/main_test.go" \
       "$here/e2e/default_test.go" \
       "$here/e2e/nsmall_test.go" \
       "$here/e2e/faults_test.go" \
       "$here/e2e/bits_test.go" \
       "$here/e2e/seqof_test.go" \
       "$here/e2e/set_test.go" \
       "$here/e2e/inlconstr_test.go" \
       "$here/e2e/extwide_test.go" \
       "$here/e2e/extgroup_test.go" \
       "$here/e2e/strings_test.go" \
       "$here/e2e/oids_test.go" \
       "$here/e2e/names_test.go" \
       "$here/e2e/xmod_test.go" \
       "$here/e2e/choice_test.go" \
       "$here/e2e/real32_test.go" \
       "$here/e2e/iocforms_test.go" \
       "$here/e2e/iocinline_test.go" \
       "$here/e2e/randenc_test.go" \
       "$work/go/"
    # The BMPString / UniversalString helpers are unexported: their test lives
    # in the generated strs package.
    # JER tests exist only when the JER functions are generated.
    if [ "$jer" = 1 ]; then
        cp "$here/e2e/jer_test.go" "$here/e2e/jer_faults_test.go" "$work/go/"
    fi
    cp "$here/e2e/strs_internal_test.go" "$work/go/strs/"
    # Likewise the OBJECT IDENTIFIER / RELATIVE-OID helpers and XER entry
    # points of the generated oids package.
    cp "$here/e2e/oids_internal_test.go" "$work/go/oids/"
    # The alias-of-CHOICE XER cross-check against the C converter (unexported
    # XER entry points of the generated aliaschoice package).
    cp "$here/e2e/aliaschoice_internal_test.go" "$work/go/aliaschoice/"
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
                if [ "$jer" = 1 ]; then
                    echo "	jerDec[\"$n.$ty\"] = func(b []byte) (any, error) { return p_$n.DecodeJER$ty(b) }"
                fi
            done
        done
        echo "}"
    } >"$work/go/randreg_test.go"
    # The C converter built from the same C tree: the cross-check oracle for
    # APER/UPER/XER in default_test.go.
    (
        cd "$work/c"
        # shellcheck disable=SC2046
        ${CC:-cc} -O1 -w -DASN_PDU_COLLECTION $oerdef $jerdef -I. -o "$work/converter" \
            $(ls ./*.c | grep -v '/converter-example.c$') ./converter-example.c -lm
    ) >"$work/converter.log" 2>&1 || { cat "$work/converter.log" >&2; echo "run-e2e: converter build failed" >&2; return 1; }
    (
        cd "$work/go"
        export ASN1CGO_C_CONVERTER="$work/converter"
        export CGO_CFLAGS="-O2 -g -Werror=incompatible-pointer-types"
        go test -count=1 ./...
        # The same under AddressSanitizer (default ASAN_OPTIONS): out-of-bounds
        # accesses in the generated C conversion code or the runtime abort.
        if [ "$asan" = 1 ]; then
            go test -asan -count=1 ./...
        fi
        # The SEQUENCE OF inline-element, inline SEQUENCE/CHOICE and
        # extension-addition / wide-INTEGER / `present`-alt / restricted string
        # cases under the race detector.
        go test -race -count=1 -run 'SeqofInline|Set|InlConstr|ExtWide|ExtNil|ExtOld|ExtGroup|Strings|Oids' .
        go test -race -count=1 ./strs/ ./oids/
        if [ "$jer" = 1 ]; then
            go test -race -count=1 -run JER .
        fi
        # Allocation-fault sweep (needs the injection hooks compiled in).
        # -v so the per-direction N and the "no injectable allocations" note
        # for encode are visible.
        go test -count=1 -v -tags asn1cgo_faults -run TestAllocFaultSweep .
    )
}

run_one aper-no-oer -no-gen-OER
run_one aper-oer
run_one aper-jer -no-gen-OER -gen-JER
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

# A PDU whose DecodeJER<T> name equals another PDU's Decode<T>: fine without
# -gen-JER, refused (exit 70) with it.
run_jer_clash() {
    work="$tmp/jerclash"
    mkdir -p "$work/c" "$work/c2"
    echo "== run-e2e: DecodeJER name clash =="
    cat >"$work/jc.asn" <<'EOS'
JC DEFINITIONS AUTOMATIC TAGS ::= BEGIN
X ::= SEQUENCE { a INTEGER }
JERX ::= SEQUENCE { b BOOLEAN }
END
EOS
    (
        cd "$work"
        ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test ASN1CGO_RT_LOCAL="$repo/libasn1compiler_go/rt/go" \
        "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
            -fcompound-names -findirect-choice -fno-include-deps -gen-PER \
            -pdu=auto -D "$work/c" -Fgo="$work/go" jc.asn
    ) >"$work/asn1c.log" 2>&1 || { cat "$work/asn1c.log" >&2; echo "run-e2e: plain run failed" >&2; return 1; }
    ( cd "$work/go" && export CGO_CFLAGS="-O2 -g -Werror=incompatible-pointer-types" && go build ./... ) || return 1
    rc=0
    (
        cd "$work"
        ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test ASN1CGO_RT_LOCAL="$repo/libasn1compiler_go/rt/go" \
        "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
            -fcompound-names -findirect-choice -fno-include-deps -gen-PER -gen-JER \
            -pdu=auto -D "$work/c2" -Fgo="$work/go2" jc.asn
    ) >"$work/asn1c2.log" 2>&1 || rc=$?
    if [ "$rc" != 70 ] || ! grep -q 'collision in module.*DecodeJERX' "$work/asn1c2.log"; then
        cat "$work/asn1c2.log" >&2
        echo "run-e2e: -gen-JER clash: exit $rc, want 70 naming DecodeJERX" >&2
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

# A DEFAULT form the C generator gives no default callbacks for (a CHOICE
# value inside a SEQUENCE value) is rejected by the pre-flight: exit 70, the reason
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
    if ! grep -q 'asn1cgo: DEFAULT member Holder.p is out of model.*is a CHOICE value' "$work/asn1c.log"; then
        cat "$work/asn1c.log" >&2
        echo "run-e2e: unsupported-DEFAULT diagnostic missing" >&2
        return 1
    fi
    if [ -n "$(ls -A "$work/c")" ] || [ -e "$work/gen" ]; then
        echo "run-e2e: unsupported-DEFAULT case wrote output" >&2
        return 1
    fi
    # Precise reasons for a constructed DEFAULT that names the wrong members.
    while IFS='|' read -r label member want; do
        w="$tmp/unsupported-default-$label"
        mkdir -p "$w/c"
        cat >"$w/spec.asn" <<EOT
M DEFINITIONS AUTOMATIC TAGS ::= BEGIN
Pt ::= SEQUENCE { x INTEGER (0..255), y INTEGER (0..255) DEFAULT 7 }
T ::= SEQUENCE { $member, z BOOLEAN }
END
EOT
        rc=0
        (
            cd "$w"
            ASN1CGO_GO_MODULE_PREFIX=example.com "$tmp/bin/asn1c" \
                -S "$repo/skeletons" -gen-PER -no-gen-OER -pdu=auto \
                -D "$w/c" -Fgo="$w/gout" spec.asn
        ) >"$w/asn1c.log" 2>&1 || rc=$?
        if [ "$rc" != 70 ] || ! grep -qF "module M: $want" "$w/asn1c.log"; then
            cat "$w/asn1c.log" >&2
            echo "run-e2e: DEFAULT case '$label' (rc $rc) lacks: $want" >&2
            return 1
        fi
    done <<'EOT'
unknown|u Pt DEFAULT { q 1 }|u: `q` is not a member of the type
order|o Pt DEFAULT { y 2, x 1 }|o: member `x` is given out of order
twice|d Pt DEFAULT { x 1, x 2 }|d: member `x` is given twice
missing|m Pt DEFAULT { y 2 }|m: the required member `x` is not given
EOT
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

    # No prefix, non-colliding basename: accepted (the module is just "mymod").
    work="$tmp/collide-ok"
    mkdir -p "$work/c"
    (
        cd "$here/e2e"
        env -u ASN1CGO_GO_MODULE_PREFIX \
        "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
            -fcompound-names -findirect-choice -fno-include-deps -gen-PER \
            -pdu=auto -D "$work/c" -Fgo="$work/mymod" ex.asn
    ) >"$work/asn1c.log" 2>&1 || { cat "$work/asn1c.log" >&2; echo "run-e2e: -Fgo=mymod rejected" >&2; return 1; }
    [ -f "$work/mymod/go.mod" ] || { echo "run-e2e: -Fgo=mymod wrote no go.mod" >&2; return 1; }
}

# A -Fgo target that cannot be staged (a regular file, or a path through a
# regular file) is rejected by the pre-flight: exit 70, -D untouched.
run_outdir_unusable() {
    echo "== run-e2e: unusable -Fgo target (expect exit 70, before the C pass) =="
    work="$tmp/outdir-unusable"
    mkdir -p "$work/c"
    printf 'sentinel\n' >"$work/c/keep.c"
    touch -d '2001-01-01 00:00:00' "$work/c/keep.c"
    m0=$(stat -c %Y "$work/c/keep.c")
    printf 'file\n' >"$work/afile"
    while IFS='|' read -r target want; do
        rc=0
        (
            cd "$here/e2e"
            ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test "$tmp/bin/asn1c" \
                -S "$repo/skeletons" -fincludes-quoted -fcompound-names \
                -findirect-choice -fno-include-deps -gen-PER -pdu=auto \
                -D "$work/c" -Fgo="$work/$target" ex.asn
        ) >"$work/asn1c.log" 2>&1 || rc=$?
        if [ "$rc" != 70 ] || ! grep -qF "$want" "$work/asn1c.log" \
           || ! grep -qF 'no C output was written' "$work/asn1c.log"; then
            cat "$work/asn1c.log" >&2
            echo "run-e2e: -Fgo=$target (rc $rc) lacks: $want" >&2
            return 1
        fi
        if [ "$(ls -A "$work/c" | tr '\n' ' ')" != "keep.c " ] \
           || [ "$(cat "$work/c/keep.c")" != sentinel ] \
           || [ "$(stat -c %Y "$work/c/keep.c")" != "$m0" ]; then
            echo "run-e2e: -Fgo=$target: -D was modified" >&2
            return 1
        fi
    done <<'EOT'
afile|asn1cgo: -Fgo target exists and is not a directory
afile/go|asn1cgo: cannot stat -Fgo target
EOT
    if [ -n "$(ls -A "$work" | grep -v -x -e c -e afile -e asn1c.log)" ]; then
        echo "run-e2e: unusable -Fgo target left files behind" >&2
        return 1
    fi
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
run_jer_clash
run_oneway
run_unsupported_default
run_stdlib_collision
run_outdir_unusable
run_stdlib_names_drift
run_rt_fetch
run_rt_skeleton_sync
echo "run-e2e: PASS"
