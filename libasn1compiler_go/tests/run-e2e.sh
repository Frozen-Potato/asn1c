#!/bin/sh
# End-to-end test of the Go backend: generate Go from tests/e2e/ex.asn and
# tests/e2e/ioc.asn, build it with cgo (CGO_CFLAGS with -Werror=incompatible-pointer-types), check an APER
# and a UPER round-trip, every reachable error code, and an allocation-fault sweep.
# Runs three times: with -no-gen-OER, with OER enabled, and with -no-gen-OER
# -gen-JER (which adds EncodeJER / DecodeJER<T> and their tests).
# Exit codes: 0 pass, 77 skipped (automake SKIP), anything else failure.
# On Windows (GOOS=windows) it exits 77: the Go backend is not supported there.
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
case "$(go env GOOS)" in
windows)
    echo "run-e2e: SKIP: the Go backend is not supported on Windows (LLP64); use WSL2 or Linux" >&2
    exit 77 ;;
esac
case "$(go env GOARCH)" in
amd64|arm64) ;;
*)
    echo "run-e2e: SKIP: GOARCH is neither amd64 nor arm64" >&2
    exit 77 ;;
esac

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
            iocforms.asn iocinline.asn param.asn alias.asn
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
       "$here/e2e/param_test.go" \
       "$here/e2e/alias_test.go" \
       "$here/e2e/randenc_test.go" \
       "$here/e2e/uper_test.go" \
       "$here/e2e/uper_faults_test.go" \
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
                echo "	uperDec[\"$n.$ty\"] = func(b []byte) (any, error) { return p_$n.DecodeUPER$ty(b) }"
                # the ASN.1 type name (the C converter's -p), from the nil
                # receiver error of Encode
                lb=$(sed -n "/^func (p \*$ty) Encode() /{n;n;s/.*TypeName: \"\([^\"]*\)\".*/\1/p;q;}" "$d/glue.go")
                echo "	uperLabel[\"$n.$ty\"] = \"$lb\""
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
        go test -race -count=1 -run UPER .
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

# A PDU whose DecodeUPER<T> name equals another PDU's Decode<T> (X and
# UPERX: DecodeUPERX twice) is refused (exit 70) before any Go is written.
run_uper_clash() {
    work="$tmp/uperclash"
    mkdir -p "$work/c"
    echo "== run-e2e: DecodeUPER name clash =="
    cat >"$work/uc.asn" <<'EOS'
UC DEFINITIONS AUTOMATIC TAGS ::= BEGIN
X ::= SEQUENCE { a INTEGER }
UPERX ::= SEQUENCE { b BOOLEAN }
END
EOS
    rc=0
    (
        cd "$work"
        ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test ASN1CGO_RT_LOCAL="$repo/libasn1compiler_go/rt/go" \
        "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
            -fcompound-names -findirect-choice -fno-include-deps -gen-PER \
            -pdu=auto -D "$work/c" -Fgo="$work/go" uc.asn
    ) >"$work/asn1c.log" 2>&1 || rc=$?
    if [ "$rc" != 70 ] || ! grep -q 'collision in module UC: DecodeUPERX' "$work/asn1c.log"; then
        cat "$work/asn1c.log" >&2
        echo "run-e2e: DecodeUPER clash: exit $rc, want 70 naming DecodeUPERX" >&2
        return 1
    fi
    if [ -e "$work/go" ]; then
        echo "run-e2e: DecodeUPER clash wrote Go output" >&2
        return 1
    fi
}

# The constructor New<T> of a struct with DEFAULT members is a package-level
# name: a type named New<T> next to it is refused (exit 70) before any Go is
# written.
run_ctor_clash() {
    work="$tmp/ctorclash"
    mkdir -p "$work/c"
    echo "== run-e2e: New<T> name clash =="
    cat >"$work/cc.asn" <<'EOS'
CC DEFINITIONS AUTOMATIC TAGS ::= BEGIN
X ::= SEQUENCE { a INTEGER (0..7) DEFAULT 3 }
NewX ::= SEQUENCE { b BOOLEAN }
END
EOS
    rc=0
    (
        cd "$work"
        ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test ASN1CGO_RT_LOCAL="$repo/libasn1compiler_go/rt/go" \
        "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
            -fcompound-names -findirect-choice -fno-include-deps -gen-PER \
            -pdu=auto -D "$work/c" -Fgo="$work/go" cc.asn
    ) >"$work/asn1c.log" 2>&1 || rc=$?
    if [ "$rc" != 70 ] || ! grep -q 'collision in module CC: NewX <- X (constructor)' "$work/asn1c.log"; then
        cat "$work/asn1c.log" >&2
        echo "run-e2e: New<T> clash: exit $rc, want 70 naming NewX" >&2
        return 1
    fi
    if [ -e "$work/go" ]; then
        echo "run-e2e: New<T> clash wrote Go output" >&2
        return 1
    fi
}

# -pdu selects the PDU types that get Encode/Decode functions, as it selects
# the C PDU table: no -pdu option acts as -pdu=auto, and each -pdu=<Type>
# adds that type. A type defined as an instance of a parameterized type
# (Inst ::= T{INTEGER}) has functions of its own (DecodeInst).
run_pdu_select() {
    echo "== run-e2e: -pdu=<Type> selection =="
    cat >"$tmp/pdusel.asn" <<'EOS'
PS DEFINITIONS AUTOMATIC TAGS ::= BEGIN
Msg ::= SEQUENCE { id INTEGER (0..255), inner Inner, ... }
Inner ::= SEQUENCE { x BOOLEAN }
Other-PDU ::= CHOICE { a INTEGER, b NULL }
T{X} ::= SEQUENCE { v X }
Inst ::= T{INTEGER}
END
EOS
    for sel in "none:DecodeMsg DecodeOtherPDU DecodeInst:DecodeInner DecodeT5P0" \
               "-pdu=Inner:DecodeInner DecodeUPERInner:DecodeMsg DecodeOtherPDU" \
               "-pdu=Inner -pdu=Other-PDU:DecodeInner DecodeOtherPDU:DecodeMsg" \
               "-pdu=auto -pdu=Inner:DecodeMsg DecodeOtherPDU DecodeInner:"; do
        opts=${sel%%:*}; rest=${sel#*:}; want=${rest%%:*}; nowant=${rest#*:}
        [ "$opts" = none ] && opts=
        work="$tmp/pdusel/$(echo "x$opts" | tr -c 'A-Za-z0-9\n' _)"
        mkdir -p "$work/c"
        (
            cd "$work"
            # shellcheck disable=SC2086
            ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test ASN1CGO_RT_LOCAL="$repo/libasn1compiler_go/rt/go" \
            "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
                -fcompound-names -findirect-choice -fno-include-deps -gen-PER \
                $opts -D "$work/c" -Fgo="$work/go" "$tmp/pdusel.asn"
        ) >"$work/asn1c.log" 2>&1 || { cat "$work/asn1c.log" >&2; echo "run-e2e: -pdu selection [$opts]: asn1c failed" >&2; return 1; }
        for f in $want; do
            grep -q "^func $f(" "$work/go/ps/glue.go" || { echo "run-e2e: -pdu selection [$opts]: no $f" >&2; return 1; }
        done
        for f in $nowant; do
            if grep -q "^func $f(" "$work/go/ps/glue.go"; then
                echo "run-e2e: -pdu selection [$opts]: unexpected $f" >&2; return 1
            fi
        done
        (
            cd "$work/go"
            export CGO_CFLAGS="-O2 -g -Werror=incompatible-pointer-types"
            go build ./...
        ) || { echo "run-e2e: -pdu selection [$opts]: go build failed" >&2; return 1; }
    done
    work="$tmp/pdusel/inst"
    mkdir -p "$work/c"
    (
        cd "$work"
        ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test ASN1CGO_RT_LOCAL="$repo/libasn1compiler_go/rt/go" \
        "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
            -fcompound-names -findirect-choice -fno-include-deps -gen-PER \
            -pdu=Inst -D "$work/c" -Fgo="$work/go" "$tmp/pdusel.asn"
    ) >"$work/asn1c.log" 2>&1 || { cat "$work/asn1c.log" >&2; echo "run-e2e: -pdu=Inst: asn1c failed" >&2; return 1; }
    for f in DecodeInst DecodeUPERInst; do
        grep -q "^func $f(" "$work/go/ps/glue.go" || { echo "run-e2e: -pdu=Inst: no $f" >&2; return 1; }
    done
    (
        cd "$work/go"
        export CGO_CFLAGS="-O2 -g -Werror=incompatible-pointer-types"
        go build ./...
    ) || { echo "run-e2e: -pdu=Inst: go build failed" >&2; return 1; }
}

# An open type whose object set has no object (`ExtIEs IE ::= { ... }`, the
# usual extension container) made asn1c crash in the Go pass. Such a value
# union has only its Present field; a message without such values encodes
# and decodes, and one with a value fails to encode.
run_empty_object_set() {
    echo "== run-e2e: empty object set =="
    work="$tmp/emptyset"
    mkdir -p "$work/c"
    cat >"$work/emptyset.asn" <<'EOS'
ES DEFINITIONS AUTOMATIC TAGS ::= BEGIN
IE ::= CLASS { &id INTEGER (0..65535) UNIQUE, &Value } WITH SYNTAX { ID &id TYPE &Value }
Field {IE : Set} ::= SEQUENCE { id IE.&id ({Set}), value IE.&Value ({Set}{@id}) }
Container {IE : Set} ::= SEQUENCE (SIZE (1..4)) OF Field {{Set}}
ExtIEs IE ::= { ... }
Direct ::= SEQUENCE { id IE.&id ({ExtIEs}), value IE.&Value ({ExtIEs}{@id}) }
Msg ::= SEQUENCE { a INTEGER (0..7), ext Container {{ExtIEs}} OPTIONAL, d SEQUENCE (SIZE (0..2)) OF Direct, ... }
END
EOS
    cat >"$work/emptyset_test.go" <<'EOS'
package e2e

import (
	"testing"

	es "asn1cgo.test/go/es"
)

func TestEmptyObjectSet(t *testing.T) {
	m := &es.Msg{A: 5}
	b, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := es.DecodeMsg(b)
	if err != nil || d.A != 5 || d.Ext != nil || len(d.D) != 0 {
		t.Fatalf("%+v %v", d, err)
	}
	m.D = []es.Direct{{Id: 1}}
	if _, err := m.Encode(); err == nil {
		t.Fatal("a value of an empty object set encoded")
	}
}
EOS
    (
        cd "$work"
        ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test ASN1CGO_RT_LOCAL="$repo/libasn1compiler_go/rt/go" \
        "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
            -fcompound-names -findirect-choice -fno-include-deps -gen-PER \
            -pdu=auto -D "$work/c" -Fgo="$work/go" "$work/emptyset.asn"
    ) >"$work/asn1c.log" 2>&1 || { cat "$work/asn1c.log" >&2; echo "run-e2e: empty object set: asn1c failed" >&2; return 1; }
    cp "$work/emptyset_test.go" "$work/go/"
    (
        cd "$work/go"
        export CGO_CFLAGS="-O2 -g -Werror=incompatible-pointer-types"
        go vet ./...
        go test -count=1 .
    ) || { echo "run-e2e: empty object set: go test failed" >&2; return 1; }
}

# asn1c -fopen-type-unknown: a module (e2e/otunknown.asn) decodes the
# encodings of ids and procedures that its newer version (otunknown-peer.asn,
# no flag) added, as the Unknown alternative, and encodes them back
# unchanged. The peer tree checks that it still encodes the vectors
# (otunknown_vectors_test.go). Without the flag the module builds too and
# has no Unknown alternative.
run_open_type_unknown() {
    echo "== run-e2e: -fopen-type-unknown =="
    for side in peer:otunknown-peer.asn:-gen-JER known:otunknown.asn:"-gen-JER -fopen-type-unknown" clash:otunknown2.asn:"-gen-JER -fopen-type-unknown" plain:otunknown.asn:-gen-JER; do
        label=${side%%:*}; rest=${side#*:}; asn=${rest%%:*}; opts=${rest#*:}
        work="$tmp/otunknown/$label"
        mkdir -p "$work/c"
        (
            cd "$here/e2e"
            # shellcheck disable=SC2086
            env ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test ASN1CGO_RT_LOCAL="$repo/libasn1compiler_go/rt/go" \
            "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
                -fcompound-names -findirect-choice -fno-include-deps -gen-PER \
                $opts -pdu=auto -D "$work/c" -Fgo="$work/go" "$asn"
        ) >"$work/asn1c.log" 2>&1 || { cat "$work/asn1c.log" >&2; echo "run-e2e: -fopen-type-unknown [$label]: asn1c failed" >&2; return 1; }
        case $label in
        peer)  cp "$here/e2e/otunknown_peer_test.go" "$here/e2e/otunknown_vectors_test.go" "$work/go/" ;;
        known) cp "$here/e2e/otunknown_test.go" "$here/e2e/otunknown_vectors_test.go" "$work/go/" ;;
        clash) cp "$here/e2e/otunknown2_test.go" "$work/go/" ;;
        plain)
            if grep -q 'OpenTypeRaw' "$work/go/otunknown/types.go"; then
                echo "run-e2e: -fopen-type-unknown: Unknown alternative without the flag" >&2
                return 1
            fi ;;
        esac
        (
            cd "$work/go"
            export CGO_CFLAGS="-O2 -g -Werror=incompatible-pointer-types"
            go vet ./...
            go test -count=1 ./...
            if [ "$asan" = 1 ] && [ "$label" != plain ]; then
                go test -asan -count=1 .
            fi
        ) || { echo "run-e2e: -fopen-type-unknown [$label]: go test failed" >&2; return 1; }
    done
}

# With -Fgo a failed run leaves -D as it was: a Go refusal after the C pass
# (the -gen-JER name clash) and a C-pass failure (a directory where a .c file
# goes) restore every replaced file and remove every created one; a
# successful run leaves no backup files behind.
run_post_c_restore() {
    work="$tmp/restore"
    mkdir -p "$work/c"
    echo "== run-e2e: failed run restores -D =="
    cat >"$work/jc.asn" <<'EOS'
JC DEFINITIONS AUTOMATIC TAGS ::= BEGIN
X ::= SEQUENCE { a INTEGER }
JERX ::= SEQUENCE { b BOOLEAN }
END
EOS
    gen() {
        (
            cd "$work"
            ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test ASN1CGO_RT_LOCAL="$repo/libasn1compiler_go/rt/go" \
            "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
                -fcompound-names -findirect-choice -fno-include-deps -gen-PER \
                -pdu=auto -D "$work/c" -Fgo="$work/go" "$@" jc.asn
        ) >"$work/asn1c.log" 2>&1
    }
    snap() {
        ( cd "$1" && find . ! -path . -printf '%p %y %s %T@ %l\n' | sort \
          && find . -type f -exec cksum {} + | sort -k3 )
    }
    printf 'keep\n' >"$work/c/user-file.txt"
    gen || { cat "$work/asn1c.log" >&2; echo "run-e2e: restore: first run failed" >&2; return 1; }
    printf '/* local edit */\n' >>"$work/c/X.c"
    find "$work/c" "$work/go" -exec touch -h -d '2001-01-01 00:00:00' {} +
    snap "$work/c" >"$work/c.0"
    snap "$work/go" >"$work/go.0"
    for case in jer dir; do
        rc=0
        if [ $case = jer ]; then
            gen -gen-JER || rc=$?
        else
            rm "$work/c/JERX.c"
            mkdir "$work/c/JERX.c"
            snap "$work/c" >"$work/c.0"
            gen || rc=$?
        fi
        if [ "$rc" != 70 ] || ! grep -qF 'was restored' "$work/asn1c.log"; then
            cat "$work/asn1c.log" >&2
            echo "run-e2e: restore ($case): exit $rc, want 70 and 'was restored'" >&2
            return 1
        fi
        snap "$work/c" >"$work/c.1"
        snap "$work/go" >"$work/go.1"
        if ! cmp -s "$work/c.0" "$work/c.1" || ! cmp -s "$work/go.0" "$work/go.1"; then
            diff "$work/c.0" "$work/c.1" >&2 || :
            diff "$work/go.0" "$work/go.1" >&2 || :
            echo "run-e2e: restore ($case): -D or the Go tree changed" >&2
            return 1
        fi
    done
    rmdir "$work/c/JERX.c"
    gen || { cat "$work/asn1c.log" >&2; echo "run-e2e: restore: last run failed" >&2; return 1; }
    if [ -n "$(ls -A "$work/c" | grep -F '.asn1c-bak.')" ] \
       || [ "$(cat "$work/c/user-file.txt")" != keep ]; then
        ls -A "$work/c" >&2
        echo "run-e2e: restore: backups left behind or a user file changed" >&2
        return 1
    fi
}

# Output directory safety with -Fgo: a -D that is the -Fgo directory or
# inside it is refused before the C pass; a regenerated Go tree keeps its
# directory permissions; backup files left by a killed run stop the next run
# (-D untouched); two runs writing the same -D and -Fgo at the same time are
# serialised, so each leaves a consistent C + Go generation.
run_outdir_safety() {
    work="$tmp/outsafe"
    mkdir -p "$work"
    echo "== run-e2e: output directory safety =="
    gen() {
        dir=$1; spec=$2; shift 2
        (
            cd "$work/$dir"
            ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test ASN1CGO_RT_LOCAL="$repo/libasn1compiler_go/rt/go" \
            "$tmp/bin/asn1c" -S "$repo/skeletons" -fincludes-quoted \
                -fcompound-names -findirect-choice -fno-include-deps -gen-PER \
                -pdu=all "$@" "$spec"
        )
    }
    for rev in 1 2; do
        {
            echo "Many DEFINITIONS AUTOMATIC TAGS ::= BEGIN"
            i=0
            while [ $i -lt 40 ]; do
                if [ $rev = 2 ]; then
                    echo "Item$i ::= SEQUENCE { a INTEGER (0..255), newField BOOLEAN }"
                else
                    echo "Item$i ::= SEQUENCE { a INTEGER (0..255) }"
                fi
                i=$((i + 1))
            done
            echo "END"
        } >"$work/rev$rev.asn"
    done

    # overlapping directories
    while IFS='|' read -r name d g; do
        mkdir -p "$work/$name/$d"
        printf 'keep\n' >"$work/$name/$d/keep.txt"
        rc=0
        gen "$name" "$work/rev1.asn" -D "$d" -Fgo="$g" >"$work/$name.log" 2>&1 || rc=$?
        if [ "$rc" != 70 ] || ! grep -qF 'use separate directories' "$work/$name.log" \
           || [ "$(ls -A "$work/$name/$d")" != keep.txt ]; then
            cat "$work/$name.log" >&2
            echo "run-e2e: overlap $name (-D $d -Fgo=$g): exit $rc, want 70 and -D untouched" >&2
            return 1
        fi
    done <<'EOT'
same|out|out
dotted|out|./out/.
inside|go/c|go
EOT

    # permissions of a regenerated tree
    mkdir -p "$work/perm/c"
    gen perm "$work/rev1.asn" -D c -Fgo=gen >"$work/perm.log" 2>&1 || { cat "$work/perm.log" >&2; return 1; }
    chmod 750 "$work/perm/gen"
    gen perm "$work/rev2.asn" -D c -Fgo=gen >"$work/perm.log" 2>&1 || { cat "$work/perm.log" >&2; return 1; }
    if [ "$(stat -c %a "$work/perm/gen")" != 750 ]; then
        echo "run-e2e: regenerated Go tree mode $(stat -c %a "$work/perm/gen"), want 750" >&2
        return 1
    fi

    # backups of a killed run
    printf 'old\n' >"$work/perm/c/.Item0.c.asn1c-bak.1.0"
    ls -lA --time-style=+%s "$work/perm/c" >"$work/perm.0"
    rc=0
    gen perm "$work/rev1.asn" -D c -Fgo=gen >"$work/perm.log" 2>&1 || rc=$?
    ls -lA --time-style=+%s "$work/perm/c" >"$work/perm.1"
    if [ "$rc" != 70 ] || ! grep -qF 'backup files of a run that was killed' "$work/perm.log" \
       || ! cmp -s "$work/perm.0" "$work/perm.1"; then
        cat "$work/perm.log" >&2
        echo "run-e2e: stale backup: exit $rc, want 70 and -D untouched" >&2
        return 1
    fi
    rm "$work/perm/c/.Item0.c.asn1c-bak.1.0"

    # concurrent runs on the same -D and -Fgo
    mkdir -p "$work/conc/c"
    gen conc "$work/rev1.asn" -D c -Fgo=gen >"$work/conc.log" 2>&1 || { cat "$work/conc.log" >&2; return 1; }
    for round in 1 2 3; do
        rc1=0; rc2=0
        gen conc "$work/rev1.asn" -D c -Fgo=gen >"$work/conc1.log" 2>&1 & p1=$!
        gen conc "$work/rev2.asn" -D c -Fgo=gen >"$work/conc2.log" 2>&1 & p2=$!
        wait $p1 || rc1=$?
        wait $p2 || rc2=$?
        nc=$(grep -l newField "$work"/conc/c/Item*.h | wc -l)
        ns=$(grep -l newField "$work"/conc/gen/internal/cspec/Item*.h | wc -l)
        ng=$(grep -c NewField "$work/conc/gen/many/types.go" || :)
        if [ "$rc1" != 0 ] || [ "$rc2" != 0 ] || [ "$nc" != "$ns" ] \
           || [ "$nc" != "$ng" ] || { [ "$nc" != 0 ] && [ "$nc" != 40 ]; }; then
            cat "$work/conc1.log" "$work/conc2.log" >&2
            echo "run-e2e: concurrent round $round: rc $rc1/$rc2, newField in C $nc, cspec $ns, Go $ng (want 0 or 40, all equal)" >&2
            return 1
        fi
    done
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
run_uper_clash
run_ctor_clash
run_pdu_select
run_empty_object_set
run_open_type_unknown
run_post_c_restore
run_outdir_safety
run_oneway
run_unsupported_default
run_stdlib_collision
run_outdir_unusable
run_stdlib_names_drift
run_rt_fetch
run_rt_skeleton_sync
echo "run-e2e: PASS"
