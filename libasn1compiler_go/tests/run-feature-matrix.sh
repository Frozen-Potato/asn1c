#!/bin/sh
# Feature-matrix regression test for the Go backend. Every feature-matrix/*.asn
# (module Probe) is generated with the standard e2e flags; when generation
# succeeds, `go vet ./...` runs over the output. Each case is classified:
#   OK       generated and vetted clean
#   REFUSED  asn1c exited non-zero with a clean `asn1cgo: <construct> in module
#            ...` style refusal (no internal error)
#   BROKEN   an internal error (`asn1cgo: conv:|glue:|flat:|ctor:`), a
#            non-asn1cgo failure, or generated code that fails `go vet`
# and compared with feature-matrix/expected.tsv (tab separated):
#   <case> OK
#   <case> REFUSED <substring of the refusal message>
#   <case> KNOWN-BROKEN <task>
# BROKEN is never acceptable except for KNOWN-BROKEN rows (reported XFAIL); a
# KNOWN-BROKEN case that starts to generate and vet clean fails, so it gets
# flipped to OK. (A KNOWN-BROKEN row may also be a clean refusal that a later
# task turns into support, e.g. choice-present.)
# Exit codes: 0 pass, 77 skipped, anything else failure.
set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
asn1c="$repo/asn1c/asn1c"
fm="$here/feature-matrix"

if [ ! -x "$asn1c" ]; then
    echo "run-feature-matrix: SKIP: $asn1c not found" >&2
    exit 77
fi
if ! command -v go >/dev/null 2>&1; then
    echo "run-feature-matrix: SKIP: 'go' not found" >&2
    exit 77
fi
if [ "$(go env CGO_ENABLED)" != 1 ]; then
    echo "run-feature-matrix: SKIP: CGO_ENABLED is not 1" >&2
    exit 77
fi

tmp=$(mktemp -d)
cleanup() { rm -rf "${tmp:?}"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# run_case <name>: writes $tmp/<name>.res = "<OK|REFUSED|BROKEN>\t<detail>"
run_case() {
    n=$1
    w="$tmp/w-$n"
    mkdir -p "$w/c"
    rc=0
    ASN1CGO_GO_MODULE_PREFIX=asn1cgo.test \
    ASN1CGO_RT_LOCAL="$repo/libasn1compiler_go/rt/go" \
    "$asn1c" -S "$repo/skeletons" -fincludes-quoted -fcompound-names \
        -findirect-choice -fno-include-deps -gen-PER -no-gen-OER -pdu=auto \
        -D "$w/c" -Fgo="$w/go" "$fm/$n.asn" >"$w/asn1c.log" 2>&1 || rc=$?
    if grep -Eq 'asn1cgo: (conv|glue|flat|ctor):' "$w/asn1c.log"; then
        d=$(grep -E 'asn1cgo: (conv|glue|flat|ctor):' "$w/asn1c.log" | head -1)
        printf 'BROKEN\tinternal error: %s\n' "$d" >"$tmp/$n.res"
        return
    fi
    if [ "$rc" != 0 ]; then
        d=$(grep -E '^asn1cgo: ' "$w/asn1c.log" | head -1)
        if [ -z "$d" ]; then
            d="exit $rc without an asn1cgo refusal: $(tail -1 "$w/asn1c.log")"
            printf 'BROKEN\t%s\n' "$d" >"$tmp/$n.res"
        else
            printf 'REFUSED\t%s\n' "$d" >"$tmp/$n.res"
        fi
        return
    fi
    if (cd "$w/go" && CGO_CFLAGS="-O2 -g -Werror=incompatible-pointer-types" \
            go vet ./... ) >"$w/vet.log" 2>&1; then
        printf 'OK\t\n' >"$tmp/$n.res"
    else
        printf 'BROKEN\tgo vet failed: %s\n' "$(head -3 "$w/vet.log" | tr '\n' ' ')" >"$tmp/$n.res"
    fi
    rm -rf "$w/go" "$w/c"
}

cases=$(cd "$fm" && ls ./*.asn | sed -e 's|^\./||' -e 's|\.asn$||')
jobs_max=${FEATURE_MATRIX_JOBS:-8}
i=0
for n in $cases; do
    run_case "$n" 2>/dev/null &
    i=$((i + 1))
    if [ $((i % jobs_max)) = 0 ]; then wait; fi
done
wait

if [ -n "${FEATURE_MATRIX_DUMP:-}" ]; then
    for n in $cases; do printf '%s\t' "$n"; cat "$tmp/$n.res"; done
    exit 0
fi

fail=0
npass=0 nxfail=0
printf '%-24s %-10s %-9s %s\n' CASE EXPECTED ACTUAL RESULT
for n in $cases; do
    exp=$(awk -F'\t' -v n="$n" '$1 == n { print $2 "\t" $3; exit }' "$fm/expected.tsv")
    if [ -z "$exp" ]; then
        printf '%-24s %-10s %-9s %s\n' "$n" "-" "?" "FAIL (no expected.tsv row)"
        fail=1; continue
    fi
    ekind=${exp%%	*}
    edet=${exp#*	}
    akind=$(cut -f1 "$tmp/$n.res")
    adet=$(cut -f2- "$tmp/$n.res")
    res=
    case $ekind in
    OK)
        if [ "$akind" = OK ]; then res=PASS; else res="FAIL ($akind: $adet)"; fi ;;
    REFUSED)
        if [ "$akind" != REFUSED ]; then
            res="FAIL ($akind: $adet)"
        else
            case $adet in
            *"$edet"*) res=PASS ;;
            *) res="FAIL (refusal message lacks '$edet': $adet)" ;;
            esac
        fi ;;
    KNOWN-BROKEN*)
        # not yet fixed: anything but a clean OK (a clean refusal included —
        # such a row waits for the construct to be supported)
        if [ "$akind" != OK ]; then res="XFAIL"
        else res="FAIL (KNOWN-BROKEN case now generates and vets; flip expected.tsv to OK)"; fi ;;
    *) res="FAIL (bad expected kind '$ekind')" ;;
    esac
    case $res in
    PASS) npass=$((npass + 1)) ;;
    XFAIL) nxfail=$((nxfail + 1)) ;;
    *) fail=1 ;;
    esac
    shown=$ekind
    [ "$ekind" = KNOWN-BROKEN ] && shown="BROKEN-${edet}"
    printf '%-24s %-10s %-9s %s\n' "$n" "$shown" "$akind" "$res"
done
# every expected row needs a case file
for n in $(cut -f1 "$fm/expected.tsv"); do
    [ -f "$fm/$n.asn" ] || { echo "run-feature-matrix: expected.tsv row '$n' has no $n.asn" >&2; fail=1; }
done
echo "run-feature-matrix: $npass pass, $nxfail xfail"
[ "$fail" = 0 ] || { echo "run-feature-matrix: FAIL" >&2; exit 1; }
echo "run-feature-matrix: PASS"
