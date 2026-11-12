#!/bin/sh
# The Go runtime's C files (rt/go/rt) must stay identical to their namesakes
# in skeletons/. The only allowed difference is the leading
# "//go:build asn1cgo_oer" line plus the blank line after it, which the OER
# files carry. Also: every rt .c must compile warning-free with
# `$CC -pthread -Wall -Wextra -Werror=cpp` (cgo passes -pthread, which
# predefines _REENTRANT; a redefinition must not come back).
# Exit codes: 0 pass, 77 skipped (no compiler), anything else failure.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
rt="$here/../rt/go/rt"
sk="$here/../../skeletons"
tmp=$(mktemp -d)
trap 'rm -rf "${tmp:?}"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

rc=0
n=0
for f in "$rt"/*.c "$rt"/*.h; do
    b=$(basename "$f")
    [ -f "$sk/$b" ] || continue
    n=$((n + 1))
    if [ "$(sed -n 1p "$f")" = "//go:build asn1cgo_oer" ] && [ -z "$(sed -n 2p "$f")" ]; then
        sed '1,2d' "$f" >"$tmp/cmp"
    else
        cp "$f" "$tmp/cmp"
    fi
    if ! cmp -s "$tmp/cmp" "$sk/$b"; then
        echo "run-rt-skeleton-sync: $b differs from skeletons/$b:" >&2
        diff -u "$sk/$b" "$tmp/cmp" >&2 || true
        rc=1
    fi
done
if [ "$n" -eq 0 ]; then
    echo "run-rt-skeleton-sync: no namesake files found" >&2
    exit 1
fi
[ "$rc" = 0 ] || exit "$rc"

cc=${CC:-cc}
if ! command -v "$cc" >/dev/null 2>&1; then
    echo "run-rt-skeleton-sync: PASS ($n files identical); compile check SKIP: '$cc' not found" >&2
    exit 0
fi
for f in "$rt"/*.c; do
    # The //go:build asn1cgo_oer files are only built together with OER
    # support, so they are compiled without -DASN_DISABLE_OER_SUPPORT.
    oer=-DASN_DISABLE_OER_SUPPORT
    [ "$(sed -n 1p "$f")" = "//go:build asn1cgo_oer" ] && oer=
    if ! $cc -pthread -Wall -Wextra -Werror=cpp -I"$rt" $oer \
            -c "$f" -o /dev/null 2>"$tmp/err"; then
        echo "run-rt-skeleton-sync: $(basename "$f") failed with $cc:" >&2
        cat "$tmp/err" >&2
        exit 1
    fi
done
echo "run-rt-skeleton-sync: PASS ($n files identical, rt compiles with $cc -pthread -Werror=cpp)"
