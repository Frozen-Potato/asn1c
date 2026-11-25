#!/bin/sh
# Fail when the Go backend (libasn1compiler_go, linked into asn1c) defines a
# global symbol without its prefix: go_ or asn1cgo_ (functions, data),
# g_go_ (data) or GO_ (constant tables). The rest of asn1c links into the
# same program, so a generic global name (own, xrealloc, ...) could clash.
# usage: check-go-symbols.sh <directory with the go_*.o objects>
dir=${1:-asn1c}
set -- "$dir"/go_*.o
if [ ! -f "$1" ]; then
    echo "check-go-symbols: no $dir/go_*.o objects (build first)" >&2
    exit 1
fi
bad=$(nm -g --defined-only "$@" | awk 'NF == 3 { print $3 }' \
      | grep -vE '^(go_|asn1cgo_|g_go_|GO_)' | LC_ALL=C sort -u)
if [ -n "$bad" ]; then
    echo "Go backend globals without a go_/asn1cgo_/g_go_/GO_ prefix" \
         "(prefix them, or make them static):"
    echo "$bad"
    exit 1
fi
echo "Go backend globals: all prefixed ($# objects)."
