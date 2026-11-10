#!/bin/sh
# Refresh the asn1c skeleton runtime copy inside the Go runtime module
# (rt/go/rt) from <fork>/skeletons. Run after any change under skeletons/.
# Everything is copied except converter-example.c (it defines main()).
set -e
here=$(cd "$(dirname "$0")" && pwd)
skel="$here/../../skeletons"
dst="$here/go/rt"
for f in "$skel"/*.c "$skel"/*.h; do
    b=$(basename "$f")
    [ "$b" = converter-example.c ] && continue
    case "$b" in
    # Not guarded by ASN_DISABLE_OER_SUPPORT upstream (asn1c just doesn't copy
    # them for -no-gen-OER). Keep them out of the cgo build unless the
    # asn1cgo_oer tag is set; cgo honours //go:build lines in .c files.
    oer_decoder.c|oer_encoder.c|oer_support.c|OPEN_TYPE_oer.c)
        { printf '//go:build asn1cgo_oer\n\n'; cat "$f"; } > "$dst/$b" ;;
    *) cp "$f" "$dst/$b" ;;
    esac
done
