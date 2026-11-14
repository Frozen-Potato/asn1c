#!/bin/sh

# A DEFAULT of a SEQUENCE / SET / SEQUENCE OF / SET OF member that the
# generator cannot convert (an unknown or missing member, a CHOICE value, a
# recursive default, ...) is not an error: asn1c exits 0, prints nothing
# on stderr besides the names of the files it writes, and the member keeps "0, 0, /* No default value */" like before.
# The accepted forms are in 175-default-constructed-OK.asn1.

top_srcdir="${top_srcdir:-../..}"
top_builddir="${top_builddir:-../..}"
asn1c="$(cd "${top_builddir}" && pwd)/asn1c/asn1c"
skel="$(cd "${top_srcdir}" && pwd)/skeletons"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-default-constructed.XXXXXX") || exit 99
trap 'rm -rf "$tmp"' EXIT
fail=0

# fallback <label> <file with the member> <module body>
fallback() {
	label=$1; file=$2; body=$3
	mkdir "$tmp/$label" "$tmp/$label/c"
	cat >"$tmp/$label/m.asn" <<EOT
M DEFINITIONS AUTOMATIC TAGS ::= BEGIN
$body
END
EOT
	(cd "$tmp/$label" && "$asn1c" -S "$skel" -gen-PER -no-gen-OER -D c m.asn \
		>out 2>err)
	rc=$?
	[ $rc = 0 ] || { echo "FAIL: $label: rc=$rc"; cat "$tmp/$label/err"; fail=1; }
	# asn1c reports the files it writes on stderr; anything else is new
	extra=$(grep -v -E '^(Compiled|Copied|Generated) ' "$tmp/$label/err")
	[ -z "$extra" ] || {
		echo "FAIL: $label: unexpected stderr"; echo "$extra"; fail=1; }
	grep -q "0, 0, /\* No default value \*/" "$tmp/$label/c/$file" || {
		echo "FAIL: $label: no 'No default value' member in $file"; fail=1; }
	if grep -q "asn_DFL_" "$tmp/$label/c/$file"; then
		echo "FAIL: $label: default callbacks were generated"; fail=1
	fi
}

PT='Pt ::= SEQUENCE { x INTEGER (0..255), y INTEGER (0..255) DEFAULT 7 }'

fallback unknown T.c "$PT
T ::= SEQUENCE { a Pt DEFAULT { q 1 }, z BOOLEAN }"
fallback missing T.c "$PT
T ::= SEQUENCE { a Pt DEFAULT { y 2 }, z BOOLEAN }"
fallback order T.c "$PT
T ::= SEQUENCE { a Pt DEFAULT { y 2, x 1 }, z BOOLEAN }"
fallback twice T.c "$PT
T ::= SEQUENCE { a Pt DEFAULT { x 1, x 2 }, z BOOLEAN }"
fallback choice T.c "Ch ::= CHOICE { n INTEGER (0..9), b BOOLEAN }
S ::= SEQUENCE { c Ch }
T ::= SEQUENCE { s S DEFAULT { c n : 3 }, z BOOLEAN }"
fallback badtype T.c "$PT
T ::= SEQUENCE { a Pt DEFAULT { x TRUE }, z BOOLEAN }"
fallback recursive R.c "R ::= SEQUENCE { v INTEGER, r R DEFAULT { v 1 } }"
fallback mutual A.c "A ::= SEQUENCE { v INTEGER, b B DEFAULT { v 1 } }
B ::= SEQUENCE { v INTEGER, a A DEFAULT { v 2 } }"

exit $fail
