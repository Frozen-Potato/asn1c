#!/bin/sh

# A brace group of 2 or 4 numbers never produces the bogus "too large"
# message, and a Tuple out of range inside a constraint is still rejected.
# The accepted forms are in 174-brace-tuple-OK.asn1.

top_srcdir="${top_srcdir:-../..}"
top_builddir="${top_builddir:-../..}"
asn1c="$(cd "${top_builddir}" && pwd)/asn1c/asn1c"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-brace-tuple.XXXXXX") || exit 99
trap 'rm -rf "$tmp"' EXIT
fail=0

# run <label> <definitions> <expected: ok|bad>
run() {
	label=$1; defs=$2; want=$3
	cat >"$tmp/m.asn" <<EOT
M DEFINITIONS AUTOMATIC TAGS ::= BEGIN
$defs
U ::= INTEGER (0..9)
END
EOT
	out=$("$asn1c" -E "$tmp/m.asn" 2>&1)
	rc=$?
	if [ "$want" = ok ] && [ $rc != 0 ]; then
		echo "FAIL: $label rejected: $out"; fail=1
	fi
	if [ "$want" = bad ] && [ $rc = 0 ]; then
		echo "FAIL: $label accepted"; fail=1
	fi
	if echo "$out" | grep -q "too large"; then
		echo "FAIL: $label printed \"too large\""; fail=1
	fi
}

run out-of-range-tuple 'S ::= IA5String (FROM ({0, 20}..{0, 9}))' bad
run tuple 'S ::= IA5String (FROM ({0, 7}..{0, 9}))' ok
run quadruple 'S ::= BMPString (FROM ({0, 0, 0, 65}..{0, 0, 0, 90}))' ok
for v in '{ 1, 2 }' '{ 1, 20 }' '{ 1, 2, 3, 4 }' '{ 1, 2, 3, 400 }'; do
	run "value $v" "Ls ::= SEQUENCE OF INTEGER
T ::= SEQUENCE { e Ls DEFAULT $v, f INTEGER (0..9) }" ok
done

exit $fail
