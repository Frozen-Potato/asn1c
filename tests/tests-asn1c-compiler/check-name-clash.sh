#!/bin/sh

# A real name clash must fail the run even with -fcompound-names, and a
# false one (the same declaration synthesized twice) must not be reported.
# Also for the Go backend: the bit-position constants of a named-bit BIT STRING
# are Go package-level names and clash with types and with each other.

top_srcdir="${top_srcdir:-../..}"
top_builddir="${top_builddir:-../..}"
asn1c="$(cd "${top_builddir}" && pwd)/asn1c/asn1c"
skel="$(cd "${top_srcdir}" && pwd)/skeletons"
srcdir_t="$(cd "${top_srcdir}" && pwd)/tests/tests-asn1c-compiler"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-name-clash.XXXXXX") || exit 99
trap 'rm -rf "$tmp"' EXIT
fail=0

# 1. Real clash: non-zero exit, FATAL message, no output files.
mkdir "$tmp/real"
out=$(cd "$tmp/real" && "$asn1c" -S "$skel" \
	-fcompound-names "$srcdir_t/166-compound-real-clash-OK.asn1" 2>&1)
rc=$?
if [ $rc = 0 ]; then
	echo "FAIL: real clash under -fcompound-names exited 0"; fail=1
fi
echo "$out" | grep -q "Name clashes encountered even with -fcompound-names" || {
	echo "FAIL: no clash diagnostic"; fail=1; }
if [ -n "$(ls -A "$tmp/real")" ]; then
	echo "FAIL: files written despite the clash"; fail=1
fi

# 2. Same declaration reached twice: must succeed without any clash.
mkdir "$tmp/dup"
out=$(cd "$tmp/dup" && "$asn1c" -S "$skel" \
	-fcompound-names "$srcdir_t/165-open-type-selector-compound-OK.asn1" 2>&1)
rc=$?
[ $rc = 0 ] || { echo "FAIL: 165 exited $rc"; fail=1; }
echo "$out" | grep -q "FATAL" && { echo "FAIL: 165 reported FATAL"; fail=1; }

# 3. Go backend (-Fgo): the constants of a named-bit BIT STRING (type X, bit
#    B1 -> XB1) collide with a type named XB1, with another bit of the same
#    type, and (inline member) with a type named like the member's constants.
#    Exit 70, a collision diagnostic naming both, no Go tree written. The same
#    module minus the collision is accepted.
n_go=0
go_clash() {
	name=$1; asn=$2; want=$3; shift 3
	name="$name$n_go"; n_go=$((n_go + 1))
	mkdir "$tmp/$name" "$tmp/$name/c"
	printf '%s\n' "$asn" >"$tmp/$name/m.asn"
	out=$(cd "$tmp/$name" && "$asn1c" -S "$skel" -D c -Fgo=gen \
		"$@" m.asn 2>&1)
	rc=$?
	if [ -n "$want" ]; then
		[ $rc = 70 ] || { echo "FAIL: $name exited $rc, want 70"; fail=1; }
		echo "$out" | grep -q "asn1cgo: collision in module M: $want" || {
			echo "FAIL: $name: no collision diagnostic for $want"
			echo "$out"; fail=1; }
		[ -e "$tmp/$name/gen" ] && { echo "FAIL: $name wrote a Go tree"; fail=1; }
	else
		[ $rc = 0 ] || { echo "FAIL: $name exited $rc"; echo "$out"; fail=1; }
		echo "$out" | grep -q "collision" && { echo "FAIL: $name: false collision"; fail=1; }
	fi
}
for flags in "" "-fcompound-names"; do
	go_clash type-vs-bit "M DEFINITIONS AUTOMATIC TAGS ::= BEGIN
X ::= BIT STRING { b1(0) }
XB1 ::= INTEGER
END" "XB1 <- X.b1 (enum-const) and XB1 (type)" $flags
	go_clash bit-vs-bit "M DEFINITIONS AUTOMATIC TAGS ::= BEGIN
X ::= BIT STRING { b1(0), b-1(1) }
END" "XB1 <- X.b1 (enum-const) and X.b-1 (enum-const)" $flags
	go_clash inline-vs-type "M DEFINITIONS AUTOMATIC TAGS ::= BEGIN
T ::= SEQUENCE { m BIT STRING { b1(0) } }
TMB1 ::= INTEGER
END" "TMB1 <- T.m.b1 (enum-const) and TMB1 (type)" $flags
	go_clash alt-vs-type "M DEFINITIONS AUTOMATIC TAGS ::= BEGIN
C ::= CHOICE { a BIT STRING { b1(0) }, i INTEGER }
CAB1 ::= INTEGER
END" "CAB1 <- C.a.b1 (enum-const) and CAB1 (type)" $flags
	go_clash no-clash "M DEFINITIONS AUTOMATIC TAGS ::= BEGIN
X ::= BIT STRING { b1(0) }
XB2 ::= INTEGER
END" "" $flags
done

exit $fail
