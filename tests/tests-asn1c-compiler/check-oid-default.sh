#!/bin/sh

# An OBJECT IDENTIFIER / RELATIVE-OID DEFAULT that names values which cannot
# be resolved (unknown name, wrong type, a cycle) stops generation, plain C,
# with a message naming the member and the name. The accepted forms are in
# 173-default-namedbit-oid-OK.asn1.

top_srcdir="${top_srcdir:-../..}"
top_builddir="${top_builddir:-../..}"
asn1c="$(cd "${top_builddir}" && pwd)/asn1c/asn1c"
skel="$(cd "${top_srcdir}" && pwd)/skeletons"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-oid-default.XXXXXX") || exit 99
trap 'rm -rf "$tmp"' EXIT
fail=0

# bad <label> <member-regex> <name-regex> <type definitions> <member decl>
bad() {
	label=$1; memb=$2; nm=$3; defs=$4; decl=$5
	mkdir "$tmp/$label" "$tmp/$label/c"
	cat >"$tmp/$label/m.asn" <<EOT
M DEFINITIONS AUTOMATIC TAGS ::= BEGIN
$defs
T ::= SEQUENCE { $decl, z BOOLEAN }
END
EOT
	out=$(cd "$tmp/$label" && "$asn1c" -S "$skel" -D c m.asn 2>&1)
	rc=$?
	[ $rc != 0 ] || { echo "FAIL: $label accepted"; fail=1; }
	echo "$out" | grep -q -- "$memb" || {
		echo "FAIL: $label: message lacks the member"; echo "$out"; fail=1; }
	echo "$out" | grep -q -- "$nm" || {
		echo "FAIL: $label: message lacks the name"; echo "$out"; fail=1; }
}

bad unknown "DEFAULT of member u" no-such '' 'u OBJECT IDENTIFIER DEFAULT { no-such 5 }'
bad unknownref ur 'ur->no-such' '' 'ur OBJECT IDENTIFIER DEFAULT no-such'
bad cycle 'DEFAULT of member c' 'x' \
	'x OBJECT IDENTIFIER ::= { y 1 }
y OBJECT IDENTIFIER ::= { x 1 }' \
	'c OBJECT IDENTIFIER DEFAULT x'
bad cyclebrace 'DEFAULT of member cb' 'x' \
	'x OBJECT IDENTIFIER ::= { y 1 }
y OBJECT IDENTIFIER ::= { x 1 }' \
	'cb OBJECT IDENTIFIER DEFAULT { x 2 }'
bad wrongtype 'DEFAULT of member w' s 'n BOOLEAN ::= TRUE
s UTF8String ::= "a"' \
	'w OBJECT IDENTIFIER DEFAULT { 1 3 s }'
bad oidlate 'DEFAULT of member l' base 'base OBJECT IDENTIFIER ::= { 1 3 6 }' \
	'l OBJECT IDENTIFIER DEFAULT { 1 3 base }'
bad oidinrel 'DEFAULT of member r' base 'base OBJECT IDENTIFIER ::= { 1 3 6 }' \
	'r RELATIVE-OID DEFAULT { base 1 }'
bad badint 'DEFAULT of member g' 'neg' 'neg INTEGER ::= -5
b OBJECT IDENTIFIER ::= { 1 3 6 }' \
	'g OBJECT IDENTIFIER DEFAULT { b n(neg) }'
bad onearc 'DEFAULT of member o' 'two arcs' '' \
	'o OBJECT IDENTIFIER DEFAULT { 1 }'

exit $fail
