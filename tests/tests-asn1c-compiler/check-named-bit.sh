#!/bin/sh

# Go backend (-Fgo) half of check-167: a named-bit BIT STRING maps like a
# plain one (BitString / *BitString) and adds a block of `int` bit-position
# constants, named like the constants of an ENUMERATED in the same position.
# The forms that stay unsupported are refused with a clear message (exit 70,
# nothing written). The C half is tests-c-compiler/check-src/check-167.*.

top_srcdir="${top_srcdir:-../..}"
top_builddir="${top_builddir:-../..}"
asn1c="$(cd "${top_builddir}" && pwd)/asn1c/asn1c"
skel="$(cd "${top_srcdir}" && pwd)/skeletons"
srcdir_t="$(cd "${top_srcdir}" && pwd)/tests/tests-asn1c-compiler"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-named-bit.XXXXXX") || exit 99
trap 'rm -rf "$tmp"' EXIT
fail=0

# 1. The accepted module.
mkdir "$tmp/ok" "$tmp/ok/c"
out=$(cd "$tmp/ok" && "$asn1c" -S "$skel" -fcompound-names -D c -Fgo=gen \
	"$srcdir_t/167-named-bit-string-OK.asn1" 2>&1)
rc=$?
[ $rc = 0 ] || { echo "FAIL: 167 exited $rc"; echo "$out"; fail=1; }
types=$(ls "$tmp"/ok/gen/*/types.go 2>/dev/null)
[ -n "$types" ] || { echo "FAIL: no types.go written"; fail=1; }

want() {
	grep -q -- "$1" $types || { echo "FAIL: types.go lacks: $1"; fail=1; }
}
# Value type unchanged: plain BitString, pointer when OPTIONAL / CHOICE alt.
want '^type Caps BitString$'
want '^type Fixed BitString$'
want '^type Open BitString$'
want '^type List \[\]Caps$'
want '^	Opt  \*BitString$'
want '^	Flags   \*BitString$'
want '^	Named   \*Caps$'
# One block per defining type, declaration order, `int`, comment on top.
want '^// bit positions of Caps$'
want '^	CapsC int = 7$'
want '^	CapsA int = 0$'
want '^	CapsB int = 3$'
want '^	FixedLo int = 0$'
want '^	RangedQ int = 2$'
want '^	OpenQ int = 2$'
# Inline member and CHOICE alternative: named as an inline ENUMERATED would be.
want '^// bit positions of Holder.opt$'
want '^	HolderOptX int = 1$'
want '^	HolderOptY int = 4$'
want '^	SelectorFlagsOn  int = 0$'
want '^	SelectorFlagsOff int = 1$'
# The unnamed alternative and the refining alias get no constants.
grep -q 'SelectorPlain\|NarrowLo\|NarrowHi' $types && {
	echo "FAIL: constants for an unnamed alternative or an alias"; fail=1; }
[ "$(grep -c 'int = ' $types)" = 13 ] || {
	echo "FAIL: expected 13 bit constants, got $(grep -c 'int = ' $types)"; fail=1; }
# Order inside a block is declaration order, not bit order.
[ "$(grep -A5 'bit positions of Caps$' $types | grep -o 'Caps[A-Z]' | tr -d '\n')" = CapsCCapsACapsB ] || {
	echo "FAIL: Caps bits not in declaration order"; fail=1; }
if command -v gofmt >/dev/null 2>&1; then
	[ -z "$(gofmt -l $types)" ] || { echo "FAIL: types.go not gofmt-clean"; fail=1; }
fi

# 2. Refused forms: exit 70, the diagnostic names module, type and member,
#    no Go tree. $4 = "after-c": the refusal comes from the naming pass, after
#    the C pass (like the inline ENUMERATED one), so the C tree exists.
refuse() {
	name=$1; asn=$2; want=$3; when=${4:-}
	mkdir "$tmp/$name" "$tmp/$name/c"
	printf '%s\n' "$asn" >"$tmp/$name/m.asn"
	out=$(cd "$tmp/$name" && "$asn1c" -S "$skel" -D c -Fgo=gen m.asn 2>&1)
	rc=$?
	[ $rc = 70 ] || { echo "FAIL: $name exited $rc, want 70"; fail=1; }
	echo "$out" | grep -q -- "$want" || {
		echo "FAIL: $name: no diagnostic matching: $want"; echo "$out"; fail=1; }
	[ -e "$tmp/$name/gen" ] && { echo "FAIL: $name wrote a Go tree"; fail=1; }
	if [ "$when" != after-c ] && [ -n "$(ls -A "$tmp/$name/c")" ]; then
		echo "FAIL: $name wrote the C tree"; fail=1
	fi
}
# DEFAULT of a named-bit BIT STRING, in every value form the parser allows
# (the C generator emits no default callbacks for any of them).
refuse default-list "M DEFINITIONS AUTOMATIC TAGS ::= BEGIN
T ::= SEQUENCE { d BIT STRING { a(0), b(1) } DEFAULT { a } }
END" 'asn1cgo: DEFAULT member T.d is out of model in module M: DEFAULT of a named-bit BIT STRING is not supported'
refuse default-bstring "M DEFINITIONS AUTOMATIC TAGS ::= BEGIN
T ::= SEQUENCE { d BIT STRING { a(0), b(1) } DEFAULT '01'B }
END" 'asn1cgo: DEFAULT member T.d is out of model in module M: DEFAULT of a named-bit BIT STRING is not supported'
refuse default-ref "M DEFINITIONS AUTOMATIC TAGS ::= BEGIN
C ::= BIT STRING { a(0), b(1) }
T ::= SEQUENCE { d C DEFAULT '01'B }
END" 'asn1cgo: DEFAULT member T.d is out of model in module M: DEFAULT of a named-bit BIT STRING is not supported'

# 3. An inline named-bit element of a SEQUENCE OF: a plain BitString slice
#    element, the bit constants named after the C backend's synthesized
#    element (<Owner>Member), here for a top-level type and for a member.
mkdir "$tmp/seqof" "$tmp/seqof/c"
cat >"$tmp/seqof/m.asn" <<'EOF'
M DEFINITIONS AUTOMATIC TAGS ::= BEGIN
L ::= SEQUENCE OF BIT STRING { a(0), b(5) }
H ::= SEQUENCE { m SEQUENCE OF BIT STRING { c(1) }, f BOOLEAN }
END
EOF
out=$(cd "$tmp/seqof" && "$asn1c" -S "$skel" -D c -Fgo=gen m.asn 2>&1)
rc=$?
[ $rc = 0 ] || { echo "FAIL: seqof-inline exited $rc"; echo "$out"; fail=1; }
types=$(ls "$tmp"/seqof/gen/*/types.go 2>/dev/null)
[ -n "$types" ] || { echo "FAIL: seqof-inline wrote no types.go"; fail=1; }
want '^type L \[\]BitString$'
want '^	LMemberA int = 0$'
want '^	LMemberB int = 5$'
want '^type HM \[\]BitString$'
want '^	HMMemberC int = 1$'

exit $fail
