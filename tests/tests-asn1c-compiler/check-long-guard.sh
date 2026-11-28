#!/bin/sh

# The C files of the types that need constants outside the 32-bit range (PER
# bounds, value comparisons, DEFAULT and ENUMERATED values) start with a guard
# that stops the compilation where long is 32 bits (Windows). Types whose
# constants all fit get none. See 196-long-guard-OK.asn1.

top_srcdir="${top_srcdir:-../..}"
top_builddir="${top_builddir:-../..}"
asn1c="$(cd "${top_builddir}" && pwd)/asn1c/asn1c"
skel="$(cd "${top_srcdir}" && pwd)/skeletons"
src="$(cd "${top_srcdir}" && pwd)/tests/tests-asn1c-compiler/196-long-guard-OK.asn1"
cc="${CC:-cc}"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-long-guard.XXXXXX") || exit 99
trap 'rm -rf "$tmp"' EXIT
fail=0

(cd "$tmp" && mkdir c && "$asn1c" -S "$skel" -gen-PER -no-gen-OER -fcompound-names -D c "$src" >out 2>err) || {
	echo "FAIL: asn1c"; cat "$tmp/err"; exit 1; }

for t in WrapsToRange Above32 Below32 Huge Unsigned64 Dflt Enum Sz; do
	grep -q '^#if LONG_M' "$tmp/c/$t.c" || { echo "FAIL: no guard in $t.c"; fail=1; }
	grep -q '^#error ".*64-bit long' "$tmp/c/$t.c" || { echo "FAIL: no message in $t.c"; fail=1; }
done
grep -q '^#if LONG_MIN > -3000000000$' "$tmp/c/WrapsToRange.c" || { echo "FAIL: WrapsToRange.c guard"; fail=1; }
grep -q '^#if LONG_MAX < 5000000000$' "$tmp/c/Above32.c" || { echo "FAIL: Above32.c guard"; fail=1; }
grep -q '^#if LONG_MAX < 9223372036854775807$' "$tmp/c/Huge.c" || { echo "FAIL: Huge.c guard"; fail=1; }
grep -q '^#if LONG_MAX < 9223372036854775807$' "$tmp/c/Unsigned64.c" || { echo "FAIL: Unsigned64.c guard"; fail=1; }
if grep -q 'LONG_M' "$tmp/c/Narrow.c"; then echo "FAIL: guard in Narrow.c"; fail=1; fi

# Where long has 64 bits the guard compiles away; with a 32-bit LONG_MAX
# (gcc and clang take __LONG_MAX__ from the command line) it must stop.
printf '#include <limits.h>\nint a[LONG_MAX == 2147483647L ? 1 : -1];\n' >"$tmp/probe.c"
if (cd "$tmp" && $cc -fsyntax-only -D__LONG_MAX__=2147483647L probe.c) >/dev/null 2>&1; then
	for t in WrapsToRange Above32 Below32 Huge Unsigned64 Dflt Enum Sz; do
		if (cd "$tmp/c" && $cc -E -I. -I"$skel" -D__LONG_MAX__=2147483647L -DASN_DISABLE_OER_SUPPORT "$t.c") >/dev/null 2>"$tmp/err.$t"; then
			echo "FAIL: $t.c has no effect with a 32-bit long"; fail=1
		elif ! grep -q '64-bit long' "$tmp/err.$t"; then
			echo "FAIL: $t.c: unexpected error"; cat "$tmp/err.$t"; fail=1
		fi
	done
	if ! (cd "$tmp/c" && $cc -E -I. -I"$skel" -D__LONG_MAX__=2147483647L -DASN_DISABLE_OER_SUPPORT Narrow.c) >/dev/null 2>"$tmp/err.n"; then
		echo "FAIL: Narrow.c does not preprocess with a 32-bit long"; cat "$tmp/err.n"; fail=1
	fi
else
	echo "note: this compiler does not take __LONG_MAX__ from the command line; preprocessing check skipped"
fi

[ $fail = 0 ] || exit 1
echo "OK"
