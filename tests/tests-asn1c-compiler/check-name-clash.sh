#!/bin/sh

# A real name clash must fail the run even with -fcompound-names, and a
# false one (the same declaration synthesized twice) must not be reported.

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

exit $fail
