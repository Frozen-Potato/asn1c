#!/bin/sh
# Fail when a build log has a C compiler warning that is not in the baseline.
# usage: check-warnings.sh <build log> <baseline>
# Lines are compared without line and column numbers ("file: warning: text"),
# and with the typographic quotes gcc prints in a UTF-8 locale made ASCII.
log=$1
base=$2
lq=$(printf '\342\200\230')
rq=$(printf '\342\200\231')
new=$(grep -E '\.c:[0-9]+:[0-9]+: warning' "$log" \
      | sed -E -e 's/:[0-9]+:[0-9]+:/:/' -e "s/$lq/'/g" -e "s/$rq/'/g" \
      | LC_ALL=C sort -u | grep -vxF -f "$base")
if [ -n "$new" ]; then
    echo "New compiler warnings (not in $base):"
    echo "$new"
    exit 1
fi
echo "No new compiler warnings."
