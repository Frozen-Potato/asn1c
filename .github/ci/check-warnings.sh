#!/bin/sh
# Fail when a build log has a C compiler warning that is not in the baseline.
# usage: check-warnings.sh <build log> <baseline>
# Lines are compared without line and column numbers ("file: warning: text").
log=$1
base=$2
new=$(grep -E '\.c:[0-9]+:[0-9]+: warning' "$log" \
      | sed -E 's/:[0-9]+:[0-9]+:/:/' | sort -u | grep -vxF -f "$base")
if [ -n "$new" ]; then
    echo "New compiler warnings (not in $base):"
    echo "$new"
    exit 1
fi
echo "No new compiler warnings."
