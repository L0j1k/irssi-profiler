#!/usr/bin/env bash
# Saves the raw `whois` output for an IP as a test fixture, so the parser and
# proxy classifier are tested against real registry records.
#
# usage: scripts/capture_whois_fixture.sh <ip> <fixture-name>
#   writes tests/fixtures/whois-<fixture-name>.txt
set -euo pipefail

if [[ $# -ne 2 || "$1" == -h || "$1" == --help ]]; then
    sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi

ip=$1
name=$2
out="$(dirname "$0")/../tests/fixtures/whois-$name.txt"

if ! timeout 30 whois "$ip" > "$out.tmp" 2> "$out.err"; then
    echo "whois $ip failed:" >&2
    cat "$out.err" >&2
    rm -f "$out.tmp" "$out.err"
    exit 1
fi
rm -f "$out.err"
mv "$out.tmp" "$out"
echo "wrote $out ($(wc -l < "$out") lines)"
