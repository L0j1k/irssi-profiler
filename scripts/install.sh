#!/usr/bin/env bash
# Installs the profiler into an irssi home directory.
#
# usage: scripts/install.sh [irssi-dir]     (default: ~/.irssi)
#
# Copies src/profiler.pl to <irssi-dir>/scripts/ and the Profiler modules to
# <irssi-dir>/scripts/profiler-lib/. Copies the example rules to
# <irssi-dir>/scripts/profiler.rules only if no rules file exists yet. Then,
# inside irssi: /script load profiler
set -euo pipefail

if [[ "${1:-}" == -h || "${1:-}" == --help ]]; then
    sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

repo="$(cd "$(dirname "$0")/.." && pwd)"
home="${1:-$HOME/.irssi}"
scripts="$home/scripts"

if [[ ! -d "$home" ]]; then
    echo "no irssi directory at $home" >&2
    exit 1
fi

mkdir -p "$scripts/profiler-lib/Profiler"
cp "$repo/src/profiler.pl" "$scripts/profiler.pl"
cp "$repo"/src/Profiler/*.pm "$scripts/profiler-lib/Profiler/"
echo "installed profiler.pl and modules into $scripts"

if [[ -e "$scripts/profiler.rules" ]]; then
    echo "kept existing $scripts/profiler.rules"
else
    cp "$repo/config/profiler.rules.example" "$scripts/profiler.rules"
    echo "wrote example rules to $scripts/profiler.rules"
fi
