#!/usr/bin/env bash
# Installs a database built by scripts/import_logs.pl as the live profiler
# database, replacing the one irssi uses.
#
# usage: scripts/install_db.sh [--from DIR] NETWORK [irssi-dir]
#   --from     where the import wrote it (default: build/profiler-data)
#   NETWORK    irssi server tag, e.g. EFNet
#   irssi-dir  default: ~/.irssi
#
# Run /script unload profiler in irssi first, and /script load profiler after.
# It refuses to run while any process has the live database or the import
# open. The live database runs in WAL mode, so copying over it while irssi
# holds it open leaves irssi's WAL beside the new file, and SQLite replays
# those pages into it on the next open. The old database is kept as
# <network>.sqlite.<date-time>.old, and earlier backups are deleted.
set -euo pipefail

usage() { sed -n '5,8p' "$0" | sed 's/^# \{0,1\}//'; }

repo="$(cd "$(dirname "$0")/.." && pwd)"
from="$repo/build/profiler-data"
if [[ "${1:-}" == -h || "${1:-}" == --help ]]; then
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi
if [[ "${1:-}" == --from ]]; then
    from="${2:?--from needs a directory}"
    shift 2
fi
if [[ -z "${1:-}" ]]; then
    usage >&2
    exit 1
fi

# Same file name the profiler uses (Profiler::Store::path).
name="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/_/g')"
src="$from/$name.sqlite"
data="${2:-$HOME/.irssi}/scripts/profiler-data"
dest="$data/$name.sqlite"

if [[ ! -f "$src" ]]; then
    echo "no import at $src" >&2
    exit 1
fi
if [[ -e "$src-wal" ]]; then
    echo "$src-wal exists, so the import didn't finish cleanly; run it again" >&2
    exit 1
fi

# Prints "FILE is open in pid N (NAME)" for every process holding one of the
# given files open, and fails if there were any.
check_not_open() {
    local found=0 fd target f pid
    local -A wanted=()
    for f in "$@"; do
        wanted["$(realpath -m "$f")"]="$f"
    done
    # One find for every open file on the machine; a readlink per fd is
    # thousands of processes and takes seconds.
    while IFS=$'\t' read -r target fd; do
        f="${wanted[$target]:-}"
        if [[ -n "$f" ]]; then
            pid="${fd#/proc/}"
            pid="${pid%%/*}"
            echo "$f is open in pid $pid ($(cat "/proc/$pid/comm" 2>/dev/null))" >&2
            found=1
        fi
    done < <(find /proc/[0-9]*/fd -maxdepth 1 -type l -printf '%l\t%p\n' 2>/dev/null)
    return $(( found ))
}

if ! check_not_open "$src"; then
    echo "wait for the import to finish" >&2
    exit 1
fi
if ! check_not_open "$dest" "$dest-wal" "$dest-shm"; then
    echo "run /script unload profiler in irssi first" >&2
    exit 1
fi

backup="$dest.$(date +%Y-%m-%d-%H%M%S).old"
if [[ -e "$backup" ]]; then
    echo "$backup already exists; wait a second and run it again" >&2
    exit 1
fi

mkdir -p "$data"
cp "$src" "$dest.new"
kept=""
if [[ -e "$dest" ]]; then
    mv "$dest" "$backup"
    kept="; kept the old one as $backup"
fi
rm -f "$dest-wal" "$dest-shm"
mv "$dest.new" "$dest"
# The databases are big, so only the backup we just made is worth keeping.
if [[ -n "$kept" ]]; then
    for old in "$dest".*-*.old; do
        [[ "$old" == "$backup" ]] || rm -f "$old"
    done
fi
echo "installed $dest$kept; now /script load profiler"
