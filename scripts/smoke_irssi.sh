#!/usr/bin/env bash
# Loads the profiler into a real irssi running in a throwaway home directory
# (no servers, no autoconnect) and checks that it loads cleanly, reads its
# rules and answers /profiler. Catches compile errors and Irssi API mistakes
# that the unit tests in tests/ cannot, since those never load irssi.
#
# usage: scripts/smoke_irssi.sh [--keep]
#   --keep  leave the temp irssi home behind and print its path
#
# Needs irssi and tmux. Prints the irssi screen only when a check fails.
set -euo pipefail

if [[ "${1:-}" == -h || "${1:-}" == --help ]]; then
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

repo="$(cd "$(dirname "$0")/.." && pwd)"
home="$(mktemp -d "${TMPDIR:-/tmp}/profiler-smoke.XXXXXX")"
session="profiler-smoke-$$"

cleanup() {
    tmux kill-session -t "$session" 2>/dev/null || true
    if [[ "${1:-}" == --keep ]]; then echo "kept $home"; else rm -rf "$home"; fi
}
trap 'cleanup "${1:-}"' EXIT

cat > "$home/config" <<'EOF'
settings = { core = { nick = "smoketest"; user_name = "smoke"; real_name = "smoke"; }; };
EOF
mkdir -p "$home/scripts"
"$repo/scripts/install.sh" "$home" > /dev/null
printf 'efnet #chan 0.5\nefnet #bad nope\nproxy acme hosting\n' > "$home/scripts/profiler.rules"

tmux new-session -d -s "$session" -x 200 -y 50 "irssi --home='$home' --noconnect"

# Waits up to 10s for a pattern on the irssi screen. irssi wraps long lines,
# such as ones holding the temp path, so patterns must stay within one piece.
wait_for() {
    for _ in $(seq 50); do
        tmux capture-pane -p -t "$session" | grep -qE "$1" && return 0
        sleep 0.2
    done
    return 1
}

fail() {
    echo "FAIL: $1"
    echo "--- irssi screen ---"
    tmux capture-pane -p -t "$session" | grep -v '^\s*$'
    exit 1
}

wait_for 'Irssi v' || fail "irssi did not start"
tmux send-keys -t "$session" "/script load profiler" Enter
wait_for 'loaded 1 watch rule' || fail "script did not load or read its rules"
wait_for "line 2: min_trust must" || fail "bad rule line not reported"
wait_for "1 extra proxy keyword" || fail "proxy keyword not counted"

tmux send-keys -t "$session" "/profiler list" Enter
wait_for 'efnet #chan 0.5' || fail "/profiler list did not show the watch"

tmux send-keys -t "$session" "/profiler show bob" Enter
wait_for 'needs an active server' || fail "/profiler show without a server"

[[ -d "$home/scripts/profiler-data" ]] || fail "data directory not created"

if tmux capture-pane -p -t "$session" | grep -qiE 'error|died|syntax|undefined subroutine'; then
    fail "errors on screen"
fi
echo "PASS: profiler loads and answers in irssi"
