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
printf 'efnet #chan 0.5\nefnet #bad 50%%n\nproxy acme hosting\n' > "$home/scripts/profiler.rules"

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
wait_for "got '50%n'" || fail "a % in a message was taken as a colour code"
wait_for "1 extra proxy keyword" || fail "proxy keyword not counted"
# Our lines use the theme's {channick}, dark cyan (36) in the default theme.
tmux capture-pane -p -e -t "$session" | grep 'loaded 1 watch rule' | grep -q $'\e\\[36m' \
    || fail "profiler lines are not dark cyan"

# Verdict words get their own colour and the rest of the line stays dark
# cyan. Bright colours come out as bold plus the colour (1 and 3x) or as 9x.
check_word() {
    local word="$1" colour="$2" line
    tmux send-keys -t "$session" "/script exec Irssi::Script::profiler::say_in(undef, undef, 'smoke $word line', '$word')" Enter
    wait_for "$word smoke $word line" || fail "$word line not printed"
    line="$(tmux capture-pane -p -e -t "$session" | grep "smoke $word line" | tail -1)"
    grep -qE $'(\e\\[1m\e\\[3'"$colour"$'m|\e\\[9'"$colour"$'m)'"$word" <<< "$line" || fail "$word is not bright colour $colour"
    grep -qE $'\e\\[(22;)?36m'" ?smoke $word line" <<< "$line" || fail "text after $word is not dark cyan"
}
check_word WARNING 1
check_word SUSPECT 3
check_word MIXED 6
check_word CONFIDENT 2

tmux send-keys -t "$session" "/profiler list" Enter
wait_for 'efnet #chan 0.5' || fail "/profiler list did not show the watch"

tmux send-keys -t "$session" "/profiler show bob" Enter
wait_for 'needs an active server' || fail "/profiler show without a server"

[[ -d "$home/scripts/profiler-data" ]] || fail "data directory not created"

tmux send-keys -t "$session" "/script unload profiler" Enter
wait_for 'Unloaded script profiler' || fail "script did not unload"

# An upgrade is install.sh then a reload in the same irssi, so a changed
# module must be picked up rather than the copy perl already has in memory.
echo 'our $SMOKE_UPGRADED = "yes"; 1;' >> "$home/scripts/profiler-lib/Profiler/Score.pm"
tmux send-keys -t "$session" "/script load profiler" Enter
wait_for 'Loaded script profiler' || fail "script did not load again"
tmux send-keys -t "$session" '/script exec Irssi::print("upgraded=" . ($Profiler::Score::SMOKE_UPGRADED // "no"))' Enter
wait_for 'upgraded=(yes|no)' || fail "could not ask irssi which module is loaded"
wait_for 'upgraded=yes' || fail "reload kept the old modules"
tmux send-keys -t "$session" "/script unload profiler" Enter

if tmux capture-pane -p -t "$session" | grep -qiE 'error|died|syntax|undefined subroutine|redefined'; then
    fail "errors on screen"
fi
echo "PASS: profiler loads and answers in irssi"
