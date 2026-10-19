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
    grep -qE "$colour$word" <<< "$line" || fail "$word is not in its colour"
    grep -qE $'\e\\[(22;)?36m'" ?smoke $word line" <<< "$line" || fail "text after $word is not dark cyan"
}
bright() { echo $'(\e\\[1m\e\\[3'"$1"$'m|\e\\[9'"$1"$'m)'; }
grey=$'\e\\[(22;)?37m'
check_word WARNING "$(bright 1)"
check_word UNPROVEN "$(bright 5)"
check_word EVADER "$(bright 1)"
check_word SUSPECT "$(bright 3)"
check_word MIXED "$(bright 6)"
check_word CONFIDENT "$(bright 2)"
check_word 'NEW HOST' "$grey"
check_word UNKNOWN "$grey"
check_word MOVED "$grey"

# A variant gets a second word after the verdict's, coloured by how well the
# join fits the other nick's history, or comes alone.
check_words() {
    local first="$1" first_colour="$2" variant="$3" colour="$4" line
    tmux send-keys -t "$session" "/script exec Irssi::Script::profiler::say_in(undef, undef, 'smoke $variant pair', $first 'VARIANT $variant')" Enter
    wait_for "VARIANT smoke $variant pair" || fail "$variant variant line not printed"
    line="$(tmux capture-pane -p -e -t "$session" | grep "smoke $variant pair" | tail -1)"
    grep -qE "${first_colour}VARIANT" <<< "$line" || fail "VARIANT is not after the verdict word"
    grep -qE "${colour}VARIANT" <<< "$line" || fail "$variant VARIANT is not in its colour"
    grep -qE $'\e\\[(22;)?36m'" ?smoke $variant pair" <<< "$line" || fail "text after VARIANT is not dark cyan"
}
check_words "'UNKNOWN'," "UNKNOWN.*" consistent "$(bright 2)"
check_words '' '' mixed "$(bright 6)"

# Perl errors end in a newline, which irssi prints as an empty line.
# The text avoids the word "error", which the last check looks for.
tmux send-keys -t "$session" '/script exec Irssi::Script::profiler::info("smoke oops line" . chr(10)); Irssi::Script::profiler::info("smoke after oops")' Enter
wait_for 'smoke after oops' || fail "oops lines not printed"
[[ "$(tmux capture-pane -p -t "$session" | grep -A1 'smoke oops line' | tail -1)" == *'smoke after oops'* ]] \
    || fail "an error's trailing newline printed an empty line"

tmux send-keys -t "$session" "/profiler list" Enter
wait_for 'efnet #chan 0.5' || fail "/profiler list did not show the watch"
tmux send-keys -t "$session" "/profiler -h" Enter
wait_for 'nicks <nick>' || fail "/profiler -h did not show usage"
tmux send-keys -t "$session" '/script exec my $s = Profiler::Store->new(Irssi::Script::profiler::irssi_path("profiler_data_dir", "profiler-data")); $s->link_nicks("efnet", "smokea", "smokeb", 1700000000); $s->flush; Irssi::Script::profiler::cmd_profiler("nicks smokea", bless({ tag => "efnet" }, "SmokeServer"))' Enter
wait_for 'smokeb +first 2023-11-1[45], last 2023-11-1[45]' || fail "/profiler nicks did not list the nicks with dates"

# /profiler judge looks at someone already in a channel. It always gets a
# line, even one that a join would keep quiet, and records nothing.
tmux send-keys -t "$session" '/script exec package SmokeServer; sub channels { () } package main; Irssi::Script::profiler::cmd_profiler("judge smokegone", bless({ tag => "efnet" }, "SmokeServer"))' Enter
wait_for "smokegone isn't in any channel on efnet" || fail "/profiler judge did not say the nick isn't here"
tmux send-keys -t "$session" '/script exec Irssi::Script::profiler::judge({ tag => "efnet", channel => "#chan", nick => "smokecheck", ident => "~c", host => "check.example", version => "smoke", check => 1 }, {}); Irssi::Script::profiler::cmd_profiler("show smokecheck", bless({ tag => "efnet" }, "SmokeServer"))' Enter
wait_for 'UNKNOWN smokecheck' || fail "a check of someone present printed no line"
wait_for 'no profile for smokecheck' || fail "a check of someone present was recorded"

# A WHOIS whose end never comes (say the server went away mid-reply) must
# not leave the nick waiting for good. The fake server swallows everything.
tmux send-keys -t "$session" "/set profiler_version_timeout 1" Enter
tmux send-keys -t "$session" "/set profiler_whois_timeout 3" Enter
tmux send-keys -t "$session" '/script exec package SmokeServer; sub redirect_event {} sub send_raw {} package main; Irssi::Script::profiler::send_whois(bless({ tag => "smoke" }, "SmokeServer"), { tag => "smoke", channel => "#chan", nick => "stuckbob", ident => "~bob", host => "192.168.0.1" })' Enter
tmux send-keys -t "$session" "/profiler list" Enter
wait_for '1 lookup\(s\) waiting' || fail "the stuck lookup is not listed"
# Past the VERSION timeout but not the WHOIS one, it's still waiting.
sleep 2
tmux send-keys -t "$session" "/profiler list" Enter
sleep 0.5
[[ "$(tmux capture-pane -p -t "$session" | grep -c '1 lookup(s) waiting')" == 2 ]] \
    || fail "the lookup stopped waiting at the VERSION timeout"
sleep 2
tmux send-keys -t "$session" "/profiler list" Enter
wait_for '0 lookup\(s\) waiting' || fail "the stuck lookup never gave up"

# Kicks and bans in a watched channel are recorded, and /profiler show lists
# them even for a nick never seen joining. Fake server and channel objects
# stand in for a real network.
tmux send-keys -t "$session" '/script exec package SmokeServer; package SmokeChannel; sub nicks { ({ nick => "smoketroll", host => "~t\@smoke.example" }) } package main; our $s = bless({ tag => "efnet" }, "SmokeServer"); Irssi::Script::profiler::on_kick($s, "#CHAN", "smoketroll", "smokeop", "o\@op.example", "smoke reason"); Irssi::Script::profiler::on_ban_new(bless({ name => "#chan", server => $s }, "SmokeChannel"), { ban => "*!*\@smoke.example", setby => "smokeop!o\@op.example", time => 1700000000 }); Irssi::Script::profiler::cmd_profiler("show smoketroll", $s)' Enter
wait_for 'banned 1x, kicked 1x' || fail "kicks and bans not recorded or not shown"

# A regular who later gets banned under another nick isn't evading with the
# nick they already had. A nick that shows up after the ban is. Verbose, so
# the CONFIDENT line is printed.
judge_as() {
    echo "Irssi::Script::profiler::judge({ tag => \"efnet\", channel => \"#chan\", nick => \"$1\", ident => \"~o\", host => \"old.example\", version => \"smoke\" }, {})"
}
tmux send-keys -t "$session" "/set profiler_verbose on" Enter
tmux send-keys -t "$session" "/script exec $(judge_as smokeregular) for 1 .. 4" Enter
# The ban has to come after the regular's first join and before the next.
sleep 2
tmux send-keys -t "$session" '/script exec package SmokeChannel; sub nicks { ({ nick => "smokeold", host => "~o\@old.example" }) } package main; Irssi::Script::profiler::on_ban_new(bless({ name => "#chan", server => bless({ tag => "efnet" }, "SmokeServer") }, "SmokeChannel"), { ban => "*!*\@old.example", setby => "smokeop!o\@op.example", time => time - 1 })' Enter
tmux send-keys -t "$session" "/script exec $(judge_as smokeregular); Irssi::Script::profiler::info('smoke after regular')" Enter
wait_for 'smoke after regular' || fail "the regular's joins were not judged"
before="$(tmux capture-pane -p -t "$session" | grep -B4 'smoke after regular')"
grep -q 'CONFIDENT smokeregular' <<< "$before" || fail "the regular never became confident"
grep -q 'EVADER smokeregular' <<< "$before" && fail "a regular known since before the ban is an evader"
tmux send-keys -t "$session" "/script exec $(judge_as smokenewbie)" Enter
wait_for 'EVADER smokenewbie' || fail "a new nick like someone banned is not an evader"

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
