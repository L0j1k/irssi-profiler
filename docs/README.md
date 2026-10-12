# profiler

An irssi script that builds a trust profile of everyone who joins a watched
channel and prints a local warning when a joiner looks unfamiliar or comes from
a likely VPN, proxy or hosting address. Nothing is sent to the channel. The
script sends one WHOIS to the server, and the joiner gets one CTCP VERSION
request.

## Install

    scripts/install.sh            # into ~/.irssi
    /script load profiler         # inside irssi

Rules live in `~/.irssi/scripts/profiler.rules`. See
`config/profiler.rules.example` for the format. Run `/profiler reload` after
editing.

Commands: `/profiler list`, `/profiler reload`, `/profiler show <nick>`.

## What happens on a join

1. The join goes into a per-server whois queue. The queue sends at most one
   WHOIS plus CTCP VERSION every `profiler_whois_interval` seconds. If `profiler_burst_joins`
   joins land within `profiler_burst_window` seconds (a netsplit rejoin), it
   pauses for `profiler_burst_pause` seconds after the last join of the
   burst, then drains at the normal rate.
2. The WHOIS reply gives realname and server. The VERSION reply gives the
   client. If nothing comes back within `profiler_version_timeout` seconds,
   the client is recorded as `(no reply)`. Once both are in, the joiner's host is resolved
   and run through the system `whois` in a child process. The registry record
   is checked for VPN/proxy/Tor/hosting keywords. Results are cached per host
   for `profiler_hostinfo_max_age` seconds.
3. The joiner is scored against the earlier sightings of that nick, then the
   sighting is recorded in `~/.irssi/scripts/profiler-data/<network>.json`.
4. A nick profiled in a channel isn't profiled there again for
   `profiler_recheck` seconds. Rejoin spam can't inflate trust.

## Scoring

Trust is a weighted average of how familiar each attribute is:

| attribute | weight |
|-----------|--------|
| host      | 0.30   |
| ident     | 0.20   |
| realname  | 0.20   |
| channel   | 0.10   |
| server    | 0.10   |
| version   | 0.10   |

Familiarity is `count / (count + 3)`: seen 3 times scores 0.5, 9 times 0.75,
and it never quite reaches 1. For the host, a past sighting from the same /24
(IPv4) or /64 (IPv6) counts as half a sighting. A host flagged as a likely
proxy earns no host credit at all. For the version, a past reply from the same
client (the first word, so `irssi v1.4.5` and `irssi v1.4.6` match) counts as
half a sighting. Version weighs little because it's trivial to fake.

## Limits

- Proxy detection is keyword matching on registry records. It misses VPNs that
  rent space from ordinary ISPs and can flag small businesses with "hosting"
  in their name. Add `proxy <keyword>` lines to tune it.
- Cloaked hosts (`user/bob`) can't be resolved, so they get no subnet or
  proxy check.
- Profiles are keyed by nick. Someone who changes nick starts from zero.

## Tests

    prove tests/                          # unit tests
    PROFILER_LIVE_TESTS=1 prove tests/    # also runs a real whois lookup
    scripts/smoke_irssi.sh                # loads the script into a real irssi
