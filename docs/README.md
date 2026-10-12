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

Commands: `/profiler list`, `/profiler reload`, `/profiler show <nick>`,
`/profiler suspects`, `/profiler accept <nick>`, `/profiler reject <nick>`.

## Starting from your logs

`scripts/import_logs.pl` replays the joins in your irssi logs, oldest first,
through the same judging the live script uses. Each join is judged as of its
own date, so profiles, decay and quarantine come out as if the profiler had
been running all along.

    scripts/import_logs.pl --logs ~/irclogs/EFNet --network efnet
    /script unload profiler
    cp build/profiler-data/efnet.json ~/.irssi/scripts/profiler-data/
    /script load profiler

Unload the script before copying, or irssi will save its in-memory copy over
the import. `--network` must be the irssi server tag. Logs only hold nick,
ident, host, channel and time, so imported sightings have no realname, server
or version, and no host lookups are done. On a synthetic year of 182k joins it
takes under a minute and writes 24 MB. Run it with `--help` for the options.

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
3. The joiner is judged against the earlier sightings of that nick, then the
   sighting is recorded in `~/.irssi/scripts/profiler-data/<network>.json`.
   Changes are written once a minute and when the script unloads. The file
   is compact JSON, so use `jq` to read it.
4. A nick profiled in a channel isn't profiled there again for
   `profiler_recheck` seconds. Rejoin spam can't inflate trust.

## Scoring

The question is "is this really the person who has been using this nick?"
Each nick keeps a log of its last 200 sightings. Older sightings count for less
and less, losing half their weight every `profiler_half_life_days` (default 90).

Each attribute of a join scores from -1 to +1 against that history:

- **Matches:** `familiarity(weight of matching sightings)`, where familiarity
  is `w / (w + 3)`. A past sighting from the same /24 or /64 counts as half a
  match. So does one from the same dynamic ISP pool, meaning host names that
  differ only in a first label with digits in it
  (`cpe-198-51-100-202.san.res.rr.com` vs `cpe-203-0-113-17.san.res.rr.com`). So does a reply from the same client at another version (`irssi
  v1.4.5` vs `v1.4.6`).
- **Contradicts:** `-(stability × familiarity(total weight))`. Stability is
  how dominant the usual value has been. Breaking an ident used every time
  costs a lot, while a new ident from someone whose ident always changes
  costs almost nothing.
- **Missing on either side:** skipped. History imported from logs has no
  realname, server or version.
- **Host on a likely proxy:** skipped too, since many people share those.

The weights are lopsided on purpose. Ident, realname and version are visible
to anyone, so an impostor can copy them. Matching them proves little, and
failing to match is telling. A host is hard to fake.

| attribute | weight if it matches | weight if it contradicts |
|-----------|----------------------|--------------------------|
| host      | 0.40                 | 0.35                     |
| ident     | 0.10                 | 0.25                     |
| realname  | 0.10                 | 0.25                     |
| version   | 0.05                 | 0.15                     |
| server    | 0.05                 | 0.05                     |
| channel   | 0.10                 | 0.05                     |

**match** is the weighted average of the attribute scores. **confidence** is
the familiarity of the total sighting weight. **trust** is `confidence ×
match`, and that's what the rules' `min_trust` is compared to. The verdict is:

- **unknown:** confidence under 0.5, about three fresh sightings.
- **suspect:** match below 0. Always warned about, whatever the rules say. The
  sighting is quarantined: kept, but left out of the history, so an
  impostor can't train the profile. The warning notes it if the join came
  during a netsplit rejoin.
- **new host:** would be suspect, but only the host disagrees. Ident,
  realname and client (whichever we have) all match. This is usually the real
  person on another machine, a VPN or a proxy, so it gets a quiet line
  instead of a warning, like `bob: new host ~bob@x.example, ident matches
  (frequently changes hosts)`. The last part shows when the nick has used at
  least a quarter as many hosts as sightings with that ident. It's
  quarantined the same way as a suspect.
- **mixed:** match from 0 to 0.25. Typical of the real person on a new ISP,
  or a careful impostor who copied everything except the host. The two
  can't be told apart.
- **consistent:** everything above that.

Someone who really moved would otherwise stay suspect for months, since
their new host never enters the history. So when a nick's quarantined
sightings agree with each other, number at least
`profiler_promote_after_sightings` (5) over at least
`profiler_promote_after_days` (7), they're promoted: they count, and a line
says the nick has a new usual host. If the old host has stopped turning up,
that's a move and nothing else has to match. If the old host is still in
use, it's treated as a second home (work, phone, bouncer) and is promoted
only when the ident, realname and client all match the accepted history.
A troll who wears a nick while its owner keeps turning up stays quarantined
unless they copy all of those. Ident is visible in every join line, so from
logs alone a troll only has to copy that.

Quarantine needs nothing from you. When you have time, `/profiler suspects`
lists quarantined sightings. `/profiler accept <nick>` lets them count (they
really did move), and `/profiler reject <nick>` files them away.

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
    scripts/make_synthetic_logs.pl DIR    # fake logs for timing the importer
