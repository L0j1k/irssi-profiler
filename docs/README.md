# profiler

An irssi script that builds a trust profile of everyone who joins a watched
channel and prints a local warning when a joiner looks unfamiliar or comes from
a likely VPN, proxy or hosting address. Nothing is sent to the channel. The
script sends one WHOIS to the server, and the joiner gets one CTCP VERSION
request.

## Install

    scripts/install.sh            # into ~/.irssi
    /script load profiler         # inside irssi

Needs DBD::SQLite and NetAddr::IP (Debian: libdbd-sqlite3-perl,
libnetaddr-ip-perl) and the system `whois`.

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
    cp build/profiler-data/efnet.sqlite ~/.irssi/scripts/profiler-data/
    /script load profiler

Unload the script before copying, since irssi keeps the database open.
`--network` must be the irssi server tag. Logs only hold nick, ident, host,
channel and time, so imported sightings have no realname, server or version,
and no host lookups are done. On a synthetic year of 182k joins it takes
about 80 seconds and writes 20 MB. Run it with `--help` for the options.

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
   sighting is recorded in the SQLite database
   `~/.irssi/scripts/profiler-data/<network>.sqlite`, committed straight
   away. The `sqlite3` command can read it while irssi is running.
4. A nick profiled in a channel isn't profiled there again for
   `profiler_recheck` seconds. Rejoin spam can't inflate trust.

## Scoring

The question is "is this really the person who has been using this nick?"
Every sighting is kept, and a nick is judged against its latest 200. Older sightings count for less
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
- **Host on a likely proxy:** skipped too, since many people share those,
  unless it has a custom name or is an IRCCloud account (below).

Host names come in kinds. IRC servers only show a name that resolves back
to the address, so a name somebody chose, like `irc.example.net`, means
they control that DNS. That's close to impossible to fake. An ISP's
generated name (`cpe-198-51-100-202...`, anything with four or more digits
in its first label, or labels like `dsl`, `dhcp`, `pool`, `cable`, `dyn`)
or a bare address can be had by anyone on the same ISP. IRCCloud's
`id-NNN.<server>.irccloud.com` is an account number, so it's the same
person whichever IRCCloud server they come through. When the host is just
`<server>.irccloud.com`, the account comes from the `uidNNN` or `sidNNN`
ident, which IRCCloud sets and users can't. `uid` is the free tier and
`sid` a subscription, so `uid100001` and `sid100001` count as the same
ident. A private address
like `192.168.0.1` (10/8, 172.16/12, 192.168/16, 127/8, IPv6 fc00::/7,
fe80::/10, ::1) is a spoof: nobody can really connect from one, so a
server admin gave it to them.

When a nick that has used a custom name, IRCCloud account or spoof before
turns up on it again, the host match counts for 2 instead of 0.40, but
only if that raises the match. A solid host used once, long ago, never
lowers it. That makes a regular consistent even if nothing else is known
and the channel is new. It doesn't apply when the ident disagrees, since a
shell provider can give several people the same name but not the same
ident. These hosts are judged even on a hosting company's address.

The "seen N time(s) before" in a verdict counts every sighting of the
nick. Scoring only looks at the latest 200, and the line says so when
there are more.

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
match`, and that's what the rules' `min_trust` is compared to. Unknown
nicks are left out of that comparison, since their confidence keeps their
trust under 0.5 anyway. The verdict is:

- **unknown:** confidence under 0.5, about three fresh sightings.
- **suspect:** match below 0, with at least one of host, ident, realname or
  client contradicting. If only channel or server disagree, it's mixed
  instead. Suspects are always warned about, whatever the rules say. The
  sighting is quarantined: kept, but left out of the history, so an
  impostor can't train the profile. The warning notes it if the join came
  during a netsplit rejoin.
- **new host:** would be suspect, but the host is what disagrees, and none
  of ident, realname or client does. Channel and server don't count. Ident,
  realname and client (whichever we have) all match. This is usually the real
  person on another machine, a VPN or a proxy, so it gets a quiet line
  instead of a warning, like `NEW HOST bob (~bob@x.example): ident matches
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

## Nick variants

On EFnet a juped nick sends people to bob_, bobbb or B0B`. When a joiner's
own verdict is unknown or suspect, the profiler also compares them with two
kinds of related nick:

- **Linked nicks:** ones they've switched to or from with /nick, in your
  logs or live. A nick change is the same connection, so it's proof. Only
  direct links count, so a generic nick like "away" can't chain strangers
  together.
- **Same skeleton:** the nick lowercased, with `|suffix` dropped, junk
  (`_` `` ` `` `^` `-` `|` brackets) stripped from the ends and digits from
  the end, leet digits read as letters, and repeated letters collapsed.
  bob_, bobbb, B0B`, bob2 and [bob] are all `bob`. bobby isn't.

Each candidate (at most 20) is judged on host and ident like any other
join. The nick only picks who to compare with. If the best one comes out
consistent or mixed you get a line like:

    VARIANT bob_ looks like bob, who they've switched nicks with before: host, ident match; trust +0.71 against their history

This doesn't change the joiner's own verdict or what's recorded.

A nick change in a watched channel is profiled like a join under the new
nick, since `/nick bob` is the easy way to wear bob's nick without joining
as it. Its verdict line is always shown, verbose or not, and says
`was <old nick>`. When someone on the nick has switched with at least two
other nicks, any verdict line about them adds `changes nicks often, also
zed, lex, lexie` (latest first, up to three).

## Output

Lines are drawn in your theme's `{channick}` colour, the one irssi uses for
a nick that parts or quits (dark cyan by default). Every line about
someone starts with a one-word summary in its own colour:

| word      | colour        | means |
|-----------|---------------|-------|
| WARNING   | bright red    | under the channel's min_trust, or on a likely proxy |
| SUSPECT   | bright yellow | doesn't match the nick's history |
| MIXED     | bright cyan   | partly matches |
| CONFIDENT | bright green  | consistent with the nick's history |
| NEW HOST  | grey          | only the host is new |
| UNKNOWN   | grey          | too little history to say |
| VARIANT   | grey          | looks like a related nick |
| MOVED     | grey          | held sightings promoted to a new usual host |

CONFIDENT, MIXED and UNKNOWN lines show with `profiler_verbose` on, or for
a nick change. A join from a likely proxy always gets one line. It says
WARNING in place of any word but SUSPECT, and still gives the verdict. To change a colour, override the format in your theme, for
example:

    "perl/profiler" = { profiler_suspect = "{channick profiler:} %MSUSPECT%n {channick $0}"; };

The formats are `profiler_line` for status messages and `profiler_<word>`
(lowercase, `_` for the space) for the rest.

## Limits

- Proxy detection is keyword matching on registry records. It misses VPNs that
  rent space from ordinary ISPs and can flag small businesses with "hosting"
  in their name. Add `proxy <keyword>` lines to tune it.
- Cloaked hosts (`user/bob`) can't be resolved, so they get no subnet or
  proxy check.
- Profiles are keyed by nick. A variant nick gets its own profile from
  zero, and the variant search (above) is what connects it to the usual one.
- The variant search only looks one nick change away, and only at nicks
  whose skeleton matches. bob → robert → rob finds robert from bob, not rob.

## Tests

    prove tests/                          # unit tests
    PROFILER_LIVE_TESTS=1 prove tests/    # also runs a real whois lookup
    scripts/smoke_irssi.sh                # loads the script into a real irssi
    scripts/make_synthetic_logs.pl DIR    # fake logs for timing the importer
