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
`/profiler nicks <nick>`, `/profiler judge <nick>`, `/profiler suspects`,
`/profiler accept <nick>`, `/profiler reject <nick>`, `/profiler good <nick>`,
`/profiler neutral <nick>`, `/profiler bad <nick>`,
`/profiler unlabel <nick>`. `/profiler -h` says
what each does. `/profiler judge` is for someone whose join has scrolled
away: it looks them up as if they'd just joined the channel in the active
window (or any channel they're in) and always prints the line, with the
same coloured word, but records nothing. It sends them a CTCP VERSION, as a
join does. `/profiler
nicks` lists everything behind "changes nicks often, also ... and 8 more",
with when they first and last switched.

## Starting from your logs

`scripts/import_logs.pl` replays the joins in your irssi logs, oldest first,
through the same judging the live script uses. Each join is judged as of its
own date, so profiles, decay and quarantine come out as if the profiler had
been running all along.

    scripts/import_logs.pl --logs ~/irclogs/EFNet --network efnet
    /script unload profiler
    scripts/install_db.sh efnet
    /script load profiler

`install_db.sh` refuses to run while irssi still has the database open. A
plain `cp` over an open database leaves irssi's write-ahead log beside the new
file, and SQLite replays it into the new file, which corrupts it. The old
database is kept as `efnet.sqlite.<date-time>.old`, and backups from earlier
installs are deleted, since the databases are big. Installing an import
that's already installed does nothing. Installing a different one deletes the
previous backup, so copy a backup somewhere else first if you need it to
survive.
The import also records kicks and bans (see below). For a file imported
before that, `scripts/backfill_marks.pl --logs ~/irclogs/EFNet
~/.irssi/scripts/profiler-data/efnet.sqlite` adds just those, and can run
while irssi has the file open.

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
   the client is recorded as `(no reply)`. If the WHOIS hasn't ended within
   `profiler_whois_timeout` seconds (default 60), say because the server went
   away mid-reply, the join is judged on what it gave us. `/profiler list`
   shows how many lookups are still waiting. Once both are in, the joiner's host is resolved
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

- **Matches:** `familiarity(weight of matching sightings) /
  familiarity(total weight)`, where familiarity is `w / (w + 3)`. A value
  used every time scores 1 whether there are 3 sightings or 300. A past sighting from the same /24 or /64 counts as half a
  match. So does one from the same dynamic ISP pool, meaning host names that
  differ only in a first label with digits in it
  (`cpe-198-51-100-202.san.res.rr.com` vs `cpe-203-0-113-17.san.res.rr.com`).
  So does any other generated name from the same ISP
  (`56.sub-198-51-100.myvzw.com` vs `226.sub-203-0-113.myvzw.com`), since
  mobile and residential ISPs hand out addresses from all over. Bare
  addresses (IPv4 or IPv6 with no name) are compared by who whois says
  they belong to, the organisation or else the AS, which live sightings
  keep as their provider. When the organisation is only the regional
  registry that handed the address out, like RIPE NCC, the AS is used. So does a reply from the same client at another version (`irssi
  v1.4.5` vs `v1.4.6`).
- **Contradicts:** `-stability`. Stability is
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
ahead of its domain, or labels like `dsl`, `dhcp`, `pool`, `cable`, `dyn`)
or a bare address can be had by anyone on the same ISP. IRCCloud's
`id-NNN.<server>.irccloud.com` is an account number, so it's the same
person whichever IRCCloud server they come through. When the host is just
`<server>.irccloud.com`, the account comes from the `uidNNN` or `sidNNN`
ident, which IRCCloud sets and users can't. `uid` is the free tier and
`sid` a subscription, so `uid100001` and `sid100001` count as the same
ident. The account is all that counts for an IRCCloud host: everyone on
a server shares its name and addresses, so two accounts on
`hampstead.irccloud.com` are two people. A private address
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

**match** is the weighted average of the attribute scores, with each weight
also multiplied by the familiarity of that attribute's total weight. Imported
history has no realname, server or version, so those come from a few live
sightings, and they count for less than an ident seen hundreds of times.
**confidence** is the familiarity of the total sighting weight. **trust** is
`confidence × match`, and that's what the rules' `min_trust` is compared to.
A perfect match has trust equal to its confidence: 0.5 at about three recent
sightings, 0.77 at ten, 0.87 at twenty. Unknown
nicks are left out of that comparison, since their confidence keeps their
trust under 0.5 anyway. The verdict is:

- **unknown:** confidence under 0.5, about three fresh sightings. If what
  little history there is disagrees (match below 0) on ident, realname or
  client, the join is a WARNING and quarantined like a suspect. A new host
  alone isn't enough, or a newcomer on a dynamic IP would never build up
  a history. That's how someone looks who
  picked up a nick nobody has used for years, since old sightings count
  for almost nothing.
- **suspect:** match below 0, with at least one of host, ident, realname or
  client contradicting. If only channel or server disagree, it's mixed
  instead. Suspects are always warned about, whatever the rules say. The
  sighting is quarantined: kept, but left out of the history, so an
  impostor can't train the profile. The warning notes it if the join came
  during a netsplit rejoin.

  A join from an ISP-generated name is also suspect, however well the rest
  matches, when the nick has used ISPs before but never this one (the ISP
  is the registered domain, like `myvzw.com` or `telia.it`). People stick
  with their home and mobile ISPs, so a new one is what a residential proxy
  network looks like. The warning says `from an ISP they've never used,
  telia.it, usually myvzw.com`. Bare addresses work the same way with
  their provider, once the nick has live sightings with providers. A
  domain is only compared with a domain and a provider with a provider,
  and a join from a likely proxy is left out, since a VPN is nobody's home
  ISP. Someone who really changed ISP is held as
  suspect until the move is promoted, about a week of joins. A nick that
  has only used its own server or bare addresses has no usual ISP to
  leave, so this doesn't apply.
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
  can't be told apart. A contradicted ident, realname or client is mixed
  however well the rest matches, since that can be a second person on the
  same shell box.
- **consistent:** everything above that.

Someone who really moved would otherwise stay suspect for months, since
their new host never enters the history. So when a nick's quarantined
sightings agree with each other on the host, or on an ident the nick never
had (someone new on a dynamic address), number at least
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
consistent or mixed, it's added to the join's own line after a second word,
VARIANT, in green for consistent and cyan for mixed:

    UNKNOWN VARIANT Sneezy_ (~Sneezy@203.0.113.195, client: (no reply)) has trust +0.00 (unknown, match +0.00, confidence 0.00); never seen before; looks like Sneezy: host, ident, realname, client match; trust +0.34 against their history

When the join gets no line of its own (a quiet consistent join), the
variant comes alone:

    VARIANT bob_ looks like bob, who they've switched nicks with before: host, ident match; trust +0.71 against their history

This doesn't change the joiner's own verdict or what's recorded.

A nick change in a watched channel is profiled like a join under the new
nick, since `/nick bob` is the easy way to wear bob's nick without joining
as it. Its verdict line is always shown, verbose or not, and says
`was <old nick>`. When someone on the nick has switched with at least two
other nicks, any verdict line about them adds `changes nicks often, also
zed, lex, lexie` (latest first, up to three).

## Kicks, bans and evaders

Trolls get kicked and banned far more than regulars, so kicks and bans in
watched channels are recorded, live and from the logs. They're kept apart
from trust, which only asks whether a join is the usual person behind its
nick.

- **Who it hit.** Anyone can wear a nick, so each kick or ban keeps the
  ident and host of whoever had the nick. For a kick that's the nick's
  latest sighting (irssi only gives the kicker's address). A ban is matched
  to the people in the channel whose nick!ident@host fits the mask (live)
  or who joined in the week before it (logs). A ban fitting more than three
  nicks is too broad to say who it was for. Lifted bans are ignored, since
  bans get lifted to keep the list short.
- **How much it counts.** A ban counts 1 and a kick 0.5, and both fade on
  `profiler_half_life_days`. Bans fade too since bots kick whoever an op
  bans. A record counts from 0.25: a ban within the last two half-lives,
  or a kick within the last one. Only kicks and bans from the channel being
  joined count, and not ones someone set on themselves.
- **On the nick's own line.** A nick whose record counts always gets its
  line, ending with something like `banned 1x, kicked 2x, last 2026-09-02
  by alice (shamed)`. `/profiler show <nick>` lists the whole record,
  every channel included, and who each one hit.
- **EVADER.** Every join is compared with the people whose record counts,
  under any other nick. Ones sharing the ident or a related host (same
  address, subnet, ISP pool or ISP, or a custom name) with a kick or ban
  are judged against that person: the nick's sightings that look like the
  one who was hit, plus the kicks and bans themselves. Trolls are often
  kicked after a join or two, so the match alone decides: at least 0.25, as
  for a consistent verdict, from a host that matches or two of ident,
  realname and client. An ident alone isn't enough, and on a proxy the
  host isn't judged, so a proxy join needs two of the others. Channel and
  server are left out, since everybody here shares them. A different
  ident rules someone out unless they came from the very same host or
  IRCCloud account: a troll who's been banned a lot has used enough
  addresses that strangers on the same ISPs come close. A kick or ban
  stops counting once whoever it hit came back on that nick, since the
  ban was lifted or never stuck. A nick
  that's CONFIDENT on its own history is only an evader of a kick or ban
  from before we first saw it: a regular who later gets banned under
  another nick isn't evading with the one they already had. That gives a
  line like `EVADER n3wguy
  (~lol@cpe-1-2-9-9.res.example.net) looks like trollguy (kicked 1x, last
  ...): host, ident match; match +0.80 against them`. A common ident on a
  big ISP can match a stranger, so read what matched.
- **JUPER.** Juping is sitting on someone's nick so they can't have it,
  and they end up waiting on a variant like `bob_`. When a join on a
  variant nick is CONFIDENT against that nick's history (and over the
  channel's min_trust), whoever holds the nick now gets a WHOIS and
  VERSION, at most once per `profiler_recheck`. If their ident, realname
  or client disagrees with the nick's history, and the match is below 0,
  that's a jupe: `JUPER bob (lol@troll.example.org, client: mIRC v7.77) is
  sitting on bob's nick while bob_, who fits bob's history, waits: ident,
  client don't match; match -1.00 against bob. Remembered as a juper`.
  Lots of people run two clients, so bob on bob with his usual ident,
  realname and client, from any host, is left alone. A jupe is remembered
  like a ban, with the same weight, and the EVADER search uses it, so the
  juper gets a JUPER line instead of EVADER when they join again on any
  nick. `/profiler show` lists it as `juped 1x, last ... while bob_
  waited`.

## Labels

The scoring can't know what the ops have decided about someone, so you can
tell it: `/profiler good <nick>`, `/profiler neutral <nick>` or
`/profiler bad <nick>`, and `/profiler unlabel <nick>` to take it away. A
label leads every line about that person's joins, as `-=( GOOD )=-` in
green, `-=( NEUTRAL )=-` in white or `-=( BAD )=-` in red, and changes
nothing else: the verdict, EVADER and the rest are worked out as usual.

A label only shows when the join comes from where the nick connects, since
without that it could be anyone wearing the nick: the same host, address or
IRCCloud account, or a nearby address or the same ISP with the ident they
had there, like the next dynamic address from their provider. BAD also
follows the person onto other nicks, matched the same way as EVADER, and the
line ends with `labelled BAD as <nick>`.

When a join gets GOOD or NEUTRAL from its own nick but also looks like
someone labelled BAD, it's `-=( CONFLICTING )=-` in orange (irssi's dark
yellow), ending `labelled GOOD as bob and BAD as trolluser`. Maybe somebody
sat on bob's nick from bob's ISP and copied his ident, or maybe a BAD label
is out of date. The script can't tell, so sort it out from the logs and
change the labels. BAD and CONFLICTING joins always get a line, even when
they'd otherwise be quiet.

Labels are kept by a rescore, but not by importing the logs again.

## Output

Lines are drawn in your theme's `{channick}` colour, the one irssi uses for
a nick that parts or quits (dark cyan by default). Every line about
someone starts with a one-word summary in its own colour:

| word      | colour        | means |
|-----------|---------------|-------|
| WARNING   | bright red    | under the channel's min_trust with something against them, or on a likely proxy that's new for them |
| EVADER    | bright red    | looks like someone who was kicked or banned, under another nick |
| JUPER     | purple        | sitting on a nick its owner is waiting for, or looks like someone caught doing that |
| UNPROVEN  | bright purple | under the channel's min_trust, but everything matches: just not much history yet |
| SUSPECT   | bright yellow | doesn't match the nick's history |
| MIXED     | bright cyan   | partly matches |
| CONFIDENT | bright green  | consistent with the nick's history |
| NEW HOST  | grey          | only the host is new |
| UNKNOWN   | grey          | too little history to say |
| VARIANT   | bright green or cyan | looks like a related nick, and fits its history (green) or partly (cyan) |
| MOVED     | grey          | held sightings promoted to a new usual host |

CONFIDENT, MIXED and UNKNOWN lines show with `profiler_verbose` on, or for
a nick change. A nick never seen before joining from a bare address (no
reverse DNS) always gets an UNKNOWN line saying so, since that's how a lot
of trolls on proxies turn up. A join from a likely proxy the nick hasn't been seen on
before always gets one line. It says WARNING in place of any word but
SUSPECT, and still gives the verdict. A proxy they're always on is probably
their own server, so it's treated like any other host. A new address from a
provider they've used before, like another exit of their VPN, isn't a
warning either, but the line still says it's a likely proxy, adding "a
provider they've used before". To change a colour, override the format in your theme, for
example:

    "perl/profiler" = { profiler_suspect = "{channick profiler:} %MSUSPECT%n {channick $0}"; };

The formats are `profiler_line` for status messages and `profiler_<word>`
(lowercase, `_` for the space) for the rest. A variant's word is
`variant_consistent` or `variant_mixed`, and a line with two words uses
both, as in `profiler_unknown_variant_consistent`. A label (see Labels) goes
in front, as in `profiler_bad_evader`.

## Limits

- Proxy detection is keyword matching on registry records. It misses VPNs that
  rent space from ordinary ISPs and can flag small businesses with "hosting"
  in their name, or a carrier on a cloud provider's addresses, like Boost
  Mobile on Amazon's. Add `proxy <keyword>` lines to catch more, and
  `notproxy <phrase>` lines to clear records with that phrase.
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
