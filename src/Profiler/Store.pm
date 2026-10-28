package Profiler::Store;

use strict;
use warnings;

use DBI;
use List::Util qw(min max sum0);

use Profiler::Nick;
use Profiler::Score;

# One SQLite database per network in the data directory, holding every
# sighting ever recorded and the cached host lookups. Scoring only needs a
# nick's latest sightings, so those are loaded the first time the nick comes
# up and kept in memory after that, with every change written through to the
# database.
#
# A sighting judged "suspect" or "new host" is quarantined (see
# Profiler::Score::held for the rest): kept for the
# record but left out of the history its nick is judged against, so an
# impostor can't train the profile toward themselves. /profiler accept or
# reject marks it reviewed.
#
# Changes are made inside a transaction that flush() commits. The live script
# flushes after every join. The importer flushes once a month of logs, since
# committing a million times would be slow.

# Observation fields kept in each sighting. Missing ones are stored as NULL
# and left out when loaded.
my @FIELDS = qw(host ip ident realname server version channel proxy provider ports banners);

my @HOSTINFO_FIELDS = qw(ip netname org origin proxy error ports banners);

# How many of a nick's latest sightings a profile holds for scoring. Older
# ones stay in the database.
our $HISTORY_SIZE = 200;

# Kicks and bans, one row per nick they were matched to, with the ident and
# host that had the nick then, since an impostor wearing bob's nick can get
# kicked too. A ban that matched nobody we could name keeps its mask with no
# nick. Seeing the same one
# again (a log read twice, a ban list synced on every join) is ignored.
my @MARKS_SCHEMA = (
    'CREATE TABLE IF NOT EXISTS marks (
        id       INTEGER PRIMARY KEY,
        kind     TEXT NOT NULL,
        nick_key TEXT,
        nick     TEXT,
        ident    TEXT,
        host     TEXT,
        channel  TEXT NOT NULL,
        mask     TEXT,
        by       TEXT,
        reason   TEXT,
        time     INTEGER NOT NULL
    )',
    'CREATE INDEX IF NOT EXISTS marks_by_nick ON marks (nick_key)',
    "CREATE UNIQUE INDEX IF NOT EXISTS marks_once ON marks (kind, channel, time, ifnull(nick_key, ''), ifnull(mask, ''))",
);

# What you said about a nick with /profiler good, neutral or bad (see
# Profiler::Label), one per nick.
my @LABELS_SCHEMA = (
    'CREATE TABLE IF NOT EXISTS labels (
        nick_key TEXT PRIMARY KEY,
        nick     TEXT NOT NULL,
        label    TEXT NOT NULL,
        time     INTEGER NOT NULL
    )',
);

my @SCHEMA = (
    'CREATE TABLE IF NOT EXISTS sightings (
        id          INTEGER PRIMARY KEY,
        nick        TEXT NOT NULL,
        nick_key    TEXT NOT NULL,
        time        INTEGER NOT NULL,
        host TEXT, ip TEXT, ident TEXT, realname TEXT, server TEXT,
        version TEXT, channel TEXT, proxy TEXT,
        -- who the address belongs to, from whois (Profiler::Whois::provider)
        provider TEXT,
        -- the open ports we knocked on (Profiler::Probe::signature), and the
        -- banners they sent, kept for review but not scored
        ports TEXT, banners TEXT,
        verdict     TEXT NOT NULL,
        quarantined INTEGER NOT NULL DEFAULT 0,
        reviewed    INTEGER NOT NULL DEFAULT 0,
        promoted    INTEGER
    )',
    'CREATE INDEX IF NOT EXISTS sightings_by_nick ON sightings (nick_key, time)',
    'CREATE INDEX IF NOT EXISTS sightings_waiting ON sightings (time)
        WHERE quarantined = 1 AND reviewed = 0',
    'CREATE TABLE IF NOT EXISTS hostinfo (
        host    TEXT PRIMARY KEY,
        checked INTEGER NOT NULL,
        ip TEXT, netname TEXT, org TEXT, origin TEXT, proxy TEXT, error TEXT,
        ports TEXT, banners TEXT
    )',
    # Every nick we've recorded, with its skeleton (see Profiler::Nick), for
    # finding variants like bob_ and B0B`.
    'CREATE TABLE IF NOT EXISTS nicks (
        nick_key TEXT PRIMARY KEY,
        skeleton TEXT NOT NULL
    )',
    'CREATE INDEX IF NOT EXISTS nicks_by_skeleton ON nicks (skeleton)',
    # Pairs of nicks someone switched between with /nick. Stored once per
    # pair with a < b, since the link works both ways.
    'CREATE TABLE IF NOT EXISTS nick_links (
        a          TEXT NOT NULL,
        b          TEXT NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen  INTEGER NOT NULL,
        PRIMARY KEY (a, b)
    )',
    'CREATE INDEX IF NOT EXISTS nick_links_by_b ON nick_links (b)',
    @MARKS_SCHEMA,
    @LABELS_SCHEMA,
);

# Stored in the database as PRAGMA user_version. Bump it whenever the schema
# changes, and add the steps from the old version to %UPGRADE if the old
# data still fits. A version with no steps is refused and gets re-imported.
our $SCHEMA_VERSION = 6;
my %UPGRADE = (
    2 => \@MARKS_SCHEMA,
    3 => ['ALTER TABLE sightings ADD COLUMN provider TEXT'],
    4 => \@LABELS_SCHEMA,
    5 => [
        'ALTER TABLE sightings ADD COLUMN ports TEXT',
        'ALTER TABLE sightings ADD COLUMN banners TEXT',
        'ALTER TABLE hostinfo ADD COLUMN ports TEXT',
        'ALTER TABLE hostinfo ADD COLUMN banners TEXT',
    ],
);

sub new {
    my ($class, $dir) = @_;
    return bless { dir => $dir, dbs => {}, broken => {}, profiles => {} }, $class;
}

sub path {
    my ($self, $network) = @_;
    (my $name = lc $network) =~ s/[^a-z0-9._-]/_/g;
    return "$self->{dir}/$name.sqlite";
}

# The network's database handle. Returns undef if there's no database yet,
# unless $create is set, so just looking something up never makes a file.
# Dies if the file exists but isn't a usable database. The network stays
# marked broken so later calls die too and nothing ever writes to the file.
sub db {
    my ($self, $network, $create) = @_;
    my $key = lc $network;
    die $self->{broken}{$key} if $self->{broken}{$key};
    return $self->{dbs}{$key} if $self->{dbs}{$key};

    my $path = $self->path($network);
    return undef unless $create || -e $path;
    my $dbh = eval {
        my $dbh = DBI->connect("dbi:SQLite:dbname=$path", '', '',
            # DBD::SQLite starts transactions with BEGIN IMMEDIATE by default,
            # which takes the write lock even to read. Deferred lets a reader
            # in while another process holds the write lock.
            { RaiseError => 1, PrintError => 0, AutoCommit => 1, sqlite_use_immediate_transaction => 0 });
        # NORMAL skips the fsync on each commit, which is what keeps a commit
        # per join cheap. A power cut can lose the last few commits.
        $dbh->do('PRAGMA synchronous = NORMAL');
        # Setting up needs a write lock, so it's only done on a new file.
        # Otherwise a reader would wait on whoever is writing. WAL is stored
        # in the file and lets the sqlite3 command or the diagnostic read
        # while irssi or the importer writes.
        my ($version) = $dbh->selectrow_array('PRAGMA user_version');
        my ($tables) = $dbh->selectrow_array("SELECT count(*) FROM sqlite_master WHERE type = 'table'");
        if (!$tables) {
            $dbh->do('PRAGMA journal_mode = WAL');
            $dbh->do($_) for @SCHEMA;
            $dbh->do("PRAGMA user_version = $SCHEMA_VERSION");
            $version = $SCHEMA_VERSION;
        }
        else {
            # One version at a time, each in a transaction with its new
            # version number, so an upgrade cut short picks up where it was.
            while ($version < $SCHEMA_VERSION && $UPGRADE{$version}) {
                $dbh->begin_work;
                $dbh->do($_) for @{ $UPGRADE{$version} };
                $version++;
                $dbh->do("PRAGMA user_version = $version");
                $dbh->commit;
            }
        }
        if ($version != $SCHEMA_VERSION) {
            my $which = $version < $SCHEMA_VERSION ? 'an older' : 'a newer';
            die "it was made by $which version of the profiler (schema $version, need $SCHEMA_VERSION);"
                . " move it aside and run the import again\n";
        }
        $dbh->{AutoCommit} = 0;
        $dbh;
    };
    if (!$dbh) {
        (my $err = $@) =~ s/\s+$//;
        $self->{broken}{$key} = "cannot open $path: $err\n";
        die $self->{broken}{$key};
    }
    return $self->{dbs}{$key} = $dbh;
}

sub sighting_from_row {
    my ($row) = @_;
    delete @$row{qw(nick nick_key)};
    delete $row->{$_} for grep { !defined $row->{$_} } keys %$row;
    return $row;
}

# A nick's profile: { nick, first_seen, last_seen, total, sightings => [...] }
# with the latest $HISTORY_SIZE sightings, oldest first. total counts every
# sighting ever recorded. Undef if never seen.
sub profile {
    my ($self, $network, $nick) = @_;
    my $key = lc $nick;
    my $cache = $self->{profiles}{ lc $network } //= {};
    return $cache->{$key} if $cache->{$key};

    my $dbh = $self->db($network) or return undef;
    my $rows = $dbh->selectall_arrayref(
        'SELECT * FROM sightings WHERE nick_key = ? ORDER BY time DESC, id DESC LIMIT ?',
        { Slice => {} }, $key, $HISTORY_SIZE);
    return undef unless @$rows;

    my ($first_seen, $total) = $dbh->selectrow_array('SELECT MIN(time), COUNT(*) FROM sightings WHERE nick_key = ?', undef, $key);
    # Copied out before sighting_from_row strips the nick from the rows.
    my ($display, $last_seen) = @{ $rows->[0] }{qw(nick time)};
    my @sightings = map { sighting_from_row($_) } reverse @$rows;
    return $cache->{$key} = {
        nick       => $display,
        first_seen => $first_seen,
        last_seen  => $last_seen,
        total      => $total,
        sightings  => \@sightings,
    };
}

# A nick's profile pooled with the nicks it has switched to or from (see
# links), the same shape as profile() but covering every nick we know to be
# the same person. So someone who reconnects as bob_ and bob__ is judged on
# everything they've done, not on each fragment alone. Nicks are tied only by
# an observed /nick change, so this never folds in a stranger. Returns the
# plain profile when there are no links, and undef when the nick is unknown
# and has none.
sub pooled_profile {
    my ($self, $network, $nick) = @_;
    my @links = $self->links($network, $nick);
    my $own = $self->profile($network, $nick);
    return $own unless @links;

    my @profiles = grep { defined } $own, map { $self->profile($network, $_->{nick}) } @links;
    return $own unless @profiles;

    # Each profile already holds its nick's latest $HISTORY_SIZE, so merging
    # them and keeping the latest $HISTORY_SIZE gives the person's latest.
    my @all = sort { $a->{time} <=> $b->{time} || ($a->{id} // 0) <=> ($b->{id} // 0) }
        map { @{ $_->{sightings} } } @profiles;
    splice @all, 0, @all - $HISTORY_SIZE if @all > $HISTORY_SIZE;

    return {
        nick       => $own ? $own->{nick} : $profiles[0]{nick},
        first_seen => min(map { $_->{first_seen} } @profiles),
        last_seen  => max(map { $_->{last_seen} } @profiles),
        total      => sum0(map { $_->{total} } @profiles),
        sightings  => \@all,
    };
}

sub record {
    my ($self, $network, $obs, $now, $verdict, $match, $parts) = @_;
    my $dbh = $self->db($network, 1);
    my $p = $self->profile($network, $obs->{nick});
    if (!$p) {
        $p = { first_seen => $now, total => 0, sightings => [] };
        $self->{profiles}{ lc $network }{ lc $obs->{nick} } = $p;
    }

    my %sighting = map { defined $obs->{$_} ? ($_ => $obs->{$_}) : () } @FIELDS;
    $sighting{channel} = lc $sighting{channel} if defined $sighting{channel};
    $sighting{time} = $now;
    $sighting{verdict} = $verdict;
    $sighting{quarantined} = Profiler::Score::held($verdict, $match, $parts) ? 1 : 0;
    $sighting{reviewed} = 0;

    my @columns = ('time', 'verdict', 'quarantined', @FIELDS);
    my $insert = $dbh->prepare_cached('INSERT INTO sightings (nick, nick_key, ' . join(', ', @columns)
        . ') VALUES (?, ?' . ', ?' x @columns . ')');
    # map rather than a hash slice: sub arguments are aliases, so a slice
    # would add the missing fields to %sighting as undef.
    $insert->execute($obs->{nick}, lc $obs->{nick}, map { $sighting{$_} } @columns);
    $sighting{id} = $dbh->sqlite_last_insert_rowid;
    $dbh->prepare_cached('INSERT OR IGNORE INTO nicks (nick_key, skeleton) VALUES (?, ?)')
        ->execute(lc $obs->{nick}, Profiler::Nick::skeleton($obs->{nick}));

    $p->{nick} = $obs->{nick};
    $p->{last_seen} = $now;
    $p->{total}++;
    push @{ $p->{sightings} }, \%sighting;
    splice @{ $p->{sightings} }, 0, @{ $p->{sightings} } - $HISTORY_SIZE
        if @{ $p->{sightings} } > $HISTORY_SIZE;
    return $p;
}

# Fields /profiler query can search: the nick and the observation columns.
our @SEARCHABLE = ('nick', @FIELDS);

# Turns a shell-style glob (* and ?) into a SQL LIKE pattern. The LIKE
# wildcards and the escape character in the glob are escaped first, so only
# the * and ? the user typed act as wildcards.
sub glob_to_like {
    my ($glob) = @_;
    (my $like = $glob) =~ s/([\\%_])/\\$1/g;
    $like =~ s/\*/%/g;
    $like =~ s/\?/_/g;
    return $like;
}

# Sightings whose $field matches the glob $pattern, newest first, each as
# { nick => ..., sighting => ... }, like suspects(). Matching is
# case-insensitive (SQLite LIKE). Returns ($total, @rows): $total is how many
# matched in all, and @rows is one page of at most $limit of them, skipping
# the first $offset, for paging through a big result. Dies if $field isn't
# searchable.
sub search {
    my ($self, $network, $field, $pattern, $limit, $offset) = @_;
    die "can't search '$field'; try one of: @SEARCHABLE\n" unless grep { $_ eq $field } @SEARCHABLE;
    my $dbh = $self->db($network) or return (0);
    # $field is from the whitelist above, so it's safe to put in the SQL.
    my $where = "$field LIKE ? ESCAPE '\\'";
    my $like = glob_to_like($pattern);
    my ($total) = $dbh->selectrow_array("SELECT COUNT(*) FROM sightings WHERE $where", undef, $like);
    my $rows = $dbh->selectall_arrayref("SELECT * FROM sightings WHERE $where ORDER BY time DESC, id DESC LIMIT ? OFFSET ?",
        { Slice => {} }, $like, $limit, $offset // 0);
    return ($total, map { my $nick = $_->{nick}; { nick => $nick, sighting => sighting_from_row($_) } } @$rows);
}

# Quarantined sightings nobody has looked at yet, oldest first, each as
# { nick => ..., sighting => ... }.
sub suspects {
    my ($self, $network) = @_;
    my $dbh = $self->db($network) or return ();
    my $rows = $dbh->selectall_arrayref(
        'SELECT * FROM sightings WHERE quarantined = 1 AND reviewed = 0 ORDER BY time, id', { Slice => {} });
    return map { my $nick = $_->{nick}; { nick => $nick, sighting => sighting_from_row($_) } } @$rows;
}

# Let a nick's unreviewed suspect sightings count after all, say because they
# really did move. Returns how many changed.
sub accept {
    my ($self, $network, $nick) = @_;
    return $self->review($network, $nick, 0);
}

# Agree that a nick's unreviewed suspect sightings were someone else.
sub reject {
    my ($self, $network, $nick) = @_;
    return $self->review($network, $nick, 1);
}

# Works on the database, so it reaches sightings too old to be in the
# profile, then brings the profile in memory up to date.
sub review {
    my ($self, $network, $nick, $quarantined) = @_;
    my $dbh = $self->db($network) or return 0;
    my $changed = $dbh->do('UPDATE sightings SET quarantined = ?, reviewed = 1
        WHERE nick_key = ? AND quarantined = 1 AND reviewed = 0', undef, $quarantined, lc $nick);

    my $p = $self->{profiles}{ lc $network }{ lc $nick };
    for my $s (grep { $_->{quarantined} && !$_->{reviewed} } @{ $p ? $p->{sightings} : [] }) {
        $s->{quarantined} = $quarantined;
        $s->{reviewed} = 1;
    }
    return $changed + 0;
}

# Marks one sighting reviewed by hand, held ($quarantined 1) or counted (0).
sub set_reviewed {
    my ($self, $network, $sighting, $quarantined) = @_;
    $self->db($network)->prepare_cached('UPDATE sightings SET quarantined = ?, reviewed = 1 WHERE id = ?')
        ->execute($quarantined, $sighting->{id});
    $sighting->{quarantined} = $quarantined;
    $sighting->{reviewed} = 1;
}

# If the nick's quarantined sightings look like they moved rather than like
# an impostor (see Profiler::Score::promotable), let them count. They are
# marked promoted, so a later look at the data can tell them apart from
# hand-accepted ones. Returns the promoted sightings, oldest first.
sub promote_if_moved {
    my ($self, $network, $nick, $now, $min_count, $min_days) = @_;
    my $p = $self->profile($network, $nick) or return ();
    my @moved = Profiler::Score::promotable($p, $min_count, $min_days);
    return () unless @moved;

    my $sth = $self->db($network)->prepare_cached(
        'UPDATE sightings SET quarantined = 0, reviewed = 1, promoted = ? WHERE id = ?');
    for my $s (@moved) {
        $s->{quarantined} = 0;
        $s->{reviewed} = 1;
        $s->{promoted} = $now;
        $sth->execute($now, $s->{id});
    }
    return @moved;
}

# Someone went from one nick to the other with /nick, so both are the same
# person. Repeats just move last_seen along.
sub link_nicks {
    my ($self, $network, $old, $new, $now) = @_;
    my ($first, $second) = sort(lc $old, lc $new);
    return if $first eq $second;
    $self->db($network, 1)->prepare_cached('INSERT INTO nick_links (a, b, first_seen, last_seen) VALUES (?, ?, ?, ?)
        ON CONFLICT (a, b) DO UPDATE SET last_seen = excluded.last_seen')->execute($first, $second, $now, $now);
}

# Someone was kicked. $kick is { nick, ident, host, channel, by, reason },
# with ident and host undef if we don't know who had the nick.
sub record_kick {
    my ($self, $network, $kick, $time) = @_;
    $self->insert_mark($network, 'kick', { %$kick, mask => undef }, $time);
}

# A ban was set. $ban is { channel, mask, by }, and @who are the
# { nick, ident, host } it was matched to (see Profiler::Marks::banned), if
# anyone.
sub record_ban {
    my ($self, $network, $ban, $time, @who) = @_;
    $self->insert_mark($network, 'ban', { %$ban, %$_, reason => undef }, $time) for @who ? @who : ({});
}

# Someone was juping a nick (see Profiler::Jupe). $jupe is { nick, ident,
# host, channel, by }: the nick and whoever sat on it, the channel where its
# owner turned up on a variant, and the variant they waited on.
sub record_jupe {
    my ($self, $network, $jupe, $time) = @_;
    $self->insert_mark($network, 'jupe', { %$jupe, mask => undef, reason => undef }, $time);
}

sub insert_mark {
    my ($self, $network, $kind, $mark, $time) = @_;
    my $nick = $mark->{nick};
    my $added = $self->db($network, 1)->prepare_cached('INSERT OR IGNORE INTO marks
        (kind, nick_key, nick, ident, host, channel, mask, by, reason, time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
        ->execute($kind, defined $nick ? lc $nick : undef, $nick, @$mark{qw(ident host)},
        lc $mark->{channel}, @$mark{qw(mask by reason)}, $time);
    my $cache = $self->{marks}{ lc $network };
    if ($cache && defined $nick && $added > 0) {
        push @{ $cache->{ lc $nick } }, { kind => $kind, time => $time, channel => lc $mark->{channel},
            map { $_ => $mark->{$_} } qw(ident host mask by reason) };
    }
}

# Every kicked or banned nick's marks, as { <nick key> => [ marks oldest
# first, as from marks() ] }. Loaded once and kept up to date, since the
# evasion search looks through them on every join.
sub all_marks {
    my ($self, $network) = @_;
    my $key = lc $network;
    return $self->{marks}{$key} if $self->{marks}{$key};
    my $dbh = $self->db($network) or return {};
    my %by_nick;
    my $rows = $dbh->selectall_arrayref('SELECT nick_key, kind, ident, host, channel, mask, by, reason, time FROM marks
        WHERE nick_key IS NOT NULL ORDER BY time, id', { Slice => {} });
    push @{ $by_nick{ delete $_->{nick_key} } }, $_ for @$rows;
    return $self->{marks}{$key} = \%by_nick;
}

# A nick's kicks and bans, oldest first, each as { kind, ident, host,
# channel, mask, by, reason, time }.
sub marks {
    my ($self, $network, $nick) = @_;
    my $dbh = $self->db($network) or return ();
    return @{ $dbh->selectall_arrayref('SELECT kind, ident, host, channel, mask, by, reason, time FROM marks
        WHERE nick_key = ? ORDER BY time, id', { Slice => {} }, lc $nick) };
}

# Every nick that has been kicked or banned, sorted.
sub marked {
    my ($self, $network) = @_;
    my $dbh = $self->db($network) or return ();
    return @{ $dbh->selectcol_arrayref('SELECT DISTINCT nick_key FROM marks WHERE nick_key IS NOT NULL ORDER BY 1') };
}

# The nicks this one has been linked to directly, most recently used first.
sub linked {
    my ($self, $network, $nick) = @_;
    return map { $_->{nick} } $self->links($network, $nick);
}

# The same, each as { nick, first_seen, last_seen }: when someone first and
# last switched between the two.
sub links {
    my ($self, $network, $nick) = @_;
    my $dbh = $self->db($network) or return ();
    # Cached because pooled_profile calls this for every join, live and on
    # import, so re-parsing the SQL each time would add up over a long replay.
    my $sth = $dbh->prepare_cached('SELECT b AS nick, first_seen, last_seen FROM nick_links WHERE a = ?
        UNION ALL SELECT a, first_seen, last_seen FROM nick_links WHERE b = ? ORDER BY 3 DESC, 1');
    $sth->execute(lc $nick, lc $nick);
    return @{ $sth->fetchall_arrayref({}) };
}

# Recorded nicks with the same skeleton as this one, other than itself, sorted.
sub similar {
    my ($self, $network, $nick) = @_;
    my $dbh = $self->db($network) or return ();
    return @{ $dbh->selectcol_arrayref('SELECT nick_key FROM nicks WHERE skeleton = ? AND nick_key != ? ORDER BY nick_key',
        undef, Profiler::Nick::skeleton($nick), lc $nick) };
}

# Gives a nick a label (good, neutral or bad), replacing any it had, or takes
# it away when $label is undef. Returns how many labels changed.
sub set_label {
    my ($self, $network, $nick, $label, $time) = @_;
    my $dbh = $self->db($network, 1);
    return $dbh->do('DELETE FROM labels WHERE nick_key = ?', undef, lc $nick) + 0 unless defined $label;
    return $dbh->do('INSERT OR REPLACE INTO labels (nick_key, nick, label, time) VALUES (?, ?, ?, ?)',
        undef, lc $nick, $nick, $label, $time) + 0;
}

# A nick's label, or undef.
sub label {
    my ($self, $network, $nick) = @_;
    my $dbh = $self->db($network) or return undef;
    return scalar $dbh->selectrow_array('SELECT label FROM labels WHERE nick_key = ?', undef, lc $nick);
}

# Every nick with this label, sorted.
sub labelled {
    my ($self, $network, $label) = @_;
    my $dbh = $self->db($network) or return ();
    return @{ $dbh->selectcol_arrayref('SELECT nick_key FROM labels WHERE label = ? ORDER BY 1', undef, $label) };
}

sub set_hostinfo {
    my ($self, $network, $host, $info, $now) = @_;
    $self->db($network, 1)->do('INSERT OR REPLACE INTO hostinfo (host, checked, ' . join(', ', @HOSTINFO_FIELDS)
        . ') VALUES (?, ?' . ', ?' x @HOSTINFO_FIELDS . ')', undef, $host, $now, @$info{@HOSTINFO_FIELDS});
}

# The cached lookup for a host if it is younger than max_age seconds.
sub fresh_hostinfo {
    my ($self, $network, $host, $now, $max_age) = @_;
    my $dbh = $self->db($network) or return undef;
    my $info = $dbh->selectrow_hashref('SELECT * FROM hostinfo WHERE host = ?', undef, $host) or return undef;
    delete $info->{host};
    return $now - $info->{checked} <= $max_age ? $info : undef;
}

# Every sighting of every nick, oldest first, shaped as
# { users => { <lowercased nick> => { nick, sightings => [...] } } }.
# This reads the whole database into memory, so it's for offline tools like
# the suspect diagnostic, not for irssi.
sub all_profiles {
    my ($self, $network) = @_;
    my %users;
    my $dbh = $self->db($network) or return { users => {} };
    my $sth = $dbh->prepare('SELECT * FROM sightings ORDER BY nick_key, time, id');
    $sth->execute;
    while (my $row = $sth->fetchrow_hashref) {
        my $p = $users{ $row->{nick_key} } //= { sightings => [] };
        $p->{nick} = $row->{nick};
        push @{ $p->{sightings} }, sighting_from_row({ %$row });
    }
    return { users => \%users };
}

# Commits whatever changed on every network.
sub flush {
    my ($self) = @_;
    $_->commit for values %{ $self->{dbs} };
}

sub close {
    my ($self) = @_;
    $self->flush;
    $_->disconnect for values %{ $self->{dbs} };
    $self->{dbs} = {};
    $self->{profiles} = {};
}

# A store that goes away without close() still commits what it has, rather
# than DBI rolling it back with a warning.
sub DESTROY {
    my ($self) = @_;
    local $@;
    eval { $self->close };
}

1;
