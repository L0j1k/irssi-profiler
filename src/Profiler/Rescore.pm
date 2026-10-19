package Profiler::Rescore;

use strict;
use warnings;

use DBI;
# Loaded here for OPEN_READONLY, which DBI would only load at connect.
use DBD::SQLite;

use Profiler::Import;
use Profiler::Store;
use Profiler::Whois;

# Builds a new data file from an old one by judging every stored sighting
# again, oldest first, with the current scoring. That's what to run after a
# scoring change, instead of importing the logs again, since it keeps what
# only the live script saw: realname, server, version, ip and proxy, and
# sightings from after the logs.
#
# Nick links, cached host lookups, kicks and bans are copied as they are. A sighting
# someone accepted or rejected by hand stays that way. Promotions are worked
# out again, like the verdicts.
#
# Arguments, as a hash:
#   from       the old <network>.sqlite, which is only read
#   out        directory for the new one, which must not exist yet
#   network    the irssi server tag, which names the new file
#   promote_after_sightings, promote_after_days
#              optional, see Profiler::Score::promotable
#   on_progress  optional, called with the count every 100,000 sightings
#
# Returns stats: sightings, promoted, and changed, counting sightings by old
# verdict then new verdict, as in changed->{suspect}{consistent}.
sub rescore {
    my (%arg) = @_;
    my ($network, $store) = ($arg{network}, Profiler::Store->new($arg{out}));
    my $path = $store->path($network);
    die "$path already exists; move it away or pick another out directory\n" if -e $path;
    my $promote_count = $arg{promote_after_sightings} // $Profiler::Score::PROMOTE_AFTER_SIGHTINGS;
    my $promote_days = $arg{promote_after_days} // $Profiler::Score::PROMOTE_AFTER_DAYS;

    my $old = DBI->connect("dbi:SQLite:dbname=$arg{from}", '', '',
        { RaiseError => 1, PrintError => 0, sqlite_open_flags => DBD::SQLite::OPEN_READONLY() });
    # Schema 2 is the same without kicks and bans, and 3 without providers.
    my ($version) = $old->selectrow_array('PRAGMA user_version');
    die "$arg{from} is schema $version, and this reads 2 to $Profiler::Store::SCHEMA_VERSION\n"
        if $version < 2 || $version > $Profiler::Store::SCHEMA_VERSION;

    my $new = $store->db($network, 1);
    my $links = $old->selectall_arrayref('SELECT a, b, first_seen, last_seen FROM nick_links');
    $new->prepare('INSERT INTO nick_links (a, b, first_seen, last_seen) VALUES (?, ?, ?, ?)')->execute(@$_) for @$links;
    # Sightings from before providers were kept get theirs from the cached
    # lookup of their host, where there is one.
    my %provider;
    for my $info (@{ $old->selectall_arrayref('SELECT * FROM hostinfo', { Slice => {} }) }) {
        my $host = delete $info->{host};
        $store->set_hostinfo($network, $host, $info, $info->{checked});
        $provider{$host} = Profiler::Whois::provider($info);
    }
    if ($version >= 3) {
        my @columns = qw(kind nick_key nick ident host channel mask by reason time);
        my $marks = $old->selectall_arrayref('SELECT ' . join(', ', @columns) . ' FROM marks');
        $new->prepare('INSERT INTO marks (' . join(', ', @columns) . ') VALUES (' . join(', ', ('?') x @columns) . ')')
            ->execute(@$_) for @$marks;
    }

    my %stats = (sightings => 0, promoted => 0, changed => {});
    my $rows = $old->prepare('SELECT * FROM sightings ORDER BY time, id');
    $rows->execute;
    while (my $row = $rows->fetchrow_hashref) {
        my %obs = (nick => $row->{nick},
            map { defined $row->{$_} ? ($_ => $row->{$_}) : () } qw(host ip ident realname server version channel proxy provider));
        $obs{provider} //= $provider{ $obs{host} } if defined $obs{host};
        my $s = Profiler::Import::observe($store, $network, \%obs, $row->{time});
        # Reviewed without a promotion means someone ran /profiler accept or
        # reject on it.
        $store->set_reviewed($network, $s, $row->{quarantined}) if $row->{reviewed} && !$row->{promoted};
        $stats{promoted} += () = $store->promote_if_moved($network, $obs{nick}, $row->{time}, $promote_count, $promote_days);
        $stats{changed}{ $row->{verdict} }{ $s->{verdict} }++;
        if (++$stats{sightings} % 100_000 == 0) {
            $store->flush;
            $arg{on_progress}->($stats{sightings}) if $arg{on_progress};
        }
    }
    $old->disconnect;
    $store->close;
    return \%stats;
}

1;
