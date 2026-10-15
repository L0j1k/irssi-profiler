#!/usr/bin/env perl
# Measures what a "who is this really" search would cost: judging a join
# against other nicks' profiles to find whose history it fits, instead of
# only the nick it used. Run it before building that search to pick an
# approach. It works on a temporary copy and prints timings and counts only:
# no nicks, hosts or idents.
#
# usage: scripts/bench_fingerprint_search.pl [--skip-brute] FILE [JOINS]
#   --skip-brute  leave out brute force, which takes about a second per
#                 thousand nicks per join
#   FILE   a profiler data file, e.g. build/profiler-data/efnet.sqlite
#   JOINS  how many sample joins to search for (default 30), taken from
#          random sightings in the file
#
# Approaches:
#   brute      every profile loaded into memory, the join judged against all
#   prefilter  only nicks sharing the join's ident, host or ip, found with SQL,
#              first without indexes on those columns and then with them
use strict;
use warnings;

use File::Copy qw(copy);
use File::Temp qw(tempdir);
use FindBin;
use List::Util qw(sum0);
use Time::HiRes qw(time);
use lib "$FindBin::Bin/../src";

use Profiler::Score;
use Profiler::Store;

my $skip_brute = @ARGV && $ARGV[0] eq '--skip-brute' ? shift @ARGV : 0;
my ($path, $joins) = @ARGV;
if (!$path || $path =~ /^-/ || !-f $path) {
    open my $fh, '<', $0 or die $!;
    while (<$fh>) { next if $. == 1; last unless s/^# ?//; print STDERR $_ }
    exit 2;
}
$joins //= 30;

my $dir = tempdir(CLEANUP => 1);
copy($path, "$dir/bench.sqlite") or die "copy $path: $!\n";
my $store = Profiler::Store->new($dir);
my $dbh = $store->db('bench');

my ($nicks, $rows, $now) = $dbh->selectrow_array('SELECT COUNT(DISTINCT nick_key), COUNT(*), MAX(time) + 1 FROM sightings');
printf "%d nicks, %d sightings\n", $nicks, $rows;

# The sample joins, each searched for as if it came in under a new nick.
my $sample = $dbh->selectall_arrayref(
    "SELECT * FROM sightings WHERE quarantined = 0 ORDER BY random() LIMIT $joins", { Slice => {} });
my @obs = map { my $key = $_->{nick_key}; [ $key, Profiler::Store::sighting_from_row({ %$_ }) ] } @$sample;

sub rss_mb {
    open my $fh, '<', '/proc/self/status' or return 0;
    while (<$fh>) { return $1 / 1024 if /^VmRSS:\s+(\d+)/ }
    return 0;
}

# Judges $obs against each profile, skipping its own nick, and returns how
# many came out consistent.
sub search {
    my ($obs, $own, $profiles) = @_;
    my $fits = 0;
    for my $key (keys %$profiles) {
        next if $key eq $own;
        my $r = Profiler::Score::judge($profiles->{$key}, $obs, $now);
        $fits++ if $r->{verdict} eq 'consistent';
    }
    return $fits;
}

sub report {
    my ($name, $times, $candidates) = @_;
    my @sorted = sort { $a <=> $b } @$times;
    printf "%-22s per join: mean %7.1f ms, median %7.1f ms, max %7.1f ms; candidates mean %.0f, max %d\n",
        $name, 1000 * sum0(@sorted) / @sorted, 1000 * $sorted[$#sorted / 2], 1000 * $sorted[-1],
        sum0(@$candidates) / @$candidates, (sort { $b <=> $a } @$candidates)[0];
}

# Brute force. Profiles keep their latest 200 sightings, like Store::profile.
if (!$skip_brute) {
    my $rss = rss_mb();
    my $t0 = time;
    my $all = $store->all_profiles('bench')->{users};
    for my $p (values %$all) {
        my $s = $p->{sightings};
        splice @$s, 0, @$s - $Profiler::Store::HISTORY_SIZE if @$s > $Profiler::Store::HISTORY_SIZE;
    }
    printf "brute: loading every profile took %.1f s and %.0f MB\n", time - $t0, rss_mb() - $rss;
    my (@times, @candidates);
    for my $o (@obs) {
        my $t = time;
        search($o->[1], $o->[0], $all);
        push @times, time - $t;
        push @candidates, scalar(keys %$all) - 1;
    }
    report('brute', \@times, \@candidates);
}

my $find = $dbh->prepare(
    'SELECT DISTINCT nick_key FROM sightings WHERE nick_key != ? AND (ident = ? OR host = ? OR ip = ?)');
sub prefilter {
    my ($name) = @_;
    my (@times, @candidates);
    for my $o (@obs) {
        my ($own, $obs) = @$o;
        $store->{profiles} = {};
        my $t = time;
        my $keys = $dbh->selectcol_arrayref($find, undef, $own, $obs->{ident} // '', $obs->{host} // '', $obs->{ip} // '');
        my %profiles = map { $_ => $store->profile('bench', $_) } @$keys;
        search($obs, $own, \%profiles);
        push @times, time - $t;
        push @candidates, scalar @$keys;
    }
    report($name, \@times, \@candidates);
}

prefilter('prefilter, no indexes');

my $size = -s "$dir/bench.sqlite";
my $t0 = time;
$dbh->do("CREATE INDEX bench_by_$_ ON sightings ($_)") for qw(ident host ip);
$store->flush;
$dbh->do('PRAGMA wal_checkpoint(TRUNCATE)');
printf "indexes on ident, host, ip: built in %.1f s, file %.0f MB -> %.0f MB\n",
    time - $t0, $size / 2**20, (-s "$dir/bench.sqlite") / 2**20;
prefilter('prefilter, indexed');
