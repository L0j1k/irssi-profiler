#!/usr/bin/env perl
# Builds profiler data from your irssi logs by replaying every join, oldest
# first, through the profiler's own judging. Run it once to give the profiler
# a history to start from instead of starting everyone at zero.
#
# usage: scripts/import_logs.pl --logs DIR [--network NAME] [--out DIR]
#                               [--recheck SECONDS] [--half-life-days DAYS]
#
#   --logs            the network's log directory, laid out as
#                     <year>/<month>/<year>-<month>-<day>-<target>.log
#   --network         irssi server tag the data is for (default: the name of
#                     the log directory, e.g. EFNet)
#   --out             where to write <network>.sqlite (default: build/profiler-data
#                     in this repo). Refuses to overwrite an existing file, so a
#                     second run can't count everything twice.
#   --recheck         skip a rejoin of the same channel within this many
#                     seconds (default 600, same as the live script)
#   --half-life-days  how fast old sightings fade (default 90)
#   --promote-after-sightings, --promote-after-days
#                     when quarantined sightings count as a move instead of an
#                     impostor (default 5 sightings over 7 days)
#
# Keep these in step with the live script's settings
# (profiler_half_life_days, profiler_promote_after_*), or imported verdicts
# won't match what the live script would have decided.
#
# Progress goes to stderr, one line per month. Malformed join lines are counted
# and the first few are shown at the end.
#
# Then install the result with the script unloaded, since irssi keeps the
# database open:
#   /script unload profiler
#   scripts/install_db.sh <network>
#   /script load profiler
use strict;
use warnings;

use File::Basename qw(basename dirname);
use File::Path qw(make_path);
use FindBin;
use Getopt::Long;
use lib "$FindBin::Bin/../src";

use Profiler::Import;
use Profiler::Score;
use Profiler::Store;

sub usage {
    open my $fh, '<', $0 or die $!;
    while (<$fh>) {
        next if $. == 1;
        last unless s/^# ?//;
        print STDERR $_;
    }
    exit 2;
}

my %opt = (
    recheck                   => 600,
    'half-life-days'          => 90,
    'promote-after-sightings' => $Profiler::Score::PROMOTE_AFTER_SIGHTINGS,
    'promote-after-days'      => $Profiler::Score::PROMOTE_AFTER_DAYS,
    out                       => "$FindBin::Bin/../build/profiler-data",
);
GetOptions(\%opt, 'logs=s', 'network=s', 'out=s', 'recheck=i', 'half-life-days=i',
    'promote-after-sightings=i', 'promote-after-days=i', 'help|h') or usage();
usage() if $opt{help} || !$opt{logs};

die "no log directory at $opt{logs}\n" unless -d $opt{logs};
my $network = $opt{network} // basename($opt{logs});
$Profiler::Score::HALF_LIFE = 86400 * $opt{'half-life-days'};

make_path($opt{out}) unless -d $opt{out};
my $store = Profiler::Store->new($opt{out});
my $path = $store->path($network);
die "$path already exists; move it away or pick another --out\n" if -e $path;

my $started = time;
my $stats = Profiler::Import::replay(
    store    => $store,
    network  => $network,
    logs     => $opt{logs},
    recheck  => $opt{recheck},
    on_month => sub { print STDERR "$_[0]\n" },
    promote_after_sightings => $opt{'promote-after-sightings'},
    promote_after_days      => $opt{'promote-after-days'},
);
$store->close;

my $v = $stats->{verdicts};
printf "replayed %d joins in %ds (%d quick rejoins skipped)\n", $stats->{joins}, time - $started, $stats->{repeats};
printf "verdicts: %s\n", join(', ', map { "$_ " . ($v->{$_} // 0) } ('unknown', 'consistent', 'mixed', 'new host', 'suspect'));
printf "%d quarantined sighting(s) later promoted as moves\n", $stats->{promoted};
printf "%d nick change line(s) linked\n", $stats->{nick_changes};
if ($stats->{unparsed}) {
    print "$stats->{unparsed} join line(s) could not be parsed, for example:\n";
    print "  $_\n" for @{ $stats->{unparsed_examples} };
}
print "wrote $path\n";
