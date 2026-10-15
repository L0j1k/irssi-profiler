#!/usr/bin/env perl
# Judges every sighting in a profiler data file again with the current
# scoring and writes the result to a new file. Run it after a scoring change
# instead of importing the logs again: it keeps everything the live script
# saw (realname, server, version, host lookups, sightings newer than the
# logs), nick links, and what you accepted or rejected by hand.
#
# usage: scripts/rescore.pl [--out DIR] [--half-life-days DAYS]
#                           [--promote-after-sightings N] [--promote-after-days N] FILE
#
#   FILE              the <network>.sqlite to rescore; it's only read, so it
#                     can be the live one while irssi runs
#   --out             where to write the new <network>.sqlite (default:
#                     build/profiler-data/rescored in this repo). Refuses to
#                     overwrite.
#   --half-life-days, --promote-after-*
#                     keep these in step with the live script's settings
#
# Prints how many sightings went from each old verdict to each new one.
# Then install the result:
#   /script unload profiler
#   scripts/install_db.sh --from build/profiler-data/rescored <network>
#   /script load profiler
# Anything irssi records between the rescore and the install is lost, so
# install soon after.
use strict;
use warnings;

use File::Basename qw(fileparse);
use File::Path qw(make_path);
use FindBin;
use Getopt::Long;
use lib "$FindBin::Bin/../src";

use Profiler::Rescore;
use Profiler::Score;

sub usage {
    open my $fh, '<', $0 or die $!;
    while (<$fh>) { next if $. == 1; last unless s/^# ?//; print STDERR $_ }
    exit 2;
}

my %opt = (
    out                       => "$FindBin::Bin/../build/profiler-data/rescored",
    'half-life-days'          => 90,
    'promote-after-sightings' => $Profiler::Score::PROMOTE_AFTER_SIGHTINGS,
    'promote-after-days'      => $Profiler::Score::PROMOTE_AFTER_DAYS,
);
GetOptions(\%opt, 'out=s', 'half-life-days=i', 'promote-after-sightings=i', 'promote-after-days=i', 'help|h')
    or usage();
my ($from) = @ARGV;
usage() if $opt{help} || !$from;
die "no data file at $from\n" unless -f $from;
my ($network) = fileparse($from, '.sqlite');
$Profiler::Score::HALF_LIFE = 86400 * $opt{'half-life-days'};

make_path($opt{out}) unless -d $opt{out};
my $started = time;
my $stats = Profiler::Rescore::rescore(
    from        => $from,
    out         => $opt{out},
    network     => $network,
    on_progress => sub { print STDERR "$_[0] sightings\n" },
    promote_after_sightings => $opt{'promote-after-sightings'},
    promote_after_days      => $opt{'promote-after-days'},
);

my @verdicts = ('unknown', 'consistent', 'mixed', 'new host', 'suspect');
printf "rescored %d sightings in %ds; %d promoted as moves\n", $stats->{sightings}, time - $started, $stats->{promoted};
print "old verdict down, new across:\n";
printf "  %-11s%s\n", '', join('', map { sprintf '%11s', $_ } @verdicts);
for my $old (@verdicts) {
    printf "  %-11s%s\n", $old, join('', map { sprintf '%11d', $stats->{changed}{$old}{$_} // 0 } @verdicts);
}
print "wrote $opt{out}/$network.sqlite\n";
