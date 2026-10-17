#!/usr/bin/env perl
# Lists who the profiler would call an EVADER. Run it on a data file after
# changing how evasion is judged, so false alarms show up here instead of in
# the channel.
#
# usage: scripts/evasion_sweep.pl [--days N] [--half-life DAYS] FILE
#
#   --days       how far back to look for joins (default 90)
#   --half-life  profiler_half_life_days (default 90)
#   FILE         a <network>.sqlite. Nothing is written to it, but a copy
#                saves fighting irssi for the lock.
#
# Each nick seen in the last --days is judged on its latest sighting, as if
# it had just joined: against its history before that sighting, and with the
# kicks and bans as they stood then. A nick counts as confident when its
# verdict is consistent, ignoring any min_trust in your rules.
use strict;
use warnings;

use File::Basename qw(fileparse);
use FindBin;
use Getopt::Long;
use POSIX qw(strftime);
use lib "$FindBin::Bin/../src";

use Profiler::Evasion;
use Profiler::Marks;
use Profiler::Score;
use Profiler::Store;

sub usage {
    open my $fh, '<', $0 or die $!;
    while (<$fh>) { next if $. == 1; last unless s/^# ?//; print STDERR $_ }
    exit 2;
}

my %opt = (days => 90, 'half-life' => 90);
GetOptions(\%opt, 'days=i', 'half-life=i', 'help|h') or usage();
my ($path) = @ARGV;
usage() if $opt{help} || !$path;
die "no data file at $path\n" unless -f $path;
my ($network, $dir) = fileparse($path, '.sqlite');

local $Profiler::Score::HALF_LIFE = 86400 * $opt{'half-life'};
my $store = Profiler::Store->new($dir);
my $since = time - 86400 * $opt{days};
my $nicks = $store->db($network)->selectcol_arrayref(
    'SELECT nick_key FROM sightings GROUP BY nick_key HAVING MAX(time) >= CAST(? AS INTEGER)', undef, $since);

my $hits = 0;
for my $key (sort @$nicks) {
    my $profile = $store->profile($network, $key);
    my @before = @{ $profile->{sightings} };
    my $latest = pop @before;
    my $now = $latest->{time};
    my $obs = { %$latest, nick => $profile->{nick} };
    my $history = @before ? { %$profile, sightings => \@before } : undef;
    my $r = Profiler::Score::judge($history, $obs, $now);
    my $confident = $history && $r->{verdict} eq 'consistent';
    my $e = Profiler::Evasion::best_match($store, $network, $profile->{nick}, $obs, $now,
        $confident ? $profile->{first_seen} : undef);
    next unless $e;
    $hits++;
    my $parts = join ' ', map { sprintf '%s %+.2f', $_, $e->{result}{parts}{$_} } sort keys %{ $e->{result}{parts} };
    printf "%s %s (%s@%s, %s) looks like %s (%s): match %+.2f; %s\n",
        strftime('%Y-%m-%d', localtime $now), $profile->{nick}, $obs->{ident} // '?', $obs->{host} // '?',
        $r->{verdict}, $e->{nick}, Profiler::Marks::summary($e->{marks}), $e->{result}{match}, $parts;
}
printf "%d of %d nicks seen in the last %d days would get EVADER\n", $hits, scalar @$nicks, $opt{days};
