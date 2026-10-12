#!/usr/bin/env perl
# Explains, in aggregate, why sightings in a profiler data file were judged
# suspect. Use it after an import (or on live data) to see whether suspects
# look like impostors or like the scoring being too strict. It prints counts
# and percentages only: no nicks, hosts or idents.
#
# usage: scripts/diagnose_suspects.pl FILE
#   e.g. scripts/diagnose_suspects.pl build/profiler-data/efnet.sqlite
#
# Each held sighting (verdict suspect or new host) is compared with the accepted sightings of the same
# nick that came before it: how the host and ident relate, how long since the
# last accepted sighting, how much history there was, what became of it, and
# whether the usual person turned up again later.
use strict;
use warnings;

use File::Basename qw(fileparse);
use FindBin;
use lib "$FindBin::Bin/../src";

use Profiler::Diagnose;
use Profiler::Store;

my ($path) = @ARGV;
if (!$path || $path =~ /^-/) {
    open my $fh, '<', $0 or die $!;
    while (<$fh>) { next if $. == 1; last unless s/^# ?//; print STDERR $_ }
    exit 2;
}

my ($network, $dir) = fileparse($path, '.sqlite');
die "$path should be a <network>.sqlite file\n" unless $path =~ /\.sqlite$/;
die "no file at $path\n" unless -f $path;
my $r = Profiler::Diagnose::suspect_report(Profiler::Store->new($dir)->all_profiles($network));

my $total = $r->{suspects} || 1;
sub pct { sprintf '%5.1f%%', 100 * $_[0] / $total }

sub section {
    my ($title, $counts, $order) = @_;
    print "\n$title\n";
    my @keys = $order ? grep { exists $counts->{$_} } @$order : sort { $counts->{$b} <=> $counts->{$a} } keys %$counts;
    printf "  %8d  %s  %s\n", $counts->{$_}, pct($counts->{$_}), $_ for @keys;
}

printf "%d held sightings (suspect or new host) across %d of %d nicks\n", $r->{suspects}, $r->{nicks_with_suspects}, $r->{nicks};
printf "top 1%% of those nicks hold %s of suspects, top 10%% hold %s\n",
    pct($r->{concentration}{top_1_percent}), pct($r->{concentration}{top_10_percent});
printf "the usual person turned up again afterwards for %d (%s)\n", $r->{owner_seen_after}, pct($r->{owner_seen_after});

section('verdict', $r->{by_verdict});
section('what changed, against the accepted history', $r->{by_change});
section('time since the last accepted sighting', $r->{by_gap},
    ['under a day', 'under a week', 'under a month', 'under six months', 'under a year', 'a year or more']);
section('accepted sightings before it', $r->{by_history}, ['1-4', '5-19', '20-99', '100+']);
section('what became of it', $r->{by_outcome});
