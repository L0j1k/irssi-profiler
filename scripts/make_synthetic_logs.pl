#!/usr/bin/env perl
# Writes fake irssi channel logs in the same layout and line format as real
# ones, for timing scripts/import_logs.pl without touching real logs.
#
# usage: scripts/make_synthetic_logs.pl OUT_DIR [DAYS] [JOINS_PER_DAY] [NICKS]
#   defaults: 365 days, 500 joins a day, 2000 distinct nicks
use strict;
use warnings;

use File::Path qw(make_path);
use POSIX qw(strftime);

my ($out, $days, $per_day, $nicks) = @ARGV;
if (!$out || $out =~ /^-/) {
    open my $fh, '<', $0 or die $!;
    while (<$fh>) { next if $. == 1; last unless s/^# ?//; print STDERR $_ }
    exit 2;
}
$days //= 365;
$per_day //= 500;
$nicks //= 2000;

srand 42;
my $start = 1704067200;    # 2024-01-01 UTC
for my $d (0 .. $days - 1) {
    my @t = gmtime($start + $d * 86400);
    my $dir = sprintf('%s/%04d/%02d', $out, $t[5] + 1900, $t[4] + 1);
    make_path($dir);
    open my $fh, '>', sprintf('%s/%s-#chan.log', $dir, strftime('%Y-%m-%d', @t)) or die $!;
    for my $sec (sort { $a <=> $b } map { int rand 86400 } 1 .. $per_day) {
        my $n = int rand $nicks;
        # Most people come from their usual /24, some wander.
        my $net = rand() < 0.9 ? $n % 250 : int rand 250;
        printf $fh "%02d:%02d:%02d-!- user%d [~u%d\@10.%d.%d.%d] has joined #chan\n",
            $sec / 3600, $sec / 60 % 60, $sec % 60, $n, $n, $net, $n % 200, 1 + int rand 3;
    }
    close $fh;
}
print "wrote $days days of logs to $out\n";
