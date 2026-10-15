#!/usr/bin/env perl
# Adds the kicks and bans in your irssi logs to an existing profiler data
# file, leaving its sightings alone. Use it once on a file imported before
# kicks and bans were recorded; scripts/import_logs.pl records them itself
# now. Running it again adds nothing new.
#
# usage: scripts/backfill_marks.pl --logs DIR FILE
#
#   --logs  the network's log directory, as for scripts/import_logs.pl
#   FILE    the <network>.sqlite to add to. It can be the live one while
#           irssi runs, since both just take turns writing.
#
# A kick is matched to the latest join of that nick in that channel. A ban
# is matched to whoever joined the channel in the week before it, unless it
# matched more than a few nicks. Lifted bans are ignored.
use strict;
use warnings;

use File::Basename qw(fileparse);
use FindBin;
use Getopt::Long;
use lib "$FindBin::Bin/../src";

use Profiler::Import;
use Profiler::Store;

sub usage {
    open my $fh, '<', $0 or die $!;
    while (<$fh>) { next if $. == 1; last unless s/^# ?//; print STDERR $_ }
    exit 2;
}

my %opt;
GetOptions(\%opt, 'logs=s', 'help|h') or usage();
my ($path) = @ARGV;
usage() if $opt{help} || !$opt{logs} || !$path;
die "no log directory at $opt{logs}\n" unless -d $opt{logs};
die "no data file at $path\n" unless -f $path;
my ($network, $dir) = fileparse($path, '.sqlite');

my $started = time;
my $store = Profiler::Store->new($dir);
my $stats = Profiler::Import::replay(
    store      => $store,
    network    => $network,
    logs       => $opt{logs},
    marks_only => 1,
    on_month   => sub { print STDERR "$_[0]\n" },
);
$store->close;
printf "read %d kick(s), %d ban mask(s) in %ds; ones already there were skipped\n",
    $stats->{kicks}, $stats->{bans}, time - $started;
