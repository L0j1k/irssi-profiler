use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use File::Temp qw(tempdir);
use Test::More;

use Profiler::Store;

my $LOGS = "$FindBin::Bin/fixtures/logs/EFNet";
my $SCRIPT = "$FindBin::Bin/../scripts/backfill_marks.pl";

subtest 'adds the kicks and bans from the logs to an existing file' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    $store->record('efnet', { nick => 'bob', ident => '~bob', host => 'h.example.net', channel => '#chan' }, 1, 'unknown');
    $store->close;

    my $out = `'$SCRIPT' --logs '$LOGS' '$dir/efnet.sqlite' 2>&1`;
    is($?, 0, 'succeeds') or diag $out;
    like($out, qr/2 kick\(s\), 2 ban mask\(s\)/, 'says what it added');

    $store = Profiler::Store->new($dir);
    is(scalar(() = $store->marks('efnet', 'bob')), 2, 'kicks and bans are in');
    is($store->profile('efnet', 'bob')->{total}, 1, 'and the sightings are as they were');
};

subtest 'complains about a missing file' => sub {
    my $out = `'$SCRIPT' --logs '$LOGS' /nonexistent/efnet.sqlite 2>&1`;
    isnt($?, 0, 'fails');
    like($out, qr/no data file at/, $out);
};

done_testing;
