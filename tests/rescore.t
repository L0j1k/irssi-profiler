use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use DBI;
use File::Basename ();
use File::Temp qw(tempdir);
use Test::More;

use Profiler::Rescore;
use Profiler::Store;

my $DAY = 86400;
my $T = 1_600_000_000;
my %bob = (nick => 'Bob', host => 'host.example.net', ident => '~bob', channel => '#chan');

# An old file whose verdicts came from some earlier scoring: everything
# after the first few was called suspect.
sub old_store {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    for my $d (0 .. 19) {
        my %live = $d == 19 ? (realname => 'Bob Smith', version => 'irssi v1.4.5', server => 'irc.example.net') : ();
        $store->record('efnet', { %bob, %live }, $T + $d * $DAY, $d < 3 ? 'unknown' : 'suspect');
    }
    $store->record('efnet', { %bob, nick => 'carol', ident => 'carol' }, $T, 'suspect');
    $store->record('efnet', { %bob, nick => 'dave', ident => 'dave' }, $T, 'suspect');
    $store->record('efnet', { %bob, nick => 'dave', ident => 'lol', host => 'troll.example.org' }, $T + 30 * $DAY, 'suspect');
    $store->accept('efnet', 'carol');
    $store->reject('efnet', 'dave');
    $store->link_nicks('efnet', 'Bob', 'bob_', $T);
    $store->set_hostinfo('efnet', 'host.example.net', { ip => '192.0.2.1', org => 'Example ISP' }, $T);
    $store->close;
    return "$dir/efnet.sqlite";
}

subtest 'every sighting is judged again with the current scoring' => sub {
    my $from = old_store();
    my $out = tempdir(CLEANUP => 1);
    my $stats = Profiler::Rescore::rescore(from => $from, out => $out, network => 'efnet');
    is($stats->{sightings}, 23, 'all of them');
    ok($stats->{changed}{suspect}{consistent}, 'bob was the usual bob all along');
    ok(!$stats->{changed}{suspect}{suspect}, 'and nobody is a suspect now');

    my $store = Profiler::Store->new($out);
    my $bob = $store->profile('efnet', 'bob');
    is($bob->{total}, 20, 'bob has every sighting');
    is(scalar(grep { $_->{quarantined} } @{ $bob->{sightings} }), 0, 'none held');
    is($bob->{sightings}[-1]{realname}, 'Bob Smith', 'what live lookups gave is kept');
    is_deeply([ $store->linked('efnet', 'bob') ], ['bob_'], 'nick links are kept');
    is($store->fresh_hostinfo('efnet', 'host.example.net', $T, 3600)->{org}, 'Example ISP', 'and host lookups');
    is($bob->{sightings}[0]{provider}, 'example isp', 'which fill in who the address belongs to');
};

subtest 'what was decided by hand stays decided' => sub {
    my $out = tempdir(CLEANUP => 1);
    Profiler::Rescore::rescore(from => old_store(), out => $out, network => 'efnet');
    my $store = Profiler::Store->new($out);
    my ($carol) = @{ $store->profile('efnet', 'carol')->{sightings} };
    ok(!$carol->{quarantined} && $carol->{reviewed}, 'an accepted sighting still counts');
    my $dave = $store->profile('efnet', 'dave')->{sightings};
    ok($dave->[-1]{quarantined} && $dave->[-1]{reviewed}, 'a rejected one is still held');
};

subtest 'kicks and bans are kept, and a file from before them is read too' => sub {
    my $from = old_store();
    my $store = Profiler::Store->new(File::Basename::dirname($from));
    $store->record_kick('efnet', { nick => 'dave', channel => '#chan', by => 'op', reason => 'troll' }, $T);
    $store->close;
    my $out = tempdir(CLEANUP => 1);
    Profiler::Rescore::rescore(from => $from, out => $out, network => 'efnet');
    is(scalar(() = Profiler::Store->new($out)->marks('efnet', 'dave')), 1, 'kicks and bans are copied');

    $from = old_store();
    my $dbh = DBI->connect("dbi:SQLite:dbname=$from", '', '', { RaiseError => 1 });
    $dbh->do('DROP TABLE marks');
    $dbh->do('PRAGMA user_version = 2');
    $dbh->disconnect;
    $out = tempdir(CLEANUP => 1);
    my $stats = Profiler::Rescore::rescore(from => $from, out => $out, network => 'efnet');
    is($stats->{sightings}, 23, 'a schema 2 file is rescored');
};

subtest 'labels are kept, and a file from before them is read too' => sub {
    my $from = old_store();
    my $store = Profiler::Store->new(File::Basename::dirname($from));
    $store->set_label('efnet', 'dave', 'bad', $T);
    $store->close;
    my $out = tempdir(CLEANUP => 1);
    Profiler::Rescore::rescore(from => $from, out => $out, network => 'efnet');
    is(Profiler::Store->new($out)->label('efnet', 'dave'), 'bad', 'labels are copied');

    $from = old_store();
    my $dbh = DBI->connect("dbi:SQLite:dbname=$from", '', '', { RaiseError => 1 });
    $dbh->do('DROP TABLE labels');
    $dbh->do('PRAGMA user_version = 4');
    $dbh->disconnect;
    $out = tempdir(CLEANUP => 1);
    my $stats = Profiler::Rescore::rescore(from => $from, out => $out, network => 'efnet');
    is($stats->{sightings}, 23, 'a schema 4 file is rescored');
};

subtest 'it never overwrites' => sub {
    my $from = old_store();
    my $out = tempdir(CLEANUP => 1);
    Profiler::Rescore::rescore(from => $from, out => $out, network => 'efnet');
    ok(!eval { Profiler::Rescore::rescore(from => $from, out => $out, network => 'efnet'); 1 }, 'refuses');
    like($@, qr/already exists/, $@);
};

subtest 'the script, in a process of its own' => sub {
    my $from = old_store();
    my $out = tempdir(CLEANUP => 1);
    my $output = `'$FindBin::Bin/../scripts/rescore.pl' --out '$out/new' '$from' 2>&1`;
    is($?, 0, 'succeeds') or diag $output;
    like($output, qr/rescored 23 sightings/, 'says how many');
    like($output, qr/^\s+suspect\s+\d+\s+\d+/m, 'and how the verdicts moved');
    ok(-f "$out/new/efnet.sqlite", 'and writes the file');
};

done_testing;
