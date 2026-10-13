use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use File::Temp qw(tempdir);
use Test::More;

use Profiler::Score;
use Profiler::Store;

my %obs = (
    nick     => 'Bob',
    host     => 'host.example.net',
    ip       => '10.10.10.2',
    ident    => '~bob',
    realname => 'Bob Smith',
    server   => 'irc.example.net',
    channel  => '#CHAN',
    version  => 'irssi v1.4.5',
);

# A second store on the same directory sees only what the first committed.
sub reopened { Profiler::Store->new($_[0]) }

subtest 'recording and reloading sightings' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);

    is($store->profile('EFnet', 'bob'), undef, 'unknown nick');
    $store->record('EFnet', \%obs, 1000, 'unknown');
    $store->record('EFnet', { %obs, realname => undef, server => undef }, 2000, 'consistent');
    $store->flush;

    ok(-f "$dir/efnet.sqlite", 'one database per network, lowercased');

    my $p = reopened($dir)->profile('efnet', 'BOB');
    is($p->{nick}, 'Bob', 'display nick kept');
    is($p->{first_seen}, 1000, 'first seen');
    is($p->{last_seen}, 2000, 'last seen');
    is(scalar @{ $p->{sightings} }, 2, 'two sightings');

    my ($first, $second) = @{ $p->{sightings} };
    is($first->{time}, 1000, 'time');
    is($first->{host}, 'host.example.net', 'fields kept');
    is($first->{channel}, '#chan', 'channel lowercased');
    is($first->{verdict}, 'unknown', 'verdict kept');
    ok(!$first->{quarantined}, 'not quarantined');
    ok(!exists $second->{realname}, 'missing values are left out');
    ok(!exists $first->{nick}, 'nick is not repeated in every sighting');
};

subtest 'nothing is visible to others until flushed' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    $store->record('efnet', \%obs, 1, 'unknown');
    is(reopened($dir)->profile('efnet', 'bob'), undef, 'not yet');
    $store->flush;
    ok(reopened($dir)->profile('efnet', 'bob'), 'after flush');
};

subtest 'merely reading creates no database' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    is($store->profile('other', 'bob'), undef, 'nothing there');
    is($store->fresh_hostinfo('other', 'h', 1, 1), undef, 'no host info either');
    is_deeply([ $store->suspects('other') ], [], 'no suspects either');
    $store->flush;
    ok(!-e "$dir/other.sqlite", 'no file');
};

subtest 'suspect sightings are quarantined until reviewed' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    $store->record('efnet', \%obs, 1000, 'consistent');
    $store->record('efnet', { %obs, ident => 'lol' }, 2000, 'suspect');
    $store->record('efnet', { %obs, nick => 'Carol', ident => 'x' }, 3000, 'suspect');

    my @s = $store->suspects('efnet');
    is_deeply([ map { "$_->{nick}\@$_->{sighting}{time}" } @s ], ['Bob@2000', 'Carol@3000'], 'listed oldest first');
    is($s[0]{sighting}{ident}, 'lol', 'with the sighting');
    ok($store->profile('efnet', 'bob')->{sightings}[1]{quarantined}, 'quarantined');

    is($store->accept('efnet', 'BOB'), 1, 'accept reports how many');
    my $accepted = $store->profile('efnet', 'bob')->{sightings}[1];
    ok(!$accepted->{quarantined}, 'accepted sighting now counts');
    ok($accepted->{reviewed}, 'and is marked reviewed');

    is($store->reject('efnet', 'carol'), 1, 'reject reports how many');
    my $rejected = $store->profile('efnet', 'carol')->{sightings}[0];
    ok($rejected->{quarantined} && $rejected->{reviewed}, 'rejected stays out, reviewed');

    is_deeply([ $store->suspects('efnet') ], [], 'nothing left to review');
    is($store->accept('efnet', 'nobody'), 0, 'unknown nick is a no-op');

    $store->flush;
    my $again = reopened($dir)->profile('efnet', 'bob')->{sightings}[1];
    ok(!$again->{quarantined} && $again->{reviewed}, 'reviews are stored');

    $store->record('efnet', { %obs, host => 'elsewhere.example.org' }, 4000, 'new host');
    ok($store->profile('efnet', 'bob')->{sightings}[-1]{quarantined}, 'a new host is quarantined too');
};

subtest 'someone who moved stops being held within about a week' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    my ($t, %verdicts, @promoted) = (1_600_000_000);

    # Daily joins from one host for 100 days, then from another ISP for 100.
    for my $d (0 .. 199) {
        my $obs = { nick => 'bob', ident => '~bob', channel => '#c',
            host => $d < 100 ? 'cpe-1-2-3-4.sd.res.rr.com' : 'pool-9-8-7-6.nyc.fios.verizon.net' };
        my $now = $t + $d * 86400;
        my $r = Profiler::Score::judge($store->profile('n', 'bob'), $obs, $now);
        $store->record('n', $obs, $now, $r->{verdict});
        if (my $n = $store->promote_if_moved('n', 'bob', $now, 5, 7)) { push @promoted, $n }
        $verdicts{ $r->{verdict} }++ if $d >= 100;
    }
    my $held = $verdicts{'new host'} // 0;
    ok(!$verdicts{suspect}, 'a move with the same ident is never called suspect');
    ok($held >= 5 && $held <= 8, "held as a new host for $held days after the move");
    is(scalar @promoted, 1, 'promoted once');
    is($promoted[0], $held, 'every quarantined sighting promoted');

    my @s = grep { $_->{promoted} } @{ $store->profile('n', 'bob')->{sightings} };
    ok(!grep({ $_->{quarantined} || !$_->{reviewed} } @s), 'promoted sightings count and are marked reviewed');
    is_deeply([ $store->suspects('n') ], [], 'nothing left to review');

    $store->flush;
    my @stored = grep { $_->{promoted} } @{ reopened($dir)->profile('n', 'bob')->{sightings} };
    is(scalar @stored, $held, 'promotions are stored');
    is($store->promote_if_moved('n', 'nobody', $t, 5, 7), 0, 'unknown nick');
};

subtest 'scoring sees the latest sightings, the database keeps everything' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    local $Profiler::Store::HISTORY_SIZE = 3;
    $store->record('efnet', \%obs, $_, 'consistent') for 1 .. 5;
    my $p = $store->profile('efnet', 'bob');
    is_deeply([ map { $_->{time} } @{ $p->{sightings} } ], [3, 4, 5], 'last three in the profile');
    is($p->{first_seen}, 1, 'first seen goes back further');
    is($p->{total}, 5, 'and the total counts every sighting');

    $store->flush;
    my $other = reopened($dir);
    is_deeply([ map { $_->{time} } @{ $other->profile('efnet', 'bob')->{sightings} } ], [3, 4, 5], 'same after reloading');
    is($other->profile('efnet', 'bob')->{first_seen}, 1, 'first seen after reloading');
    is($other->profile('efnet', 'bob')->{total}, 5, 'total after reloading');
    my $all = $other->all_profiles('efnet');
    is_deeply([ map { $_->{time} } @{ $all->{users}{bob}{sightings} } ], [1 .. 5], 'every sighting kept');
    is($all->{users}{bob}{nick}, 'Bob', 'with the display nick');
    $other->record('efnet', \%obs, 6, 'consistent');
    is($other->profile('efnet', 'bob')->{total}, 6, 'total after recording');
};

subtest 'reviews reach sightings older than the profile shows' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    local $Profiler::Store::HISTORY_SIZE = 2;
    $store->record('efnet', { %obs, ident => 'lol' }, 1, 'suspect');
    $store->record('efnet', \%obs, $_, 'consistent') for 2, 3;
    is($store->accept('efnet', 'bob'), 1, 'found the old one');
    $store->flush;
    my ($old) = @{ reopened($dir)->all_profiles('efnet')->{users}{bob}{sightings} };
    ok(!$old->{quarantined} && $old->{reviewed}, 'and accepted it');
};

subtest 'nick changes link two nicks, one hop only' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    $store->link_nicks('efnet', 'CybBob', 'Bob', 100);
    $store->link_nicks('efnet', 'bob', 'cybbob', 200);
    $store->link_nicks('efnet', 'bob', 'robert', 300);
    $store->link_nicks('efnet', 'bob', 'BOB', 400);
    is_deeply([ $store->linked('efnet', 'BOB') ], ['robert', 'cybbob'], 'both ways, each once, latest first');
    is_deeply([ $store->linked('efnet', 'cybbob') ], ['bob'], 'not through bob to robert');
    is_deeply([ $store->linked('efnet', 'nobody') ], [], 'no links');
    is_deeply([ $store->linked('other', 'bob') ], [], 'unknown network');

    $store->flush;
    is_deeply([ reopened($dir)->linked('efnet', 'robert') ], ['bob'], 'stored');
};

subtest 'similar nicks share a skeleton' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    $store->record('efnet', { %obs, nick => $_ }, 1, 'unknown') for qw(Bob bob_ B0B` bobby);
    is_deeply([ $store->similar('efnet', 'bob__') ], ['b0b`', 'bob', 'bob_'], 'variants, not bobby');
    is_deeply([ $store->similar('efnet', 'bob_') ], ['b0b`', 'bob'], 'not itself');
    is_deeply([ $store->similar('other', 'bob') ], [], 'unknown network');
};

subtest 'a database from an older profiler is refused' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $dbh = DBI->connect("dbi:SQLite:dbname=$dir/efnet.sqlite", '', '', { RaiseError => 1 });
    $dbh->do('CREATE TABLE sightings (id INTEGER PRIMARY KEY)');
    $dbh->disconnect;
    eval { Profiler::Store->new($dir)->profile('efnet', 'bob') };
    like($@, qr/older version of the profiler.*import/s, 'says to re-import');
};

subtest 'odd network names make safe file names' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    $store->record('../My Net', \%obs, 1, 'unknown');
    $store->flush;
    ok(-f "$dir/.._my_net.sqlite", 'slashes and spaces replaced');
};

subtest 'host lookups are cached with an age' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    my %info = (ip => '10.10.10.2', netname => 'NET', org => 'Org', origin => 'AS1', proxy => 'vpn', error => undef);
    $store->set_hostinfo('efnet', 'host.example.net', \%info, 1000);
    is($store->fresh_hostinfo('efnet', 'host.example.net', 1500, 600)->{ip}, '10.10.10.2', 'fresh');
    is($store->fresh_hostinfo('efnet', 'host.example.net', 1700, 600), undef, 'stale');
    is($store->fresh_hostinfo('efnet', 'other', 1500, 600), undef, 'unknown host');

    $store->set_hostinfo('efnet', 'host.example.net', { %info, ip => '10.10.10.3' }, 1100);
    $store->flush;
    is_deeply(reopened($dir)->fresh_hostinfo('efnet', 'host.example.net', 1500, 600),
        { %info, ip => '10.10.10.3', error => undef, checked => 1100 }, 'a newer lookup replaces the old one');
};

subtest 'a corrupt file is reported and never overwritten' => sub {
    my $dir = tempdir(CLEANUP => 1);
    open my $fh, '>', "$dir/efnet.sqlite" or die $!;
    print $fh "not a database at all, just some text long enough to fill a header....";
    close $fh;

    my $store = Profiler::Store->new($dir);
    eval { $store->profile('efnet', 'bob') };
    like($@, qr/cannot open .*efnet\.sqlite/, 'load error names the file');

    eval { $store->record('efnet', \%obs, 1, 'unknown') };
    like($@, qr/cannot open/, 'still refuses on later use');
    $store->flush;

    open $fh, '<', "$dir/efnet.sqlite" or die $!;
    like(scalar <$fh>, qr/^not a database/, 'file untouched');
};

done_testing;
