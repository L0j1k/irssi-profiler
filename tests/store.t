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

subtest 'recording and reloading sightings' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);

    is($store->profile('EFnet', 'bob'), undef, 'unknown nick');
    $store->record('EFnet', \%obs, 1000, 'unknown');
    $store->record('EFnet', { %obs, realname => undef, server => undef }, 2000, 'consistent');
    $store->save('EFnet');

    ok(-f "$dir/efnet.json", 'one file per network, lowercased');

    my $p = Profiler::Store->new($dir)->profile('efnet', 'BOB');
    is($p->{nick}, 'Bob', 'display nick kept');
    is($p->{first_seen}, 1000, 'first seen');
    is($p->{last_seen}, 2000, 'last seen');
    is(scalar @{ $p->{sightings} }, 2, 'two sightings');

    my ($first, $second) = @{ $p->{sightings} };
    is($first->{time}, 1000, 'time');
    is($first->{channel}, '#chan', 'channel lowercased');
    is($first->{verdict}, 'unknown', 'verdict kept');
    ok(!$first->{quarantined}, 'not quarantined');
    ok(!exists $second->{realname}, 'missing values are left out');
    ok(!exists $first->{nick}, 'nick is not repeated in every sighting');
};

subtest 'suspect sightings are quarantined until reviewed' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    $store->record('efnet', \%obs, 1000, 'consistent');
    $store->record('efnet', { %obs, ident => 'lol' }, 2000, 'suspect');
    $store->record('efnet', { %obs, nick => 'Carol', ident => 'x' }, 3000, 'suspect');

    my @s = $store->suspects('efnet');
    is_deeply([ map { "$_->{nick}\@$_->{sighting}{time}" } @s ], ['Bob@2000', 'Carol@3000'], 'listed oldest first');
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
};

subtest 'someone who moved stops being suspect within about a week' => sub {
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
        $verdicts{$r->{verdict}}++ if $d >= 100;
    }
    ok($verdicts{suspect} <= 8, "suspect for $verdicts{suspect} days after the move");
    is(scalar @promoted, 1, 'promoted once');
    is($promoted[0], $verdicts{suspect}, 'every quarantined sighting promoted');

    my @s = grep { $_->{promoted} } @{ $store->profile('n', 'bob')->{sightings} };
    ok(!grep({ $_->{quarantined} || !$_->{reviewed} } @s), 'promoted sightings count and are marked reviewed');
    is_deeply([ $store->suspects('n') ], [], 'nothing left to review');
};

subtest 'promotion marks the network dirty only when it happens' => sub {
    my $store = Profiler::Store->new(tempdir(CLEANUP => 1));
    $store->record('n', \%obs, 1, 'consistent');
    $store->save_dirty;
    is($store->promote_if_moved('n', 'bob', 2, 5, 7), 0, 'nothing to promote');
    is($store->promote_if_moved('n', 'nobody', 2, 5, 7), 0, 'unknown nick');
    is_deeply([ $store->save_dirty ], [], 'still clean');
};

subtest 'history is capped, dropping the oldest' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    local $Profiler::Store::MAX_SIGHTINGS = 3;
    $store->record('efnet', \%obs, $_, 'consistent') for 1 .. 5;
    my $p = $store->profile('efnet', 'bob');
    is_deeply([ map { $_->{time} } @{ $p->{sightings} } ], [3, 4, 5], 'last three kept');
    is($p->{first_seen}, 1, 'first seen survives the cap');
};

subtest 'save_dirty writes only networks that changed' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    is_deeply([ $store->save_dirty ], [], 'nothing to save');

    $store->record('EFnet', \%obs, 1, 'unknown');
    $store->set_hostinfo('libera', 'h', {}, 1);
    $store->profile('other', 'bob');
    is_deeply([ sort $store->save_dirty ], ['efnet', 'libera'], 'saved changed networks');
    ok(-f "$dir/efnet.json" && -f "$dir/libera.json", 'files written');
    ok(!-e "$dir/other.json", 'merely reading does not save');
    is_deeply([ $store->save_dirty ], [], 'clean again');

    $store->record('efnet', { %obs, ident => 'x' }, 2, 'suspect');
    $store->save_dirty;
    $store->accept('efnet', 'bob');
    is_deeply([ $store->save_dirty ], ['efnet'], 'reviewing marks dirty too');
    is($store->accept('efnet', 'bob'), 0, 'nothing left');
    is_deeply([ $store->save_dirty ], [], 'a no-op review does not');
};

subtest 'odd network names make safe file names' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    $store->record('../My Net', \%obs, 1, 'unknown');
    $store->save('../My Net');
    ok(-f "$dir/.._my_net.json", 'slashes and spaces replaced');
};

subtest 'host lookups are cached with an age' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    $store->set_hostinfo('efnet', 'host.example.net', { ip => '10.10.10.2', proxy => undef }, 1000);
    is($store->fresh_hostinfo('efnet', 'host.example.net', 1500, 600)->{ip}, '10.10.10.2', 'fresh');
    is($store->fresh_hostinfo('efnet', 'host.example.net', 1700, 600), undef, 'stale');
    is($store->fresh_hostinfo('efnet', 'other', 1500, 600), undef, 'unknown host');
};

subtest 'a corrupt file is reported and never overwritten' => sub {
    my $dir = tempdir(CLEANUP => 1);
    open my $fh, '>', "$dir/efnet.json" or die $!;
    print $fh "{ not json";
    close $fh;

    my $store = Profiler::Store->new($dir);
    eval { $store->profile('efnet', 'bob') };
    like($@, qr/cannot parse .*efnet\.json/, 'load error names the file');

    eval { $store->record('efnet', \%obs, 1, 'unknown') };
    like($@, qr/cannot parse/, 'still refuses on later use');
    eval { $store->save('efnet') };
    like($@, qr/cannot parse/, 'save refuses too');

    open $fh, '<', "$dir/efnet.json" or die $!;
    is(scalar <$fh>, '{ not json', 'file untouched');
};

done_testing;
