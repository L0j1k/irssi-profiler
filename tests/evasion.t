use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use File::Temp qw(tempdir);
use Test::More;

use Profiler::Evasion;
use Profiler::Store;

my $DAY = 86400;
my $NOW = 1_000_000_000;

my %troll = (nick => 'trollguy', ident => '~lol', host => 'cpe-1-2-3-4.res.example.net', channel => '#chan');
my %bob = (nick => 'bob', ident => '~bob', host => 'bob.example.org', channel => '#chan');

sub store_with {
    my (%opt) = @_;
    my $store = Profiler::Store->new(tempdir(CLEANUP => 1));
    $store->record('efnet', { %troll }, $NOW - $_ * $DAY, 'consistent') for 2 .. 11;
    $store->record('efnet', { %bob }, $NOW - $_ * $DAY, 'consistent') for 2 .. 21;
    $store->record_kick('efnet', { %troll, by => 'op', reason => 'shamed' }, $NOW - ($opt{kicked_days_ago} // 1) * $DAY);
    # Someone else wore bob's nick and got kicked for it.
    my %impostor = (%bob, ident => 'creep', host => 'proxy.example.com', realname => 'creepy');
    $store->record('efnet', { %impostor }, $NOW - $DAY, 'suspect');
    $store->record_kick('efnet', { %impostor, by => 'op', reason => 'creep' }, $NOW - $DAY);
    return $store;
}

sub search { Profiler::Evasion::best_match($_[0], 'efnet', $_[1]{nick}, $_[1], $NOW) }

subtest 'a kicked troll back on a new nick' => sub {
    my $m = search(store_with(), { %troll, nick => 'n3wguy', host => 'cpe-1-2-9-9.res.example.net' });
    is($m->{nick}, 'trollguy', 'found');
    ok($m->{result}{match} >= $Profiler::Score::CONSISTENT_AT, "fits their history (match $m->{result}{match})");
    is($m->{marks}[0]{reason}, 'shamed', 'with their record');
};

subtest 'nobody like them' => sub {
    is(search(store_with(), { nick => 'carol', ident => '~carol', host => 'c.example.com', channel => '#chan' }), undef,
        'nothing found');
};

subtest 'the troll on their own nick is not an evader' => sub {
    is(search(store_with(), { %troll }), undef, 'their own record is shown on their own line instead');
};

subtest 'a kick long ago no longer counts' => sub {
    is(search(store_with(kicked_days_ago => 400), { %troll, nick => 'n3wguy' }), undef, 'not found');
};

# The host isn't judged on a proxy, so the ident is all that's left.
my %creep = (nick => 'creep2', ident => 'creep', host => '50-1-2-3.ip.example.net', ip => '50.1.2.3', proxy => 'example',
    channel => '#chan');

subtest 'an ident alone is too little to go on' => sub {
    is(search(store_with(), { %creep }), undef, 'not found');
};

subtest 'an ident with the same realname is enough' => sub {
    my $m = search(store_with(), { %creep, realname => 'creepy' });
    is($m && $m->{nick}, 'bob', 'found');
};

subtest 'a nick we know well only evades a kick from before it showed up' => sub {
    my $store = store_with();
    my $joiner = { %troll, nick => 'n3wguy', host => 'cpe-1-2-9-9.res.example.net' };
    my $m = Profiler::Evasion::best_match($store, 'efnet', 'n3wguy', $joiner, $NOW, $NOW - $DAY / 2);
    is($m && $m->{nick}, 'trollguy', 'kicked before it showed up: found');
    is(Profiler::Evasion::best_match($store, 'efnet', 'n3wguy', $joiner, $NOW, $NOW - 5 * $DAY), undef,
        'kicked after it showed up: not found');
};

subtest 'an impostor kicked on a nick is told apart from the nick' => sub {
    my $store = store_with();
    my $m = search($store, { %bob, nick => 'creep2', ident => 'creep', host => 'proxy.example.com' });
    is($m->{nick}, 'bob', 'the creep is found under the nick they wore');
    is(search($store, { %bob, nick => 'bob_away' }), undef, 'but bob himself on another nick is not');
};

done_testing;
