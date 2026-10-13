use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use File::Temp qw(tempdir);
use Test::More;

use Profiler::Score;
use Profiler::Store;
use Profiler::Variants;

my $NOW = 1_000_000_000;
my %bob = (host => 'host.example.net', ip => '10.10.10.2', ident => '~bob', channel => '#chan');
my %troll = (host => 'troll.example.org', ip => '192.0.2.66', ident => 'lol', channel => '#chan');

# A store with 10 recent sightings for each nick => fingerprint pair.
sub store_with {
    my (%who) = @_;
    my $store = Profiler::Store->new(tempdir(CLEANUP => 1));
    for my $nick (sort keys %who) {
        $store->record('efnet', { %{ $who{$nick} }, nick => $nick }, $NOW - $_ * 3600, 'consistent') for reverse 1 .. 10;
    }
    return $store;
}

sub best { Profiler::Variants::best_match($_[0], 'efnet', $_[1], $_[2], $NOW) }

subtest 'a variant nick from the usual host and ident' => sub {
    my $store = store_with(Bob => \%bob);
    my $m = best($store, 'bob_', \%bob);
    is($m->{nick}, 'Bob', 'looks like Bob');
    is($m->{result}{verdict}, 'consistent', 'judged against his history');
    ok(!$m->{linked}, 'found by the nick, not a link');
};

subtest 'a variant nick from someone else is nobody' => sub {
    is(best(store_with(Bob => \%bob), 'B0B`', \%troll), undef, 'no match');
};

subtest 'a nick linked by a nick change counts even if it looks nothing alike' => sub {
    my $store = store_with(bob => \%bob);
    $store->link_nicks('efnet', 'cybnat', 'bob', $NOW - 86400);
    my $m = best($store, 'cybnat', \%bob);
    is($m->{nick}, 'bob', 'looks like bob');
    ok($m->{linked}, 'through the link');
};

subtest 'the closest of several variants wins' => sub {
    # Same host as bob, so bob is a passable match too, but bobb's ident fits.
    my %other = (%bob, ident => '~bobb');
    my $store = store_with(bob => \%bob, bobb => \%other);
    my $against_bob = Profiler::Score::judge($store->profile('efnet', 'bob'), \%other, $NOW);
    like($against_bob->{verdict}, qr/^(consistent|mixed)$/, 'bob alone would pass');
    is(best($store, 'bob_', \%other)->{nick}, 'bobb', 'but bobb fits better');
};

subtest 'a nick is never its own variant' => sub {
    is(best(store_with(bob => \%bob), 'bob', \%bob), undef, 'only bob exists');
};

subtest 'linked nicks with no sightings are skipped' => sub {
    my $store = store_with(bob => \%bob);
    $store->link_nicks('efnet', 'ghost', 'bob_', $NOW);
    is(best($store, 'bob_', \%troll), undef, 'nothing to judge against');
};

subtest 'unknown network' => sub {
    is(Profiler::Variants::best_match(store_with(), 'other', 'bob_', \%bob, $NOW), undef, 'nothing');
};

subtest 'someone who changes nicks often' => sub {
    my $store = store_with();
    my $t = $NOW;
    $store->link_nicks('efnet', 'hugo', $_, $t++) for qw(zed lex lexie);
    $store->link_nicks('efnet', 'lex', 'stranger', $t++);

    my @others = Profiler::Variants::changes_nicks_often($store, 'efnet', 'hugo');
    is_deeply(\@others, [qw(lexie lex zed)], 'one hop away, latest first');
    is_deeply([ Profiler::Variants::changes_nicks_often($store, 'efnet', 'Dodo', 'hugo') ], \@others,
        'from either side of a nick change, leaving both out');

    $store->link_nicks('efnet', 'dodo', 'hugo', $t++);
    is_deeply([ Profiler::Variants::changes_nicks_often($store, 'efnet', 'dodo', 'hugo') ], \@others,
        'the change being made is not counted');
    is_deeply([ Profiler::Variants::changes_nicks_often($store, 'efnet', 'stranger') ], [],
        'one other nick is not often');
    is_deeply([ Profiler::Variants::changes_nicks_often($store, 'other', 'hugo') ], [], 'unknown network');
};

done_testing;
