use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use File::Temp qw(tempdir);
use Test::More;

use Profiler::Label;
use Profiler::Store;

my $DAY = 86400;
my $NOW = 1_000_000_000;

my %bob = (nick => 'Bob', ident => '~bob', host => 'cpe-1-2-3-4.res.example.net', channel => '#chan');
my %troll = (nick => 'TrollGuy', ident => 'uid123', host => 'ilkley.irccloud.com', channel => '#chan');

sub store_with {
    my $store = Profiler::Store->new(tempdir(CLEANUP => 1));
    for my $who (\%bob, \%troll) {
        $store->record('efnet', {%$who}, $NOW - $_ * $DAY, 'consistent') for 2 .. 11;
    }
    return $store;
}

sub label_for { Profiler::Label::for_join($_[0], 'efnet', $_[1]{nick}, $_[1], $NOW) }

subtest 'a label shows when the join comes from a host the nick has used' => sub {
    my $store = store_with();
    $store->set_label('efnet', 'bob', 'good', $NOW);
    is_deeply(label_for($store, { %bob, nick => 'bob' }), { label => 'good', nick => 'Bob' }, 'found');
    is(label_for($store, { %bob, host => 'cpe-1-2-3-5.res.example.net' }), undef,
        'not from a neighbouring address, since anyone at the ISP has one');
    is(label_for($store, { %bob, host => 'elsewhere.example.org' }), undef, 'or somewhere else');
};

subtest 'a held join from a host does not make it theirs' => sub {
    my $store = store_with();
    $store->set_label('efnet', 'bob', 'good', $NOW);
    $store->record('efnet', { %bob, ident => 'creep', host => 'proxy.example.com' }, $NOW - $DAY, 'suspect');
    is(label_for($store, { %bob, ident => 'creep', host => 'proxy.example.com' }), undef, 'not found');
};

subtest 'on IRCCloud it goes by the account' => sub {
    my $store = store_with();
    $store->set_label('efnet', 'trollguy', 'neutral', $NOW);
    is(label_for($store, {%troll})->{label}, 'neutral', 'same account');
    is(label_for($store, { %troll, ident => 'uid999' }), undef, 'not someone else on the same IRCCloud server');
};

subtest 'a nick with a label but no history' => sub {
    my $store = store_with();
    $store->set_label('efnet', 'carol', 'good', $NOW);
    is(label_for($store, { %bob, nick => 'carol' }), undef, 'has nothing to fit');
};

subtest 'BAD follows the person onto other nicks' => sub {
    my $store = store_with();
    $store->set_label('efnet', 'trollguy', 'bad', $NOW);
    is_deeply(label_for($store, { %troll, nick => 'n3wguy' }), { label => 'bad', nick => 'TrollGuy' }, 'found');
    is(label_for($store, { %troll, nick => 'n3wguy', ident => 'uid999' }), undef,
        'not someone else on the same IRCCloud server');
};

subtest 'GOOD and NEUTRAL stay with the nick' => sub {
    my $store = store_with();
    $store->set_label('efnet', 'bob', 'good', $NOW);
    $store->set_label('efnet', 'trollguy', 'neutral', $NOW);
    is(label_for($store, { %bob, nick => 'bob_' }), undef, 'GOOD');
    is(label_for($store, { %troll, nick => 'n3wguy' }), undef, 'NEUTRAL');
};

subtest "the nick's own label comes first" => sub {
    my $store = store_with();
    $store->set_label('efnet', 'trollguy', 'bad', $NOW);
    $store->record('efnet', { %troll, nick => 'n3wguy' }, $NOW - $_ * $DAY, 'consistent') for 2 .. 5;
    $store->set_label('efnet', 'n3wguy', 'neutral', $NOW);
    is_deeply(label_for($store, { %troll, nick => 'n3wguy' }), { label => 'neutral', nick => 'n3wguy' },
        'NEUTRAL on their nick, though they were BAD as someone else');
};

subtest 'nobody labelled' => sub {
    is(label_for(store_with(), {%bob}), undef, 'nothing');
};

done_testing;
