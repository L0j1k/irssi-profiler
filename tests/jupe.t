use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use File::Temp qw(tempdir);
use Test::More;

use Profiler::Jupe;
use Profiler::Store;

my $NOW = 1_000_000_000;
my %bob = (host => 'host.example.net', ip => '10.10.10.2', ident => '~bob', realname => 'Bob', channel => '#chan');
my %troll = (host => 'troll.example.org', ip => '192.0.2.66', ident => 'lol', realname => 'x', channel => '#chan');

# A store where Bob has joined ten times, as himself.
sub bob_store {
    my $store = Profiler::Store->new(tempdir(CLEANUP => 1));
    $store->record('efnet', { %bob, nick => 'Bob' }, $NOW - $_ * 3600, 'consistent') for reverse 1 .. 10;
    return $store;
}

subtest 'who a joiner on a variant nick may be waiting for' => sub {
    my $store = bob_store();
    my $waiting = Profiler::Jupe::waiting_for($store, 'efnet', 'bob_', \%bob, $NOW);
    is($waiting->{nick}, 'Bob', 'bob_ from the usual host and ident is waiting for Bob');
    is(Profiler::Jupe::waiting_for($store, 'efnet', 'bob_', \%troll, $NOW), undef, 'someone else on bob_ is not');
    is(Profiler::Jupe::waiting_for($store, 'efnet', 'Bob', \%bob, $NOW), undef, 'nor is Bob on his own nick');
    is(Profiler::Jupe::waiting_for($store, 'efnet', 'bob_', { %bob, host => 'elsewhere.example.org', ip => '192.0.2.9' }, $NOW),
        undef, 'and only a consistent match counts, not a mixed one');
};

subtest 'whether whoever holds the nick is juping it' => sub {
    my $store = bob_store();
    my $juper = sub { Profiler::Jupe::juper($store, 'efnet', { %{ $_[0] }, nick => $_[1] // 'bob' }, $NOW) };
    my $r = $juper->(\%troll);
    ok($r, 'a stranger on the nick is');
    ok($r->{parts}{ident} < 0, 'with what disagrees');
    is($juper->(\%bob), undef, 'Bob himself is not');
    is($juper->({ %bob, host => 'phone.example.com', ip => '198.51.100.4' }), undef,
        'nor is Bob on a second client somewhere else');
    is($juper->(\%troll, 'nobody'), undef, 'a nick with no history has nothing to jupe');
};

done_testing;
