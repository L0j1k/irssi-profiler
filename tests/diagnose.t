use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use Test::More;

use Profiler::Diagnose;

my $DAY = 86400;
my %bob = (host => 'cpe-1-2-3-4.sd.res.rr.com', ident => '~bob', channel => '#c');

sub ok_at { +{ %bob, @_[1 .. $#_], time => $_[0] * $DAY, verdict => 'consistent', quarantined => 0 } }
sub sus_at { +{ %bob, @_[1 .. $#_], time => $_[0] * $DAY, verdict => 'suspect', quarantined => 1 } }

my $data = { users => {
    # Ident lost its ~, same host. Owner shows up again afterwards.
    bob => { nick => 'bob', sightings => [ (map { ok_at($_) } 1 .. 10), sus_at(10.5, ident => 'bob'), ok_at(12) ] },
    # New host in the same ISP pool, new ident, after a two-year gap, later promoted.
    carol => { nick => 'carol', sightings => [ (map { ok_at($_) } 1 .. 30),
        { %{ sus_at(800, host => 'cpe-9-9-9-9.sd.res.rr.com', ident => 'carol') }, quarantined => 0, reviewed => 1, promoted => 1 } ] },
    # Brand new host and ident.
    dave => { nick => 'dave', sightings => [ (map { ok_at($_) } 1 .. 3), sus_at(3.5, host => 'x.example', ident => 'lol') ] },
    # Nothing suspect.
    erin => { nick => 'erin', sightings => [ map { ok_at($_) } 1 .. 5 ] },
    # Same ident from a new host, held as a new host rather than a suspect.
    finn => { nick => 'finn', sightings => [ (map { ok_at($_) } 1 .. 5),
        { %{ sus_at(5.5, host => 'elsewhere.example') }, verdict => 'new host' } ] },
} };

my $r = Profiler::Diagnose::suspect_report($data);

is($r->{suspects}, 4, 'held sightings');
is($r->{nicks_with_suspects}, 4, 'nicks with any');
is($r->{nicks}, 5, 'nicks in total');
is_deeply($r->{by_verdict}, { suspect => 3, 'new host' => 1 }, 'by verdict');
is_deeply($r->{by_change}, {
    'host same, ident differs only by ~' => 1,
    'host near, ident new'               => 1,
    'host new, ident new'                => 1,
    'host new, ident same'               => 1,
}, 'what changed');
is_deeply($r->{by_gap}, { 'under a day' => 3, 'a year or more' => 1 }, 'time since the last accepted sighting');
is_deeply($r->{by_history}, { '1-4' => 1, '5-19' => 2, '20-99' => 1 }, 'accepted sightings before it');
is_deeply($r->{by_outcome}, { promoted => 1, 'still quarantined' => 3 }, 'outcome');
is($r->{owner_seen_after}, 1, 'the usual person turned up again after one of them');
is_deeply($r->{concentration}, { top_1_percent => 1, top_10_percent => 1 }, 'share held by the top nicks');

done_testing;
