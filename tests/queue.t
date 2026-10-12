use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use Test::More;

use Profiler::Queue;

sub queue {
    return Profiler::Queue->new(
        interval => 2, burst_joins => 3, burst_window => 10, burst_pause => 60, max_len => 4, @_,
    );
}

subtest 'jobs come out in order, one per interval' => sub {
    my $q = queue();
    $q->add('a', 'job a', 0);
    $q->add('b', 'job b', 5);
    is($q->take(5), 'job a', 'first job right away');
    is($q->take(6), undef, 'too soon for the next');
    is($q->take(7), 'job b', 'next after the interval');
    is($q->take(100), undef, 'empty');
};

subtest 'a key already waiting is not queued twice' => sub {
    my $q = queue();
    ok($q->add('a', 'first', 0), 'added');
    ok(!$q->add('a', 'second', 1), 'duplicate refused');
    is($q->take(1), 'first', 'original kept');
    ok($q->add('a', 'again', 20), 'can queue again once taken');
};

subtest 'a burst of joins pauses whois until it settles' => sub {
    my $q = queue();
    $q->add($_, "job $_", 100) for qw(a b c);
    ok($q->paused(100), 'third join in the window starts a pause');
    is($q->take(150), undef, 'nothing during the pause');

    $q->add('d', 'job d', 150);
    is($q->take(159), undef, 'a lone join does not extend the pause');
    is($q->take(160), 'job a', 'drains after the pause');
    is($q->take(161), undef, 'still throttled while draining');
    is($q->take(162), 'job b', 'next one');
};

subtest 'a burst that keeps going keeps the pause going' => sub {
    my $q = queue(max_len => 100);
    $q->add($_, $_, 100) for qw(a b c);
    $q->add($_, $_, 150) for qw(d e f);
    is($q->take(165), undef, 'pause runs from the latest burst');
    is($q->take(210), 'a', 'then drains');
};

subtest 'joins spread out never trigger a pause' => sub {
    my $q = queue();
    $q->add($_->[0], $_->[0], $_->[1]) for ['a', 0], ['b', 6], ['c', 12];
    ok(!$q->paused(12), 'only two joins in any 10s window');
};

subtest 'a full queue drops new jobs' => sub {
    my $q = queue(burst_joins => 100);
    ok($q->add($_, $_, 0), "added $_") for qw(a b c d);
    ok(!$q->add('e', 'e', 0), 'fifth refused');
    is($q->length, 4, 'length');
};

subtest 'remove' => sub {
    my $q = queue();
    $q->add('a', 'job a', 0);
    $q->add('b', 'job b', 0);
    $q->remove('a');
    is($q->take(0), 'job b', 'removed job skipped');
};

done_testing;
