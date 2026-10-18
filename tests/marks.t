use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use POSIX qw(strftime);
use Test::More;

use Profiler::Marks;
use Profiler::Score;

my $DAY = 86400;
my $NOW = 1_000_000_000;

subtest 'ban masks' => sub {
    ok(Profiler::Marks::mask_matches('*!*@*.myvzw.com', 'bob', '~debian', '226.sub-203-0-113.MYVZW.com'), 'host glob');
    ok(Profiler::Marks::mask_matches('*!~lol@*', 'troll', '~lol', 'a.example'), 'ident');
    ok(Profiler::Marks::mask_matches('Troll!*@*', 'troll', '~x', 'a.example'), 'nick, any case');
    ok(Profiler::Marks::mask_matches('t?oll!*@*', 'troll', '~x', 'a.example'), 'one character');
    ok(!Profiler::Marks::mask_matches('*!*@*.myvzw.com', 'bob', '~debian', 'myvzw.com.evil.example'), 'anchored');
    ok(!Profiler::Marks::mask_matches('*!*@a.b', 'bob', '~x', 'aXb'), 'dots are dots');
};

subtest 'who a ban was for' => sub {
    my @here = (
        { nick => 'troll', ident => '~lol', host => 'a.example.org' },
        { nick => 'bob', ident => '~bob', host => 'cpe-1-2-3-4.example.net' },
        { nick => 'troll', ident => '~lol', host => 'b.example.org' },
    );
    is_deeply([ Profiler::Marks::banned('*!~lol@*', \@here) ], [ $here[0] ], 'each nick once, as first matched');
    is_deeply([ Profiler::Marks::banned('*!*@*.nowhere', \@here) ], [], 'nobody');
    my @crowd = map { { nick => "n$_", ident => '~x', host => "h$_.example.net" } } 1 .. 4;
    is_deeply([ Profiler::Marks::banned('*!*@*.example.net', \@crowd) ], [], 'too many to say who it was for');
};

subtest 'how much a record of kicks and bans counts' => sub {
    my $kick = sub { { kind => 'kick', time => $NOW - $_[0] * $DAY, by => 'op', channel => '#chan', reason => 'r' } };
    my $ban = sub { { kind => 'ban', time => $NOW - $_[0] * $DAY, by => 'op', channel => '#chan', mask => '*!*@x' } };
    is(Profiler::Marks::weight([], $NOW), 0, 'nothing');
    is(Profiler::Marks::weight([ $ban->(0) ], $NOW), 1, 'a ban');
    ok(abs(Profiler::Marks::weight([ $ban->(90) ], $NOW) - 0.5) < 1e-9, 'fades with the half-life');
    is(Profiler::Marks::weight([ $kick->(0) ], $NOW), 0.5, 'a kick is half a ban');
    ok(abs(Profiler::Marks::weight([ $kick->(90) ], $NOW) - 0.25) < 1e-9, 'and fades the same way');
    ok(Profiler::Marks::counts([ $ban->(150) ], $NOW), 'a ban counts for two half-lives');
    ok(!Profiler::Marks::counts([ $ban->(200) ], $NOW), 'but not after');
    ok(Profiler::Marks::counts([ $kick->(30) ], $NOW), 'a kick counts for one');
    ok(!Profiler::Marks::counts([ $kick->(100) ], $NOW), 'but not after');
};

subtest 'the kicks and bans that say something about a join' => sub {
    my @marks = (
        { kind => 'kick', time => $NOW, by => 'op', channel => '#chan' },
        { kind => 'ban', time => $NOW, by => 'netbot', channel => '#efnet' },
        { kind => 'kick', time => $NOW, by => 'Bob', channel => '#chan' },
    );
    is_deeply(Profiler::Marks::in_channel(\@marks, 'bob', '#CHAN'), [ $marks[0] ],
        "only the channel joined, and not the ones they set on themselves");
};

subtest 'summary' => sub {
    my $t = $NOW - 10 * $DAY;
    my @marks = (
        { kind => 'kick', time => $t - $DAY, by => 'op', channel => '#chan', reason => 'spam' },
        { kind => 'ban', time => $t, by => 'alice', channel => '#chan', mask => '*!*@x' },
        { kind => 'kick', time => $t, by => 'alice', channel => '#chan', reason => 'shamed' },
    );
    my $date = strftime('%Y-%m-%d', localtime $t);
    is(Profiler::Marks::summary(\@marks), "banned 1x, kicked 2x, last $date by alice (shamed)", 'counts and the latest');
    is(Profiler::Marks::summary([ $marks[1] ]), "banned 1x, last $date by alice", 'a ban has no reason');
};

done_testing;
