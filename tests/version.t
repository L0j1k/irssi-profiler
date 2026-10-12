use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use Test::More;

use Profiler::Version;

subtest 'clean' => sub {
    is(Profiler::Version::clean("irssi v1.4.5 - running on Linux x86_64"),
        'irssi v1.4.5 - running on Linux x86_64', 'ordinary reply untouched');
    is(Profiler::Version::clean("\x02evil\x03" . "4red\x1b[31m text\x00"), 'evil4red[31m text',
        'control characters removed');
    is(Profiler::Version::clean("  spaced   out \t "), 'spaced out', 'whitespace collapsed');
    is(length Profiler::Version::clean('x' x 1000), 200, 'long replies cut');
    is(Profiler::Version::clean(''), $Profiler::Version::NO_REPLY, 'empty reply counts as no reply');
};

subtest 'client' => sub {
    is(Profiler::Version::client('irssi v1.4.5 - running on Linux'), 'irssi', 'irssi');
    is(Profiler::Version::client('HexChat 2.16.1 [x64] / Linux'), 'hexchat', 'lowercased');
    is(Profiler::Version::client('mIRC v7.71 Khaled Mardam-Bey'), 'mirc', 'mirc');
    is(Profiler::Version::client($Profiler::Version::NO_REPLY), $Profiler::Version::NO_REPLY,
        'no reply is its own client');
};

done_testing;
