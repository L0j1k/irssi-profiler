use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use Test::More;

use Profiler::Nick;

sub skel { Profiler::Nick::skeleton($_[0]) }

subtest 'jupe-driven variants share a skeleton' => sub {
    is(skel($_), 'bob', "$_ is bob") for qw(bob Bob bob_ bob__ bob` B0B` bobbb bob2 bob|away bob^ _bob_ [bob] bob- b0b);
};

subtest 'different names stay different' => sub {
    isnt(skel('bobby'), skel('bob'), 'bobby is not bob');
    isnt(skel('rob'), skel('bob'), 'rob is not bob');
    is(skel('anna'), 'ana', 'repeated letters collapse anywhere');
};

subtest 'leet only inside the name, after trailing digits are gone' => sub {
    is(skel('l33t'), 'let', 'l33t');
    is(skel('h4x0r'), 'haxor', 'h4x0r');
    is(skel('bob2000'), 'bob', 'a trailing number is junk, not leet');
};

subtest 'a nick that is all junk keeps itself' => sub {
    is(skel('___'), '___', 'underscores');
    is(skel('1234'), '1234', 'digits');
};

done_testing;
