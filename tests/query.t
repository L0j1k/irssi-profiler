use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use Test::More;

use Profiler::Query;

sub parse { [ Profiler::Query::parse($_[0]) ] }

subtest 'a single term' => sub {
    my ($terms, $page) = Profiler::Query::parse("version '*HexChat 2.16.2*'");
    is_deeply($terms, [ { field => 'version', pattern => '*HexChat 2.16.2*' } ], 'field and quoted pattern');
    is($page, 1, 'page defaults to 1');

    ($terms) = Profiler::Query::parse('realname bob smith');
    is_deeply($terms, [ { field => 'realname', pattern => 'bob smith' } ], 'an unquoted pattern keeps its spaces');

    ($terms) = Profiler::Query::parse('nick BoB');
    is($terms->[0]{field}, 'nick', 'the field is lowercased') or diag $terms->[0]{field};
    is($terms->[0]{pattern}, 'BoB', 'the pattern keeps its case');
};

subtest 'a trailing page number' => sub {
    my ($terms, $page) = Profiler::Query::parse("version '*x*' 3");
    is_deeply($terms, [ { field => 'version', pattern => '*x*' } ], 'pattern without the page');
    is($page, 3, 'page read off the end');

    ($terms, $page) = Profiler::Query::parse('nick *bob* 2');
    is($terms->[0]{pattern}, '*bob*', 'an unquoted pattern and a page');
    is($page, 2, 'page');

    ($terms, $page) = Profiler::Query::parse('version 2');
    is($terms->[0]{pattern}, '2', 'a lone number is the pattern, not a page');
    is($page, 1, 'default page');

    ($terms, $page) = Profiler::Query::parse("version '2.16.2' ");
    is($terms->[0]{pattern}, '2.16.2', 'a quoted pattern that is a number stays the pattern');
    is($page, 1, 'no page');
};

subtest 'combining terms' => sub {
    my ($terms) = Profiler::Query::parse("version '*HexChat 2.16.2*' && nick '*presonic*'");
    is_deeply($terms, [
        { field => 'version', pattern => '*HexChat 2.16.2*' },
        { field => 'nick', pattern => '*presonic*', op => 'AND' },
    ], 'two terms joined with &&');

    ($terms) = Profiler::Query::parse("host '*.example.net' || host '*.example.org' || nick bob 5");
    is(scalar @$terms, 3, 'three terms');
    is_deeply([ map { $_->{op} } @$terms ], [ undef, 'OR', 'OR' ], 'ors between them');
    is($terms->[2]{pattern}, 'bob', 'the page is not swallowed into the last pattern');
    is((Profiler::Query::parse("host '*.example.net' || host '*.example.org' || nick bob 5"))[1], 5, 'page');
};

subtest 'an operator inside a quoted pattern is not a separator' => sub {
    my ($terms) = Profiler::Query::parse("realname 'tom && jerry' && nick bob");
    is_deeply($terms, [
        { field => 'realname', pattern => 'tom && jerry' },
        { field => 'nick', pattern => 'bob', op => 'AND' },
    ], 'the quoted && stays in the pattern, the bare one splits');
};

subtest 'describe writes the terms back out' => sub {
    my ($terms) = Profiler::Query::parse("version '*HexChat*' && nick '*bob*'");
    is(Profiler::Query::describe($terms), "version matches '*HexChat*' && nick matches '*bob*'", 'with the operator');
};

subtest 'malformed expressions' => sub {
    is_deeply(parse(''), [], 'empty');
    is_deeply(parse('version'), [], 'a field with no pattern');
    is_deeply(parse("version '*x*' &&"), [], 'a dangling operator leaves a term with no pattern');
};

done_testing;
