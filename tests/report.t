use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use Test::More;

use Profiler::Report;

my %job = (nick => 'bob', ident => '~bob', host => 'host.example.net', version => 'irssi v1.4.5');
my %consistent = (verdict => 'consistent', trust => 0.9, match => 0.93, confidence => 0.97,
    parts => { host => 0.9, ident => 0.98 });
my %linode = (ip => '192.0.2.95', org => 'Linode', proxy => 'linode');

sub line {
    my ($r, %ctx) = @_;
    return [ Profiler::Report::verdict_line(\%job, $r, { count => 10, min => 0.5, %ctx }) ];
}

subtest 'a consistent join says nothing unless asked' => sub {
    is_deeply(line(\%consistent), [], 'quiet');
    my ($word, $text) = @{ line(\%consistent, verbose => 1) };
    is($word, 'CONFIDENT', 'verbose');
    like($text, qr/^bob \(~bob\@host\.example\.net, client: irssi v1\.4\.5\) has trust \+0\.90/, $text);
};

subtest 'under the minimum, thin history is unproven and anything against them is a warning' => sub {
    my ($word, $text) = @{ line({ %consistent, trust => 0.33, confidence => 0.57 }) };
    is($word, 'UNPROVEN', 'everything matches, there just is not much of it');
    like($text, qr/has trust \+0\.33 .* under 0\.5/, $text);

    ($word, $text) = @{ line({ %consistent, verdict => 'mixed', trust => 0.1, match => 0.15,
        parts => { host => -0.8, ident => 0.9, channel => -1 } }) };
    is($word, 'WARNING', 'something counts against them');
    like($text, qr/\[channel=-1\.00 host=-0\.80 ident=\+0\.90\]/, 'and the parts say what');
};

subtest 'a likely proxy is one warning line, whatever the verdict' => sub {
    my $proxy = qr/on a likely VPN, proxy or hosting address \(192\.0\.2\.95, Linode, matched 'linode'\)/;

    my $lines = line(\%consistent, hostinfo => \%linode);
    is(scalar @$lines, 2, 'one line') or return;
    is($lines->[0], 'WARNING', 'a warning');
    like($lines->[1], $proxy, 'says why');
    like($lines->[1], qr/trust \+0\.90 \(consistent/, 'and still gives the verdict');

    my ($word, $text) = @{ line({ %consistent, trust => 0.4 }, hostinfo => \%linode) };
    is($word, 'WARNING', 'under the minimum too');
    like($text, qr/under 0\.5/, 'says it is under the minimum');
    like($text, $proxy, 'and on a proxy');

    ($word, $text) = @{ line({ %consistent, verdict => 'suspect', match => -0.3 }, hostinfo => \%linode) };
    is($word, 'SUSPECT', 'a suspect stays a suspect');
    like($text, $proxy, 'on a proxy');

    ($word, $text) = @{ line({ %consistent, verdict => 'new host', parts => { host => -0.5, ident => 0.9 } },
        hostinfo => \%linode) };
    is($word, 'WARNING', 'a new host on a proxy is a warning');
    like($text, qr/ident matches/, 'still says what matches');
    like($text, $proxy, 'and why');
};

subtest 'nicks they change between' => sub {
    my (undef, $text) = @{ line(\%consistent, verbose => 1, other_nicks => [qw(zed lex lexie dodo)]) };
    like($text, qr/changes nicks often, also zed, lex, lexie and 1 more$/, $text);
    (undef, $text) = @{ line(\%consistent, verbose => 1, other_nicks => [qw(zed lex lexie)]) };
    like($text, qr/also zed, lex, lexie$/, 'three are all shown');
};

subtest 'a variant goes after the verdict, coloured by how well it fits' => sub {
    my %variant = (nick => 'Sneezy', result => { verdict => 'consistent', trust => 0.34,
        parts => { host => 0.5, ident => 1, realname => 1, version => 1, channel => 1 } });
    my ($word, $vword, $text) = Profiler::Report::variant_line({ %job, nick => 'Sneezy_' }, \%variant, 'UNKNOWN', 'never seen before');
    is($word, 'UNKNOWN', 'keeps the verdict word');
    is($vword, 'VARIANT consistent', 'and adds one for the variant');
    is($text, 'never seen before; looks like Sneezy: host, ident, realname, client match; trust +0.34 against their history', $text);

    ($word, $vword, $text) = Profiler::Report::variant_line({ %job, nick => 'bob_' },
        { %variant, nick => 'bob', linked => 1, result => { %{ $variant{result} }, verdict => 'mixed' } });
    is($word, undef, 'with no verdict line');
    is($vword, 'VARIANT mixed', 'the variant word comes alone');
    like($text, qr/^bob_ looks like bob, who they've switched nicks with before: /, $text);
};

done_testing;
