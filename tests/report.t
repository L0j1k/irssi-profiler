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

done_testing;
