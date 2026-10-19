use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use Test::More;

use Profiler::Whois;

sub fixture {
    my ($name) = @_;
    my $path = "$FindBin::Bin/fixtures/whois-$name.txt";
    open my $fh, '<', $path or die "cannot read $path: $!";
    local $/;
    return <$fh>;
}

my @keywords = @Profiler::Whois::DEFAULT_PROXY_KEYWORDS;

subtest 'RIPE record' => sub {
    my $rec = Profiler::Whois::parse(fixture('tor-artikel10'));
    is($rec->{netname}, 'ARTIKEL10', 'netname');
    is($rec->{org}, 'Artikel10 e.V.', 'org');
    is($rec->{origin}, 'AS60729', 'origin');
    is(Profiler::Whois::proxy_reason($rec, \@keywords), 'tor', 'tor relay operator flagged');
};

subtest 'ARIN record with a parent and child network' => sub {
    my $rec = Profiler::Whois::parse(fixture('comcast'));
    is($rec->{netname}, 'POMPANO-4', 'most specific netname wins');
    like($rec->{org}, qr/^Comcast/, 'org');
    is(Profiler::Whois::proxy_reason($rec, \@keywords), undef, 'residential ISP not flagged');
};

subtest 'hosting provider' => sub {
    my $rec = Profiler::Whois::parse(fixture('digitalocean'));
    is(Profiler::Whois::proxy_reason($rec, \@keywords), 'digitalocean', 'flagged by name');
};

subtest 'who an address belongs to' => sub {
    is(Profiler::Whois::provider(Profiler::Whois::parse(fixture('comcast'))), 'comcast cable communications, llc',
        'the organisation, lowercased');
    is(Profiler::Whois::provider({ origin => 'AS60729' }), 'as60729', 'or the AS without one');
    is(Profiler::Whois::provider({ org => 'RIPE Network Coordination Centre', netname => 'M247-LTD-Prague',
        origin => 'AS9009' }), 'as9009', 'or when the organisation is only the registry that handed it out');
    is(Profiler::Whois::provider({ org => 'Asia Pacific Network Information Centre' }), undef, 'APNIC too');
    is(Profiler::Whois::provider({ org => "  Telia   Company AB " }), 'telia company ab', 'spacing evened out');
    is(Profiler::Whois::provider({ netname => 'X' }), undef, 'nothing to go on');
    is(Profiler::Whois::provider({ error => 'no answer' }), undef, 'or a failed lookup');
};

subtest 'keywords match whole words only' => sub {
    my $rec = { text => 'Acme Storage Inc' };
    is(Profiler::Whois::proxy_reason($rec, ['tor']), undef, 'tor inside storage does not count');
    is(Profiler::Whois::proxy_reason($rec, ['acme storage']), 'acme storage', 'multi-word keyword');
};

subtest 'a notproxy phrase overrides the keywords' => sub {
    # Boost Mobile's addresses are registered to Amazon, since it runs on AWS.
    my $rec = { text => "NetName: AMAZON-DISH\nOrganization: Boost Mobile" };
    is(Profiler::Whois::proxy_reason($rec, \@keywords), 'amazon', 'flagged on its own');
    is(Profiler::Whois::proxy_reason($rec, \@keywords, ['boost mobile']), undef, 'not with notproxy boost mobile');
    is(Profiler::Whois::proxy_reason($rec, \@keywords, ['boost']), undef, 'whole words, like keywords');
    is(Profiler::Whois::proxy_reason($rec, \@keywords, ['oost']), 'amazon', 'and not inside them');
};

subtest 'lookup on a host that does not resolve' => sub {
    my $res = Profiler::Whois::lookup('user/bob', \@keywords, 10);
    is($res->{ip}, undef, 'no ip');
    like($res->{error}, qr/resolve/, 'says why');
};

subtest 'lookup on a real address' => sub {
    plan skip_all => 'set PROFILER_LIVE_TESTS=1 to run whois against the network'
        unless $ENV{PROFILER_LIVE_TESTS};
    my $res = Profiler::Whois::lookup('185.220.101.1', \@keywords, 30);
    is($res->{ip}, '185.220.101.1', 'ip kept');
    is($res->{proxy}, 'tor', 'flagged');
};

done_testing;
