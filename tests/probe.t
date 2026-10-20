use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use Test::More;
use IO::Socket::IP;

use Profiler::Probe;

subtest 'parse_ports' => sub {
    is_deeply([ Profiler::Probe::parse_ports('22, 80 443,6697') ], [22, 80, 443, 6697],
        'commas and spaces, sorted');
    is_deeply([ Profiler::Probe::parse_ports('443,22,443,22') ], [22, 443], 'deduped and sorted');
    is_deeply([ Profiler::Probe::parse_ports('0 70000 -5 http 22') ], [22],
        'out-of-range and non-numeric dropped');
    is_deeply([ Profiler::Probe::parse_ports('') ], [], 'empty spec is no ports');
};

subtest 'clean_banner' => sub {
    is(Profiler::Probe::clean_banner("SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n"),
        'SSH-2.0-OpenSSH_9.2p1 Debian-2', 'trailing CRLF trimmed');
    is(Profiler::Probe::clean_banner("\x00\x1b[31mmessy\x07  text "), '[31mmessy text',
        'control characters stripped, whitespace collapsed');
    is(Profiler::Probe::clean_banner('x' x 1000), 'x' x 200, 'long banners cut to 200');
    is(Profiler::Probe::clean_banner("   \r\n  "), undef, 'a silent port has no banner');
    is(Profiler::Probe::clean_banner(undef), undef, 'nothing read is no banner');
};

subtest 'signature' => sub {
    is(Profiler::Probe::signature([
        { port => 6697, open => 1 }, { port => 22, open => 1 }, { port => 80, open => 0 },
    ]), '22,6697', 'open ports only, sorted');
    is(Profiler::Probe::signature([ { port => 22, open => 0 } ]), '', 'nothing open is an empty signature');
    is(Profiler::Probe::signature([]), '', 'no probe results is an empty signature');
};

subtest 'banner_text' => sub {
    is(Profiler::Probe::banner_text([
        { port => 22, open => 1, banner => 'SSH-2.0-OpenSSH_9.2' },
        { port => 80, open => 1 },
        { port => 443, open => 0 },
    ]), '22=SSH-2.0-OpenSSH_9.2', 'only open ports that spoke, as port=banner');
    is(Profiler::Probe::banner_text([
        { port => 22, open => 1, banner => 'SSH-2.0-OpenSSH_9.2' },
        { port => 6697, open => 1, banner => ':irc.example NOTICE AUTH :*** Looking up' },
    ]), '22=SSH-2.0-OpenSSH_9.2 | 6697=:irc.example NOTICE AUTH :*** Looking up',
        'several banners joined');
    is(Profiler::Probe::banner_text([ { port => 22, open => 1 } ]), undef, 'no banners is undef');
};

subtest 'proxy_port_in' => sub {
    is(Profiler::Probe::proxy_port_in('22,443,9050', [9050, 1080]), 9050, 'tor socks found');
    is(Profiler::Probe::proxy_port_in('1080,3128', \@Profiler::Probe::DEFAULT_PROXY_PORTS), 1080,
        'lowest matching proxy port from the default set');
    is(Profiler::Probe::proxy_port_in('22,6697', [9050, 1080]), undef, 'no proxy ports open');
    is(Profiler::Probe::proxy_port_in('', [9050]), undef, 'empty signature has none');
    is(Profiler::Probe::proxy_port_in('8080', [9050, 1080]), undef,
        '8080 is not a proxy port by default');
};

# The real socket I/O: stand up a listener that sends a banner, probe it, and
# probe a port nothing is listening on. No mocks, just loopback.
subtest 'probe against a real listener' => sub {
    my $server = IO::Socket::IP->new(
        LocalHost => '127.0.0.1', LocalPort => 0, Listen => 1, ReuseAddr => 1, Proto => 'tcp',
    ) or plan skip_all => "cannot listen on loopback: $!";
    my $open_port = $server->sockport;

    # A second socket bound and closed gives us a port nothing answers on.
    my $closed = IO::Socket::IP->new(
        LocalHost => '127.0.0.1', LocalPort => 0, Listen => 1, ReuseAddr => 1, Proto => 'tcp');
    my $closed_port = $closed->sockport;
    $closed->close;

    my $pid = fork;
    die "cannot fork: $!" unless defined $pid;
    if ($pid == 0) {
        my $client = $server->accept;
        print $client "SSH-2.0-OpenSSH_test\r\n" if $client;
        close $client if $client;
        $server->close;
        exit 0;
    }
    $server->close;

    my $results = Profiler::Probe::probe('127.0.0.1', [$open_port, $closed_port], 3, 3, 200);
    waitpid $pid, 0;

    my %by_port = map { $_->{port} => $_ } @$results;
    ok($by_port{$open_port}{open}, 'listening port reported open');
    is($by_port{$open_port}{banner}, 'SSH-2.0-OpenSSH_test', 'banner read and cleaned');
    ok(!$by_port{$closed_port}{open}, 'unused port reported closed');
    ok(!exists $by_port{$closed_port}{banner}, 'closed port has no banner');
};

done_testing;
