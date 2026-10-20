package Profiler::Probe;

use strict;
use warnings;

use IO::Socket::IP;
use IO::Select;

use Profiler::Host;

# The ports we knock on for a joiner's address. A mix of the services an
# automation node is likely to run and the ports an open proxy or relay
# listens on. The rules file can replace this list with "port <n>" lines.
our @DEFAULT_PORTS = (22, 80, 443, 1080, 3128, 4145, 6667, 6697, 8080, 8118, 9050, 9051);

# Open ports that mean we connected straight through an anonymiser: SOCKS, Tor
# and HTTP proxies. One of these open is the one port signal strong enough to
# call a join suspect on its own. The rules file adds more with "proxyport <n>".
# 8080 is left out on purpose, too much of it is ordinary web.
our @DEFAULT_PROXY_PORTS = (1080, 3128, 4145, 8118, 9050, 9051);

# How much of a banner we keep. Same cut as a CTCP VERSION reply.
my $MAX_BANNER = 200;

# Turn a "22,80 443" style spec into a sorted, deduped list of valid ports.
# Anything that isn't a port number from 1 to 65535 is dropped.
sub parse_ports {
    my ($spec) = @_;
    my %seen;
    for my $tok (split /[\s,]+/, $spec // '') {
        next unless $tok =~ /^\d+$/ && $tok >= 1 && $tok <= 65535;
        $seen{ $tok + 0 } = 1;
    }
    return sort { $a <=> $b } keys %seen;
}

# A banner is whatever a service sent us first, so control characters and runs
# of whitespace go before it's stored or printed. undef when there's nothing
# left, which is a port that opened but stayed silent.
sub clean_banner {
    my ($raw) = @_;
    (my $b = $raw // '') =~ s/[\x00-\x1f\x7f]//g;
    $b =~ s/\s+/ /g;
    $b =~ s/^ | $//g;
    return length $b ? substr($b, 0, $MAX_BANNER) : undef;
}

# The scored fingerprint of a probe: the open ports, sorted, joined with commas.
# An empty string means we probed and nothing was open, which is different from
# never having probed (that's a missing value, see Profiler::Score::has_value).
sub signature {
    my ($results) = @_;
    return join ',', sort { $a <=> $b } map { $_->{port} } grep { $_->{open} } @$results;
}

# The banners we collected, as "port=banner" joined with " | ", for reviewing
# later. undef when nothing spoke. Not scored: the same service on the same
# port still varies from one connection to the next.
sub banner_text {
    my ($results) = @_;
    my @parts = map { "$_->{port}=$_->{banner}" } grep { defined $_->{banner} } @$results;
    return @parts ? join(' | ', @parts) : undef;
}

# Why we'd leave a host alone, or undef when it's fair game. Shared services
# where the address isn't the person's own machine are skipped: a fingerprint
# of them says nothing about who this is, and the scan just hits someone else's
# infrastructure. IRCCloud is the built-in case; the rules file adds more with
# "notprobe <phrase>", matched as a substring of the host name.
sub skip_reason {
    my ($host, $not_probe) = @_;
    return 'irccloud' if Profiler::Host::kind($host) eq 'irccloud';
    my $lc = lc $host;
    for my $phrase (@{ $not_probe // [] }) {
        return $phrase if index($lc, $phrase) >= 0;
    }
    return undef;
}

# The lowest proxy port open in a signature, or undef. $proxy_ports is the list
# that counts as an open proxy (see @DEFAULT_PROXY_PORTS).
sub proxy_port_in {
    my ($signature, $proxy_ports) = @_;
    my %is_proxy = map { $_ => 1 } @$proxy_ports;
    for my $port (sort { $a <=> $b } grep { length } split /,/, $signature // '') {
        return $port + 0 if $is_proxy{$port};
    }
    return undef;
}

# Read whatever a service says first, up to $bytes, waiting at most $timeout
# seconds. undef when the port stays silent, which plenty of services do until
# spoken to (HTTP, for one). Cleaned before it comes back.
sub read_banner {
    my ($sock, $timeout, $bytes) = @_;
    return undef unless IO::Select->new($sock)->can_read($timeout);
    my $buf = '';
    my $n = sysread($sock, $buf, $bytes);
    return clean_banner(defined $n ? $buf : undef);
}

# Knock on each port of $ip. Returns an arrayref of { port, open, banner },
# banner present only on an open port that said something. This blocks for up
# to ($connect_timeout + $banner_timeout) per port, so the caller runs it in
# the same child process as the whois lookup.
sub probe {
    my ($ip, $ports, $connect_timeout, $banner_timeout, $bytes) = @_;
    my @results;
    for my $port (@$ports) {
        my $sock = IO::Socket::IP->new(
            PeerHost => $ip, PeerPort => $port, Proto => 'tcp', Timeout => $connect_timeout,
        );
        if (!$sock) {
            push @results, { port => $port, open => 0 };
            next;
        }
        my $banner = read_banner($sock, $banner_timeout, $bytes);
        close $sock;
        push @results, { port => $port, open => 1, (defined $banner ? (banner => $banner) : ()) };
    }
    return \@results;
}

1;
