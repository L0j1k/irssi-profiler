package Profiler::Whois;

use strict;
use warnings;

use Socket qw(getaddrinfo getnameinfo NI_NUMERICHOST NIx_NOSERV SOCK_STREAM);

# Words that show up in the registry records of VPN providers, proxy and Tor
# operators, and hosting companies. A match is a guess, and the rules file can
# add more with "proxy <keyword>" lines.
our @DEFAULT_PROXY_KEYWORDS = (
    'vpn', 'proxy', 'tor', 'exit', 'anonymous', 'privacy',
    'hosting', 'hoster', 'datacenter', 'data center', 'colocation', 'vps', 'dedicated',
    'digitalocean', 'linode', 'akamai', 'vultr', 'choopa', 'ovh', 'hetzner',
    'leaseweb', 'contabo', 'm247', 'datacamp', 'cdn77', 'frantech', 'buyvm',
    'amazon', 'aws', 'google cloud', 'microsoft azure', 'oracle cloud', 'alibaba',
    'mullvad', 'nordvpn', 'expressvpn', 'surfshark', 'protonvpn', 'private internet access',
);

# The whois fields we keep. RIPE-style records use lowercase keys and ARIN uses
# CamelCase, so keys are compared lowercased.
my %ORG_KEYS = map { $_ => 1 } qw(org-name orgname organization owner);
my %TEXT_KEYS = map { $_ => 1 } qw(netname descr org-name orgname organization owner remarks comment);

# ARIN answers with the parent network first and the most specific one last,
# so a later value replaces an earlier one. RIPE gives one record, so it makes
# no difference there.
sub parse {
    my ($output) = @_;
    my %rec;
    my @text;

    for my $line (split /\n/, $output) {
        next if $line =~ /^\s*[#%]/;
        my ($key, $value) = $line =~ /^\s*([A-Za-z-]+):\s*(.*?)\s*$/ or next;
        $key = lc $key;
        next unless length $value;

        $rec{netname} = $value if $key eq 'netname';
        $rec{org} = $value if $ORG_KEYS{$key};
        $rec{origin} = $value if $key eq 'origin' || $key eq 'originas';
        push @text, $value if $TEXT_KEYS{$key};
    }
    $rec{text} = join "\n", @text;
    return \%rec;
}

# Who an address belongs to, for telling a provider's other addresses from a
# change of provider: the registry's organisation, or its AS when there's
# none, lowercased with spacing evened out. undef when the record has
# neither. The netname isn't used, since one provider has many.
sub provider {
    my ($rec) = @_;
    my $name = $rec->{org} // $rec->{origin};
    return undef unless defined $name && $name =~ /\S/;
    $name = lc $name;
    $name =~ s/\s+/ /g;
    $name =~ s/^ | $//g;
    return $name;
}

# The first keyword found as a whole word or phrase in the record, or undef.
# Also undef when the record has any of the @$not_proxy phrases.
sub proxy_reason {
    my ($rec, $keywords, $not_proxy) = @_;
    my $text = lc($rec->{text} // '');
    for my $phrase (@{ $not_proxy // [] }) {
        return undef if $text =~ /\b\Q$phrase\E\b/;
    }
    for my $kw (@$keywords) {
        return $kw if $text =~ /\b\Q$kw\E\b/;
    }
    return undef;
}

sub resolve {
    my ($host) = @_;
    my ($err, @res) = getaddrinfo($host, '', { socktype => SOCK_STREAM });
    return undef if $err || !@res;
    my ($nerr, $ip) = getnameinfo($res[0]{addr}, NI_NUMERICHOST, NIx_NOSERV);
    return $nerr ? undef : $ip;
}

# Resolve a host and run the system whois on its address. This blocks for as
# long as DNS and the registry take, so the irssi side runs it in a child
# process. Returns a hash with ip, netname, org, origin and proxy (the matched
# keyword, see proxy_reason), or with error set when something went wrong.
sub lookup {
    my ($host, $keywords, $timeout, $not_proxy) = @_;

    my $ip = resolve($host);
    return { ip => undef, error => "cannot resolve $host" } unless defined $ip;

    # The list form of open runs whois without a shell. That matters because
    # the address came from an IRC server, though resolve() only ever hands
    # back a numeric address anyway.
    my $output = eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm $timeout;
        open my $fh, '-|', 'whois', $ip or die "cannot run whois: $!\n";
        local $/;
        my $out = <$fh>;
        close $fh;
        alarm 0;
        $out;
    };
    alarm 0;
    return { ip => $ip, error => "whois $ip: " . ($@ =~ s/\n$//r) } if $@;

    my $rec = parse($output // '');
    return {
        ip      => $ip,
        netname => $rec->{netname},
        org     => $rec->{org},
        origin  => $rec->{origin},
        proxy   => proxy_reason($rec, $keywords, $not_proxy),
    };
}

1;
