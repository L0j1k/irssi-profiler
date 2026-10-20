package Profiler::Rules;

use strict;
use warnings;

use Profiler::Probe;

# Rules file lines:
#
#     <network> <channel[,channel...]> <min_trust>
#     proxy <keyword or phrase>
#     notproxy <phrase>
#     port <n[,n...]>
#     proxyport <n[,n...]>
#
# A watch line asks for a warning when someone joins one of those channels with
# trust under min_trust (0 to 1). "*" in the network or channel field means
# "any". A proxy line adds a word to look for in whois records on top of the
# built-in list in Profiler::Whois. A notproxy line clears any record that has
# the phrase, like a mobile carrier that runs on a cloud provider's addresses.
# A port line replaces the default set of ports we knock on (Profiler::Probe);
# a proxyport line adds to the ports that count as an open proxy. Lines starting
# with "#" are comments.

# Returns (\%rules, \@errors). Bad lines are skipped and described in @errors so
# one typo does not throw away the rest of the file.
sub parse {
    my (@lines) = @_;
    my %rules = (watches => [], proxy_keywords => [], not_proxy => [], probe_ports => [], proxy_ports => []);
    my @errors;

    my $n = 0;
    for my $line (@lines) {
        $n++;
        next if $line =~ /^\s*(#|$)/;

        if ($line =~ /^\s*(proxy|notproxy)\b\s*(.*?)\s*$/i) {
            my ($kind, $phrase) = (lc $1, $2);
            if (length $phrase) {
                push @{ $rules{ $kind eq 'proxy' ? 'proxy_keywords' : 'not_proxy' } }, lc $phrase;
            }
            else {
                push @errors, "line $n: $kind needs a " . ($kind eq 'proxy' ? 'keyword' : 'phrase');
            }
            next;
        }

        if ($line =~ /^\s*(proxyport|port)\b\s*(.*?)\s*$/i) {
            my ($kind, $value) = (lc $1, $2);
            my @ports = Profiler::Probe::parse_ports($value);
            if (@ports) {
                push @{ $rules{ $kind eq 'port' ? 'probe_ports' : 'proxy_ports' } }, @ports;
            }
            else {
                push @errors, "line $n: $kind needs one or more port numbers from 1 to 65535";
            }
            next;
        }

        my ($network, $channels, $min) = $line =~ /^\s*(\S+)\s+(\S+)\s+(\S+)\s*$/;
        if (!defined $min) {
            push @errors, "line $n: expected <network> <channels> <min_trust>";
            next;
        }
        if ($min !~ /^(\d+(\.\d*)?|\.\d+)$/ || $min > 1) {
            push @errors, "line $n: min_trust must be a number from 0 to 1, got '$min'";
            next;
        }
        push @{ $rules{watches} }, {
            network   => lc $network,
            channels  => [ grep { length } map { lc } split /,/, $channels ],
            min_trust => $min + 0,
            text      => "$network $channels $min",
        };
    }

    return (\%rules, \@errors);
}

# The highest min_trust among the watches covering this channel, or undef when
# nobody asked to watch it.
sub min_trust_for {
    my ($rules, $network, $channel) = @_;
    $network = lc $network;
    $channel = lc $channel;

    my $min;
    for my $w (@{ $rules->{watches} }) {
        next unless $w->{network} eq '*' || $w->{network} eq $network;
        next unless grep { $_ eq '*' || $_ eq $channel } @{ $w->{channels} };
        $min = $w->{min_trust} if !defined $min || $w->{min_trust} > $min;
    }
    return $min;
}

# Should a judged join be warned about for falling short of a watch's
# min_trust? Trust is confidence times match, and a nick we barely know has
# confidence under 0.5, so it would fall short of any sensible minimum every
# time. Those stay quiet.
sub below_minimum {
    my ($result, $min) = @_;
    return $result->{verdict} ne 'unknown' && $result->{trust} < $min;
}

1;
