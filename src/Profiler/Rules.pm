package Profiler::Rules;

use strict;
use warnings;

# Rules file lines:
#
#     <network> <channel[,channel...]> <min_trust>
#     proxy <keyword or phrase>
#
# A watch line asks for a warning when someone joins one of those channels with
# trust under min_trust (0 to 1). "*" in the network or channel field means
# "any". A proxy line adds a word to look for in whois records on top of the
# built-in list in Profiler::Whois. Lines starting with "#" are comments.

# Returns (\%rules, \@errors). Bad lines are skipped and described in @errors so
# one typo does not throw away the rest of the file.
sub parse {
    my (@lines) = @_;
    my %rules = (watches => [], proxy_keywords => []);
    my @errors;

    my $n = 0;
    for my $line (@lines) {
        $n++;
        next if $line =~ /^\s*(#|$)/;

        if ($line =~ /^\s*proxy\b\s*(.*?)\s*$/i) {
            if (length $1) {
                push @{ $rules{proxy_keywords} }, lc $1;
            }
            else {
                push @errors, "line $n: proxy needs a keyword";
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

1;
