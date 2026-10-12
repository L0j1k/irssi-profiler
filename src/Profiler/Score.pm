package Profiler::Score;

use strict;
use warnings;

use NetAddr::IP;

# How much each attribute contributes to the final trust. They add up to 1, so
# trust is a weighted average of the per-attribute familiarity.
our %WEIGHTS = (
    host     => 0.35,
    ident    => 0.20,
    realname => 0.20,
    server   => 0.10,
    channel  => 0.15,
);

# Familiarity is count / (count + K): seen K times means halfway to 1.
our $K = 3;

# A past sighting from a nearby address (same /24 or /64) counts as this much
# of a sighting from the exact address.
our $SUBNET_CREDIT = 0.5;

my %PREFIX = (4 => 24, 6 => 64);

sub familiarity {
    my ($count) = @_;
    return $count / ($count + $K);
}

sub same_subnet {
    my ($a, $b) = @_;
    my $ipa = NetAddr::IP->new($a) or return 0;
    my $ipb = NetAddr::IP->new($b) or return 0;
    return 0 unless $ipa->version == $ipb->version;
    my $net = NetAddr::IP->new($ipa->addr, $PREFIX{ $ipa->version }) or return 0;
    return $net->contains($ipb) ? 1 : 0;
}

# Score an observation (one join plus its whois) against the profile built
# from earlier sightings of that nick. Returns ($trust, \%parts) where parts
# holds each attribute's weighted contribution, handy for explaining a score.
#
# Call this before recording the observation, or a first-time joiner would get
# credit for matching themselves.
sub trust {
    my ($profile, $obs) = @_;
    return (0, {}) unless $profile;

    my %parts;
    $parts{host} = $WEIGHTS{host} * familiarity(host_count($profile, $obs));
    for my $attr (qw(ident realname server channel)) {
        my $value = $obs->{$attr};
        my $count = defined $value ? ($profile->{"${attr}s"}{$value} // 0) : 0;
        $parts{$attr} = $WEIGHTS{$attr} * familiarity($count);
    }

    my $trust = 0;
    $trust += $_ for values %parts;
    return ($trust, \%parts);
}

# Lots of people share a VPN or hosting exit, so coming from one says nothing
# about who you are, and neither does coming from next door to one.
sub host_count {
    my ($profile, $obs) = @_;
    return 0 if $obs->{proxy};

    my $host = $obs->{host};
    my $ip = $obs->{ip};
    my $exact = defined $host ? ($profile->{hosts}{$host} // 0) : 0;
    return $exact unless defined $ip;

    my $ip_exact = $profile->{ips}{$ip} // 0;
    $exact = $ip_exact if $ip_exact > $exact;

    my $nearby = 0;
    for my $seen (keys %{ $profile->{ips} }) {
        next if $seen eq $ip;
        $nearby += $profile->{ips}{$seen} if same_subnet($seen, $ip);
    }
    return $exact + $SUBNET_CREDIT * $nearby;
}

1;
