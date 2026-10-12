package Profiler::Score;

use strict;
use warnings;

use List::Util qw(max sum0);
use NetAddr::IP;

use Profiler::Version;

# The question we answer is "is this really the person who has been using this
# nick?" Each attribute of a join is compared with that nick's history and
# scores from -1 (contradicts a settled habit) to +1 (matches a long habit).
#
# Weights are lopsided on purpose. Ident, realname and client version show up
# in a plain /whois or CTCP, so an impostor can copy them: a match proves
# little, but a mismatch means they didn't even try. The host is hard to fake,
# so a match is strong evidence, while a mismatch is only moderate because
# people change ISPs and travel.
our %MATCH_WEIGHT = (
    host     => 0.40,
    ident    => 0.10,
    realname => 0.10,
    version  => 0.05,
    server   => 0.05,
    channel  => 0.10,
);
our %CONTRADICT_WEIGHT = (
    host     => 0.35,
    ident    => 0.25,
    realname => 0.25,
    version  => 0.15,
    server   => 0.05,
    channel  => 0.05,
);

# Familiarity is weight / (weight + K): K fresh sightings is halfway to 1.
our $K = 3;

# A sighting this old counts half as much as one from today.
our $HALF_LIFE = 90 * 86400;

# A past sighting from a nearby address (same /24 or /64) counts as this much
# of a match, and so does one from the same client at another version.
our $SUBNET_CREDIT = 0.5;
our $CLIENT_CREDIT = 0.5;

# Below this confidence there isn't enough history to call anyone an impostor.
# 0.5 is about three fresh sightings.
our $MIN_CONFIDENCE = 0.5;

# A match at or above this is "consistent". From 0 up to it is "mixed".
our $CONSISTENT_AT = 0.25;

my %PREFIX = (4 => 24, 6 => 64);

sub familiarity {
    my ($weight) = @_;
    return $weight / ($weight + $K);
}

sub same_subnet {
    my ($a, $b) = @_;
    my $ipa = NetAddr::IP->new($a) or return 0;
    my $ipb = NetAddr::IP->new($b) or return 0;
    return 0 unless $ipa->version == $ipb->version;
    my $net = NetAddr::IP->new($ipa->addr, $PREFIX{ $ipa->version }) or return 0;
    return $net->contains($ipb) ? 1 : 0;
}

sub age_weight {
    my ($sighting, $now) = @_;
    my $age = max(0, $now - $sighting->{time});
    return 0.5 ** ($age / $HALF_LIFE);
}

# Sightings that count: everything except what was quarantined as suspect.
sub history {
    my ($profile) = @_;
    return grep { !$_->{quarantined} } @{ $profile->{sightings} // [] };
}

# How much a past sighting agrees with the observation on one attribute: 1 for
# the same value, a partial credit for a near miss, 0 otherwise.
sub similarity {
    my ($attr, $seen, $obs) = @_;
    if ($attr eq 'host') {
        return 1 if $seen->{host} eq $obs->{host};
        return 0 unless defined $seen->{ip} && defined $obs->{ip};
        return 1 if $seen->{ip} eq $obs->{ip};
        return same_subnet($seen->{ip}, $obs->{ip}) ? $SUBNET_CREDIT : 0;
    }
    return 1 if $seen->{$attr} eq $obs->{$attr};
    if ($attr eq 'version') {
        return Profiler::Version::client($seen->{version}) eq Profiler::Version::client($obs->{version})
            ? $CLIENT_CREDIT : 0;
    }
    return 0;
}

# One attribute's score from -1 to 1, or undef when it can't be judged because
# one side has no value for it. A contradiction is scaled by how settled the
# habit was: breaking an ident used every single time costs a lot, while a new
# one from someone whose ident changes all the time costs next to nothing.
#
# Lots of people share a VPN or hosting exit, so the host isn't judged at all
# when the observation came from one.
sub attribute_score {
    my ($attr, $history, $obs, $now) = @_;
    return undef unless defined $obs->{$attr};
    return undef if $attr eq 'host' && $obs->{proxy};

    my ($total, $support, %by_value) = (0, 0);
    for my $seen (@$history) {
        next unless defined $seen->{$attr};
        my $w = age_weight($seen, $now);
        $total += $w;
        $by_value{ $seen->{$attr} } += $w;
        $support += $w * similarity($attr, $seen, $obs);
    }
    return undef unless $total > 0;
    return familiarity($support) if $support > 0;

    my $stability = max(values %by_value) / $total;
    return -$stability * familiarity($total);
}

# Judge an observation (one join plus its whois and VERSION reply) against the
# nick's history. Returns a hash of:
#
#   match       -1 to 1, a weighted average of the attribute scores
#   confidence  0 to 1, how much history there is to go on
#   trust       confidence * match
#   verdict     unknown, suspect, mixed or consistent
#   parts       each attribute's score, for explaining the verdict
#
# Call this before recording the observation, or it gets compared with itself.
sub judge {
    my ($profile, $obs, $now) = @_;
    my @history = $profile ? history($profile) : ();
    my $confidence = familiarity(sum0(map { age_weight($_, $now) } @history));

    my (%parts, $weighted, $weights);
    for my $attr (keys %MATCH_WEIGHT) {
        my $s = attribute_score($attr, \@history, $obs, $now);
        next unless defined $s;
        my $w = $s >= 0 ? $MATCH_WEIGHT{$attr} : $CONTRADICT_WEIGHT{$attr};
        $parts{$attr} = $s;
        $weighted += $w * $s;
        $weights += $w;
    }
    my $match = $weights ? $weighted / $weights : 0;

    my $verdict = $confidence < $MIN_CONFIDENCE ? 'unknown'
                : $match < 0                    ? 'suspect'
                : $match < $CONSISTENT_AT       ? 'mixed'
                :                                 'consistent';

    return {
        match      => $match,
        confidence => $confidence,
        trust      => $confidence * $match,
        verdict    => $verdict,
        parts      => \%parts,
    };
}

1;
