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

# Defaults for promotable(): how many agreeing quarantined sightings, over how
# many days, before we decide someone moved rather than got impersonated.
our $PROMOTE_AFTER_SIGHTINGS = 5;
our $PROMOTE_AFTER_DAYS = 7;

my %PREFIX = (4 => 24, 6 => 64);

sub familiarity {
    my ($weight) = @_;
    return $weight / ($weight + $K);
}

sub same_subnet {
    my ($a, $b) = @_;
    # IPv4 is the common case and comparing the first three octets as text is
    # much faster than building NetAddr::IP objects, which matters when
    # replaying years of logs.
    my ($neta) = $a =~ /^(\d+\.\d+\.\d+)\.\d+$/;
    my ($netb) = $b =~ /^(\d+\.\d+\.\d+)\.\d+$/;
    return $neta eq $netb ? 1 : 0 if defined $neta && defined $netb;

    my $ipa = NetAddr::IP->new($a) or return 0;
    my $ipb = NetAddr::IP->new($b) or return 0;
    return 0 unless $ipa->version == $ipb->version;
    my $net = NetAddr::IP->new($ipa->addr, $PREFIX{ $ipa->version }) or return 0;
    return $net->contains($ipb) ? 1 : 0;
}

# Two host names from the same dynamic ISP pool, like
# cpe-198-51-100-202.san.res.rr.com and cpe-203-0-113-17.san.res.rr.com: they
# differ only in the first label, and both first labels have digits in them.
# Requiring digits keeps named hosts out, so bob.users.example.net and
# troll.users.example.net are not treated as neighbors.
sub same_pool {
    my ($a, $b) = @_;
    my ($first_a, $rest_a) = $a =~ /^([^.]+)\.(.+\..+)$/ or return 0;
    my ($first_b, $rest_b) = $b =~ /^([^.]+)\.(.+\..+)$/ or return 0;
    return $rest_a eq $rest_b && $first_a =~ /\d/ && $first_b =~ /\d/ ? 1 : 0;
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
        if (defined $seen->{ip} && defined $obs->{ip}) {
            return 1 if $seen->{ip} eq $obs->{ip};
            return $SUBNET_CREDIT if same_subnet($seen->{ip}, $obs->{ip});
        }
        return same_pool($seen->{host}, $obs->{host}) ? $SUBNET_CREDIT : 0;
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
#
# $weighted is the history as [sighting, age weight] pairs.
sub attribute_score {
    my ($attr, $weighted, $obs) = @_;
    return undef unless defined $obs->{$attr};
    return undef if $attr eq 'host' && $obs->{proxy};

    my ($total, $support, %by_value) = (0, 0);
    for my $pair (@$weighted) {
        my ($seen, $w) = @$pair;
        next unless defined $seen->{$attr};
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
    my @weighted = map { [ $_, age_weight($_, $now) ] } $profile ? history($profile) : ();
    my $confidence = familiarity(sum0(map { $_->[1] } @weighted));

    my (%parts, $sum, $weights);
    for my $attr (keys %MATCH_WEIGHT) {
        my $s = attribute_score($attr, \@weighted, $obs);
        next unless defined $s;
        my $w = $s >= 0 ? $MATCH_WEIGHT{$attr} : $CONTRADICT_WEIGHT{$attr};
        $parts{$attr} = $s;
        $sum += $w * $s;
        $weights += $w;
    }
    my $match = $weights ? $sum / $weights : 0;

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

# When someone really moves (new ISP, new bouncer), every join from the new
# host contradicts the old history and gets quarantined, and since quarantined
# sightings never join the history, they'd stay suspect for months. So we
# look for the shape of a move: the newest unreviewed quarantined sightings
# agree with each other on the host, there are at least $min_count of them
# spread over at least $min_days, and nothing from the old habit has shown up
# since the first of them. A troll wearing the nick while its owner keeps
# turning up as usual never fits that shape.
#
# Returns the sightings to promote, or an empty list.
sub promotable {
    my ($profile, $min_count, $min_days) = @_;
    my @sightings = sort { $a->{time} <=> $b->{time} } @{ $profile->{sightings} // [] };
    my @held = grep { $_->{quarantined} && !$_->{reviewed} } @sightings;
    return () unless @held;

    my $latest = $held[-1];
    my @agreeing = grep { similarity('host', $_, $latest) > 0 } @held;
    return () if @agreeing < $min_count;
    return () if $latest->{time} - $agreeing[0]{time} < $min_days * 86400;
    return () if grep { !$_->{quarantined} && $_->{time} > $agreeing[0]{time} } @sightings;
    return @agreeing;
}

1;
