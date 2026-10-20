package Profiler::Score;

use strict;
use warnings;

use List::Util qw(any max sum0);
use NetAddr::IP;

use Profiler::Host;
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

# A host match counts this much instead of its usual weight when the host is
# a custom name or IRCCloud account the nick has used before (see
# Profiler::Host), unless the ident disagrees: a shell box can give several
# people the same name, but not the same ident.
our $SOLID_HOST_WEIGHT = 2;

# A past sighting from a nearby address (same /24 or /64) counts as this much
# of a match, and so does one from the same client at another version.
our $SUBNET_CREDIT = 0.5;
our $CLIENT_CREDIT = 0.5;

# A past sighting from another address at the same ISP, like two Verizon
# addresses in different ranges, counts as this much of a match.
our $SAME_ISP_CREDIT = 0.5;

# Below this confidence there isn't enough history to call anyone an impostor.
# 0.5 is about three fresh sightings.
our $MIN_CONFIDENCE = 0.5;

# A match at or above this is "consistent". From 0 up to it is "mixed".
our $CONSISTENT_AT = 0.25;

# Defaults for promotable(): how many agreeing quarantined sightings, over how
# many days, before we decide someone moved rather than got impersonated.
our $PROMOTE_AFTER_SIGHTINGS = 5;
our $PROMOTE_AFTER_DAYS = 7;

# Someone "changes hosts often" when they have at least this many sightings
# with the same ident, and at least a quarter as many different hosts as
# sightings.
our $HOST_CHANGES_MIN_SIGHTINGS = 5;
our $HOST_CHANGES_OFTEN_AT = 0.25;

# The attributes that say who someone is, as opposed to where they connect
# from (host, server) or what they happen to be doing (channel).
my @IDENTITY_ATTRS = qw(ident realname version);

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

# The solid key (see Profiler::Host) of a sighting or observation, or undef.
sub solid_key_of {
    my ($s) = @_;
    return defined $s->{host} ? Profiler::Host::solid_key($s->{host}, $s->{ident}) : undef;
}

sub same_solid_host {
    my ($seen, $obs) = @_;
    my $key = solid_key_of($seen) // return 0;
    return $key eq (solid_key_of($obs) // '') ? 1 : 0;
}

sub age_weight {
    my ($sighting, $now) = @_;
    my $age = max(0, $now - $sighting->{time});
    return 0.5 ** ($age / $HALF_LIFE);
}

# Whether a join judged $verdict, with judge's $match and $parts when known,
# is quarantined. Suspects and new hosts are. So is an unknown join that
# disagrees with what's left of an old history on ident, realname or client,
# since otherwise whoever picks up a nick that's been idle for years looks
# like its owner from their second join. A new host alone isn't enough,
# because a newcomer on a dynamic IP would never get a history.
sub held {
    my ($verdict, $match, $parts) = @_;
    return 1 if $verdict eq 'suspect' || $verdict eq 'new host';
    return $verdict eq 'unknown' && ($match // 0) < 0 && identity_contradicted($parts);
}

# Does any of ident, realname or client disagree, in judge's parts? Those
# are what tell two people on the same host or ISP apart.
sub identity_contradicted {
    my ($parts) = @_;
    return any { ($parts->{$_} // 0) < 0 } @IDENTITY_ATTRS;
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
        # Everyone on an IRCCloud server shares its host name and addresses,
        # so only the account says who it is.
        return same_solid_host($seen, $obs)
            if Profiler::Host::kind($seen->{host}) eq 'irccloud' || Profiler::Host::kind($obs->{host}) eq 'irccloud';
        return 1 if $seen->{host} eq $obs->{host};
        return 1 if same_solid_host($seen, $obs);
        if (defined $seen->{ip} && defined $obs->{ip}) {
            return 1 if $seen->{ip} eq $obs->{ip};
            return $SUBNET_CREDIT if same_subnet($seen->{ip}, $obs->{ip});
        }
        return $SUBNET_CREDIT if same_pool($seen->{host}, $obs->{host});
        return same_isp($seen, $obs) ? $SAME_ISP_CREDIT : 0;
    }
    return 1 if $seen->{$attr} eq $obs->{$attr};
    # Channel names aren't case sensitive. The store keeps them lowercased,
    # but a join arrives as the channel was typed.
    return lc $seen->{channel} eq lc $obs->{channel} ? 1 : 0 if $attr eq 'channel';
    # The same IRCCloud account can turn up with a few idents.
    if ($attr eq 'ident') {
        my $seen_account = Profiler::Host::irccloud_account($seen->{ident}) // return 0;
        my $obs_account = Profiler::Host::irccloud_account($obs->{ident}) // return 0;
        return $seen_account eq $obs_account ? 1 : 0;
    }
    if ($attr eq 'version') {
        return Profiler::Version::client($seen->{version}) eq Profiler::Version::client($obs->{version})
            ? $CLIENT_CREDIT : 0;
    }
    return 0;
}

# One attribute's score from -1 to 1 and how much history it had, as
# familiarity, or an empty list when it can't be judged because one side has
# no value for it.
#
# The score leaves out how much history there is, since that's what
# confidence is for. A match is how familiar the value is next to how
# familiar the attribute is, so a value used every time scores 1 after three
# sightings or three hundred. A contradiction is scaled by how settled the
# habit was: breaking an ident used every single time costs a lot, while a new
# one from someone whose ident changes all the time costs next to nothing.
#
# Lots of people share a VPN or hosting exit, so the host isn't judged at all
# when the observation came from one. A custom name or IRCCloud account on
# that address is still somebody's own, so those are judged.
#
# $weighted is the history as [sighting, age weight] pairs.
# Whether a sighting has a value worth scoring for an attribute. A missed
# CTCP VERSION reply is absence of a client, not a client habit: it comes
# from a timeout or a bouncer eating the request, so it says nothing about
# who someone is and is left out on both sides.
sub has_value {
    my ($attr, $s) = @_;
    return 0 unless defined $s->{$attr};
    return 0 if $attr eq 'version' && $s->{$attr} eq $Profiler::Version::NO_REPLY;
    return 1;
}

sub attribute_score {
    my ($attr, $weighted, $obs) = @_;
    return unless has_value($attr, $obs);
    return if $attr eq 'host' && $obs->{proxy} && !defined solid_key_of($obs);

    my ($total, $support, %by_value) = (0, 0);
    for my $pair (@$weighted) {
        my ($seen, $w) = @$pair;
        next unless has_value($attr, $seen);
        $total += $w;
        $by_value{ $seen->{$attr} } += $w;
        $support += $w * similarity($attr, $seen, $obs);
    }
    return unless $total > 0;
    return (familiarity($support) / familiarity($total), familiarity($total)) if $support > 0;

    my $stability = max(values %by_value) / $total;
    return (-$stability, familiarity($total));
}

# The attribute scores averaged with their weights, using $host_weight for a
# host that matches. An attribute with little history counts for less, so
# realname from a couple of live sightings can't outweigh an ident seen
# hundreds of times.
sub weighted_match {
    my ($parts, $history, $host_weight) = @_;
    my ($sum, $weights) = (0, 0);
    for my $attr (keys %$parts) {
        my $s = $parts->{$attr};
        my $w = $history->{$attr} * ($s < 0           ? $CONTRADICT_WEIGHT{$attr}
                                   : $attr eq 'host' ? $host_weight
                                   :                   $MATCH_WEIGHT{$attr});
        $sum += $w * $s;
        $weights += $w;
    }
    return $weights ? $sum / $weights : 0;
}

# Judge an observation (one join plus its whois and VERSION reply) against the
# nick's history. Returns a hash of:
#
#   match       -1 to 1, a weighted average of the attribute scores
#   confidence  0 to 1, how much history there is to go on
#   trust       confidence * match
#   verdict     unknown, suspect, mixed or consistent
#   parts       each attribute's score, for explaining the verdict
#   host_seen   1 if the history has this exact host, even on a proxy
#   provider_seen  1 if the history has the address's provider (from whois)
#
# Call this before recording the observation, or it gets compared with itself.
sub judge {
    my ($profile, $obs, $now) = @_;
    my @weighted = map { [ $_, age_weight($_, $now) ] } $profile ? history($profile) : ();
    my $confidence = familiarity(sum0(map { $_->[1] } @weighted));

    my (%parts, %history);
    for my $attr (keys %MATCH_WEIGHT) {
        my ($s, $familiarity) = attribute_score($attr, \@weighted, $obs) or next;
        $parts{$attr} = $s;
        $history{$attr} = $familiarity;
    }
    my $solid = defined solid_key_of($obs) && ($parts{host} // 0) > 0 && ($parts{ident} // 0) >= 0
        && any { same_solid_host($_->[0], $obs) } @weighted;

    # The match is a weighted average, so a heavy weight pulls it towards the
    # host's score. A solid host they've used only once, long ago, scores low,
    # and we don't want that to drag down an otherwise good match.
    my $match = weighted_match(\%parts, \%history, $MATCH_WEIGHT{host});
    $match = max($match, weighted_match(\%parts, \%history, $SOLID_HOST_WEIGHT)) if $solid;

    my $verdict = $confidence < $MIN_CONFIDENCE ? 'unknown'
                : $match < 0                    ? 'suspect'
                : $match < $CONSISTENT_AT       ? 'mixed'
                :                                 'consistent';

    # Most suspects on EFnet turned out to be the usual person on a host we
    # hadn't seen, with everything else the same. That's worth telling apart
    # from a stranger, so it gets its own verdict. It's still quarantined.
    my %r = (
        match      => $match,
        confidence => $confidence,
        trust      => $confidence * $match,
        verdict    => $verdict,
        parts      => \%parts,
        host_seen  => (any { $_->[0]{host} eq $obs->{host} } @weighted) ? 1 : 0,
        provider_seen => defined $obs->{provider}
            && (any { ($_->[0]{provider} // '') eq $obs->{provider} } @weighted) ? 1 : 0,
    );
    my $identity_contradicted = identity_contradicted(\%parts);
    # A different ident, realname or client means it may well be someone
    # else, like a second person on the same shell box, however much else
    # matches.
    $r{verdict} = 'mixed' if $verdict eq 'consistent' && $identity_contradicted;
    # Channel and server are weak evidence, so on their own they can't make a
    # suspect. A known nick in a new channel is just mixed.
    if ($verdict eq 'suspect' && !$identity_contradicted) {
        if (($parts{host} // 0) < 0) {
            $r{verdict} = 'new host';
            $r{host_changes_often} = host_changes_often($profile, $obs);
        }
        else {
            $r{verdict} = 'mixed';
        }
    }
    # People stay with their home or mobile ISP. Turning up from one they've
    # never used is what a residential proxy network looks like, however
    # well everything else was copied.
    $r{new_isp} = new_isp(\@weighted, $obs);
    $r{verdict} = 'suspect' if $r{new_isp} && $verdict ne 'unknown';
    return \%r;
}

# Which ISP a sighting came through, two ways: the domain of an ISP-generated
# name, and the provider whois gave for the address (live sightings only).
# Only ISP names and bare addresses have them. A custom name is somebody's
# own server, and its hosting company says nothing about their home ISP.
sub isp_keys {
    my ($s) = @_;
    my $kind = defined $s->{host} ? Profiler::Host::kind($s->{host}) : '';
    return () unless $kind eq 'isp' || $kind eq 'ip';
    my %keys;
    $keys{domain} = Profiler::Host::isp_domain($s->{host}) if $kind eq 'isp';
    $keys{provider} = $s->{provider} if defined $s->{provider};
    return %keys;
}

# Do two sightings share an ISP, by domain or by provider? A domain is only
# compared with a domain and a provider with a provider, since myvzw.com and
# "cellco partnership" are the same ISP under different names.
sub same_isp {
    my ($a, $b) = @_;
    my %a = isp_keys($a) or return 0;
    my %b = isp_keys($b) or return 0;
    return any { defined $a{$_} && defined $b{$_} && $a{$_} eq $b{$_} } keys %b;
}

# { isp, usual } when the observation comes through an ISP that a history
# with ISPs of the same kind (domain or provider) has never used, usual being
# the one they've used most. undef otherwise, including for someone who has
# only used their own server, history without providers for a bare address,
# and a join from a likely proxy, which is nobody's home ISP.
sub new_isp {
    my ($weighted, $obs) = @_;
    return undef if $obs->{proxy};
    my %isp = isp_keys($obs) or return undef;
    my %used;
    for my $pair (@$weighted) {
        my %seen = isp_keys($pair->[0]);
        $used{$_}{ $seen{$_} } += $pair->[1] for keys %seen;
    }
    # Domains first, since every ISP name has one.
    my @compared = grep { $used{$_} } sort keys %isp;
    return undef if !@compared || any { $used{$_}{ $isp{$_} } } @compared;
    my $kind = $compared[0];
    my ($usual) = sort { $used{$kind}{$b} <=> $used{$kind}{$a} || $a cmp $b } keys %{ $used{$kind} };
    return { isp => $isp{$kind}, usual => $usual };
}

# Does this person turn up from new hosts a lot? We look at every sighting
# of the nick with the same ident, quarantined or not, and count how many
# different hosts they came from. VPNs and proxies that whois doesn't give
# away look like this, as do people who hop between machines.
sub host_changes_often {
    my ($profile, $obs) = @_;
    my @same_ident = grep { defined $_->{ident} && $_->{ident} eq $obs->{ident} } @{ $profile->{sightings} };
    return 0 if @same_ident < $HOST_CHANGES_MIN_SIGHTINGS;
    my %hosts = map { $_->{host} => 1 } @same_ident;
    return keys(%hosts) / @same_ident >= $HOST_CHANGES_OFTEN_AT ? 1 : 0;
}

# Does a sighting agree with the accepted history on everything we compare
# except the host? Attributes that either side never recorded are skipped,
# so imported sightings are compared on the ident alone.
sub matches_apart_from_host {
    my ($s, $accepted) = @_;
    for my $attr (@IDENTITY_ATTRS) {
        next unless defined $s->{$attr};
        my @known = grep { defined $_->{$attr} } @$accepted;
        next unless @known;
        return 0 unless grep { similarity($attr, $_, $s) > 0 } @known;
    }
    return 1;
}

# When someone really moves (new ISP, new bouncer), every join from the new
# host contradicts the old history and gets quarantined, and since quarantined
# sightings never join the history, they'd stay suspect for months. So we
# look for the shape of a move: the newest unreviewed quarantined sightings
# agree with each other on the host, or on an ident the nick never had before,
# and there are at least $min_count of them
# spread over at least $min_days.
#
# If the old habit has stopped since the first of them, that's a move and
# anything may have changed. If it's still turning up, this could be a second
# home (work, phone, bouncer) or a troll sitting on the nick, so we only
# promote when everything other than the host matches the accepted history.
#
# Returns the sightings to promote, or an empty list.
sub promotable {
    my ($profile, $min_count, $min_days) = @_;
    # Checked before sorting because this runs on every join and almost
    # nobody has anything waiting in quarantine.
    return () unless grep { $_->{quarantined} && !$_->{reviewed} } @{ $profile->{sightings} // [] };

    my @sightings = sort { $a->{time} <=> $b->{time} } @{ $profile->{sightings} };
    my @held = grep { $_->{quarantined} && !$_->{reviewed} } @sightings;

    my $latest = $held[-1];
    my @accepted = grep { !$_->{quarantined} } @sightings;
    # Someone on a new dynamic address every join never agrees on the host,
    # so an ident the nick never had counts too. One it already had doesn't,
    # since that's just as easy for a troll to copy.
    my $new_ident = defined $latest->{ident}
        && !grep { defined $_->{ident} && similarity('ident', $_, $latest) > 0 } @accepted;
    my @agreeing = grep {
        similarity('host', $_, $latest) > 0 || $new_ident && defined $_->{ident} && similarity('ident', $_, $latest) > 0
    } @held;
    return () if @agreeing < $min_count;
    return () if $latest->{time} - $agreeing[0]{time} < $min_days * 86400;
    if (grep { $_->{time} > $agreeing[0]{time} } @accepted) {
        return () if grep { !matches_apart_from_host($_, \@accepted) } @agreeing;
    }
    return @agreeing;
}

1;
