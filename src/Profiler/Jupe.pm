package Profiler::Jupe;

use strict;
use warnings;

use Profiler::Score;
use Profiler::Variants;

# Juping is sitting on someone's nick so they can't have it. Bob then turns
# up as bob_ and waits for it. When a join on a variant nick fits that
# nick's history (waiting_for), the script WHOISes and VERSIONs whoever has
# the nick now, and juper says whether that's somebody else.
#
# Plenty of people run two clients, so bob holding bob while also on bob_ is
# normal. That's why it takes ident, realname or client disagreeing with the
# nick's history to call the holder a juper. Another host alone could be bob
# on his phone.

# The nick a join on a variant may be waiting for, as Profiler::Variants
# gives it ({ nick, linked, result }), when the join is consistent with that
# nick's history. undef otherwise.
sub waiting_for {
    my ($store, $network, $nick, $obs, $now) = @_;
    my $variant = Profiler::Variants::best_match($store, $network, $nick, $obs, $now) or return undef;
    return $variant->{result}{verdict} eq 'consistent' ? $variant : undef;
}

# What Profiler::Score::judge says about whoever holds $holder->{nick}
# (their WHOIS and VERSION) against the nick's history, when they disagree
# with it on who they are. undef when they don't, or the nick has no
# history. Channel and server say nothing about who someone is, so they're
# left out.
sub juper {
    my ($store, $network, $holder, $now) = @_;
    my $profile = $store->profile($network, $holder->{nick}) or return undef;
    my $r = Profiler::Score::judge($profile, { %$holder, channel => undef, server => undef }, $now);
    return $r->{match} < 0 && Profiler::Score::identity_contradicted($r->{parts}) ? $r : undef;
}

1;
