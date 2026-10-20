package Profiler::Label;

use strict;
use warnings;

use List::Util qw(any);

use Profiler::Evasion;
use Profiler::Score;

# Labels are what you've decided about someone with /profiler good, neutral
# or bad. They lead every line about that person's joins, ahead of whatever
# the scoring says, and change nothing else.

our @LABELS = qw(good neutral bad);

# The label for a join, as { label, nick } with the nick it was given to, or
# undef.
#
# A nick's own label counts when the join comes from a host the nick has used
# before, by its accepted history: the very same host, address or IRCCloud
# account. A nearby address or the same ISP isn't enough, since that's
# anybody's for the asking. Without that it could be anyone on the nick.
#
# BAD also follows the person onto other nicks, found the way
# Profiler::Evasion finds someone kicked or banned. A nick's own label comes
# first, so you can say someone is fine now on the nick they use these days.
sub for_join {
    my ($store, $network, $nick, $obs, $now) = @_;
    if (defined(my $label = $store->label($network, $nick))) {
        my $profile = $store->profile($network, $nick);
        return { label => $label, nick => $profile->{nick} } if $profile && from_their_host($profile, $obs);
    }
    my ($best, $best_match);
    for my $key ($store->labelled($network, 'bad')) {
        next if $key eq lc $nick;
        my $profile = $store->profile($network, $key) or next;
        # Channel and server are shared by everybody here, so they're left
        # out rather than let them pad the match.
        my $r = Profiler::Score::judge($profile, { %$obs, channel => undef, server => undef }, $now);
        next unless $r->{match} >= $Profiler::Score::CONSISTENT_AT && Profiler::Evasion::enough_evidence($r, $profile, $obs);
        next if defined $best_match && $best_match >= $r->{match};
        ($best, $best_match) = ({ label => 'bad', nick => $profile->{nick} }, $r->{match});
    }
    return $best;
}

sub from_their_host {
    my ($profile, $obs) = @_;
    return any { Profiler::Score::similarity('host', $_, $obs) == 1 } Profiler::Score::history($profile);
}

1;
