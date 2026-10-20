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
# A nick's own label counts when the join comes from where the nick usually
# connects, by its accepted history (see from_their_host). Otherwise it
# could be anyone on the nick.
#
# BAD also follows the person onto other nicks, found the way
# Profiler::Evasion finds someone kicked or banned. When a join gets a label
# from its own nick and also looks like someone else who's BAD, that's
# { label => 'conflicting', nick, own, bad }, with the nick's own label and
# the BAD nick. It's for you to sort out from the logs: maybe someone clever
# sat on a regular's nick from the regular's ISP, maybe a BAD label is out of
# date.
sub for_join {
    my ($store, $network, $nick, $obs, $now) = @_;
    my $own;
    if (defined(my $label = $store->label($network, $nick))) {
        my $profile = $store->profile($network, $nick);
        $own = { label => $label, nick => $profile->{nick} } if $profile && from_their_host($profile, $obs);
    }
    my $bad = bad_person($store, $network, $nick, $obs, $now);
    return { label => 'conflicting', nick => $own->{nick}, own => $own->{label}, bad => $bad->{nick} }
        if $own && $bad && $own->{label} ne 'bad';
    return $own // $bad;
}

# The best match among nicks labelled BAD, other than $nick, as { label, nick }.
sub bad_person {
    my ($store, $network, $nick, $obs, $now) = @_;
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

# Did the join come from where this nick connects? Their very own host,
# address or IRCCloud account is enough. A nearby address or the same ISP,
# like the next dynamic address from their provider, needs the ident they had
# there too, since the ISP has plenty of other customers.
sub from_their_host {
    my ($profile, $obs) = @_;
    return any {
        my $host = Profiler::Score::similarity('host', $_, $obs);
        $host == 1 || $host > 0 && defined $_->{ident} && defined $obs->{ident}
            && Profiler::Score::similarity('ident', $_, $obs) > 0
    } Profiler::Score::history($profile);
}

1;
