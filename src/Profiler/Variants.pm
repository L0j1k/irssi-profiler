package Profiler::Variants;

use strict;
use warnings;

use Profiler::Score;

# "Is this new client actually bob?" On EFnet people end up as bob_, B0B` or
# bobbb when their nick is juped, so a joiner on an odd nick is compared with
# the profiles of nicks it's tied to: ones it has switched to or from with
# /nick (proof they're the same person) and ones with the same skeleton (see
# Profiler::Nick). The nick only picks who to compare with. Host and ident
# decide, through the same judging as everything else.

# Skeletons like "a" could match a lot of nicks, and each comparison loads a
# profile, so we stop after this many. Linked nicks go first.
our $MAX_CANDIDATES = 20;

# Returns the best match as { nick, linked, result } where result is what
# Profiler::Score::judge said about the observation against that nick's
# history, or undef when no candidate comes out consistent or mixed.
sub best_match {
    my ($store, $network, $nick, $obs, $now) = @_;
    my %linked = map { $_ => 1 } $store->linked($network, $nick);
    my %seen;
    my @candidates = grep { !$seen{$_}++ && $_ ne lc $nick } (sort keys %linked), $store->similar($network, $nick);
    splice @candidates, $MAX_CANDIDATES if @candidates > $MAX_CANDIDATES;

    my $best;
    for my $candidate (@candidates) {
        my $profile = $store->profile($network, $candidate) or next;
        my $r = Profiler::Score::judge($profile, $obs, $now);
        next unless $r->{verdict} eq 'consistent' || $r->{verdict} eq 'mixed';
        next if $best && $best->{result}{trust} >= $r->{trust};
        $best = { nick => $profile->{nick}, linked => $linked{$candidate} ? 1 : 0, result => $r };
    }
    return $best;
}

1;
