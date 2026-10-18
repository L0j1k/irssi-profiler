package Profiler::Evasion;

use strict;
use warnings;

use List::Util qw(any min);

use Profiler::Import;
use Profiler::Marks;
use Profiler::Score;

# Is a join someone who was kicked or banned, back under another nick? Every
# nick whose record still counts (Profiler::Marks::counts) is a candidate.
#
# A nick can be worn by somebody else, and that somebody can be the one who
# got kicked. So the join is compared with the person each kick or ban hit:
# the nick's sightings that share the ident or a related host with one of
# its marks, plus the marks themselves. Bob doesn't take the blame for a
# troll who wore his nick, and the troll can still be found.

# Returns the best match as { nick, marks, result }, where result is what
# Profiler::Score::judge said about the observation against that person,
# or undef when nobody matches well enough. Trolls tend to get kicked after
# a join or two, too little history for a verdict, so this goes by the match
# alone: at least what a consistent verdict needs, from enough_evidence.
#
# $known_since is optional: when the joiner's own nick is well established,
# when we first saw it. Evading is getting kicked and coming back on a new
# nick, so the kick comes first. Someone who already had this nick when they
# got kicked on another one isn't evading with it.
sub best_match {
    my ($store, $network, $nick, $obs, $now, $known_since) = @_;
    my $all = $store->all_marks($network);
    my $best;
    for my $key (sort keys %$all) {
        next if $key eq lc $nick;
        # Only what had happened by $now, which matters when an old join is
        # judged again.
        my $marks = [ grep { $_->{time} <= $now } @{ Profiler::Marks::in_channel($all->{$key}, $key, $obs->{channel}) } ];
        next unless @$marks && Profiler::Marks::counts($marks, $now);
        next if defined $known_since && min(map { $_->{time} } @$marks) > $known_since;
        next unless any { looks_like($_, $obs) } @$marks;
        my $profile = $store->profile($network, $key);
        $marks = [ grep { !came_back($_, $profile, $now) } @$marks ];
        next unless @$marks && Profiler::Marks::counts($marks, $now);
        my $person = person($profile, $marks);
        # Channel and server are shared by everybody here, so they're left
        # out rather than let them pad the match.
        my $r = Profiler::Score::judge($person, { %$obs, channel => undef, server => undef }, $now);
        next unless $r->{match} >= $Profiler::Score::CONSISTENT_AT && enough_evidence($r, $person, $obs);
        next if $best && $best->{result}{match} >= $r->{match};
        $best = { nick => $profile ? $profile->{nick} : $key, marks => $marks, result => $r };
    }
    return $best;
}

# A host that matches, or two of ident, realname and client. An ident on its
# own is too little, and that's all a join from a proxy has left to judge,
# since the host isn't.
#
# A different ident rules them out unless they came from the very same host
# or IRCCloud account. A troll who's been banned a lot has used so many
# addresses that plenty of strangers on the same ISPs come close to one.
sub enough_evidence {
    my ($r, $person, $obs) = @_;
    if (($r->{parts}{ident} // 0) < 0) {
        return 0 unless ($r->{parts}{host} // 0) > 0;
        return any { Profiler::Score::similarity('host', $_, $obs) == 1 } @{ $person->{sightings} };
    }
    return 1 if ($r->{parts}{host} // 0) > 0;
    return (grep { ($r->{parts}{$_} // 0) > 0 } qw(ident realname version)) >= 2;
}

# Did whoever a mark hit come back on that nick afterwards, by $now? Then the
# ban was lifted or never stuck, and coming back on another nick isn't
# evading it. In #CHAN regulars get kicked and banned all the time and are
# back a minute later. Only a sighting that looks like the one who was hit
# counts, so bob coming back doesn't clear a troll who wore his nick.
sub came_back {
    my ($mark, $profile, $now) = @_;
    return any { $_->{time} > $mark->{time} && $_->{time} <= $now && looks_like($mark, $_) }
        @{ $profile ? $profile->{sightings} : [] };
}

# A kick or ban as a sighting: who it hit, where and when. undef when we
# never knew who had the nick.
sub mark_sighting {
    my ($mark) = @_;
    return undef unless defined $mark->{ident} && defined $mark->{host};
    return { ident => $mark->{ident}, host => $mark->{host}, ip => Profiler::Import::literal_ip($mark->{host}),
        channel => $mark->{channel}, time => $mark->{time} };
}

# Does a sighting share the ident, or a host that counts as a match, with
# what a mark hit? This is the cheap test that picks who to judge.
sub looks_like {
    my ($mark, $s) = @_;
    my $hit = mark_sighting($mark) or return 0;
    return 1 if defined $s->{ident} && $s->{ident} eq $hit->{ident};
    return defined $s->{host} && Profiler::Score::similarity('host', $hit, $s) > 0;
}

# The person the marks hit, as a profile: the nick's sightings that look
# like them, held ones included, since an impostor's would be held, plus
# the marks themselves.
sub person {
    my ($profile, $marks) = @_;
    my @own = grep { my $s = $_; any { looks_like($_, $s) } @$marks } @{ $profile ? $profile->{sightings} : [] };
    my @sightings = sort { $a->{time} <=> $b->{time} }
        (map { { %$_, quarantined => 0 } } @own), grep { defined } map { mark_sighting($_) } @$marks;
    return { sightings => \@sightings };
}

1;
