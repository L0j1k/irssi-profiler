package Profiler::Marks;

use strict;
use warnings;

use List::Util qw(sum0);
use POSIX qw(strftime);

use Profiler::Score;

# Kicks and bans. Trolls get kicked and banned far more than regulars, so a
# join that looks like someone with that record is worth a loud warning.
# This is kept apart from trust, which only asks whether a join is the usual
# person behind its nick: a banned troll coming back is still themselves.

# A ban counts this much, for good, since bans get lifted only to keep the
# list short. A kick counts KICK_WEIGHT, losing half of it every half-life
# (Profiler::Score::HALF_LIFE).
our $BAN_WEIGHT = 1;
our $KICK_WEIGHT = 0.5;

# A record counts from this weight: any ban, or a kick in the last half-life.
our $COUNTS_AT = 0.25;

# A ban matching more nicks than this was too broad to say who it was for.
our $BAN_MAX_NICKS = 3;

# Does nick!ident@host fit an IRC ban mask? * is any run of characters and ?
# any one, and case doesn't matter.
sub mask_matches {
    my ($mask, $nick, $ident, $host) = @_;
    (my $re = quotemeta lc $mask) =~ s/\\\*/.*/g;
    $re =~ s/\\\?/./g;
    return lc("$nick!$ident\@$host") =~ /^$re$/ ? 1 : 0;
}

# The nicks a ban was for, from @$candidates ({ nick, ident, host }), each
# once in the order first seen. Empty when nobody matched or too many did.
sub banned_nicks {
    my ($mask, $candidates) = @_;
    my (%seen, @nicks);
    for my $c (@$candidates) {
        next unless mask_matches($mask, @$c{qw(nick ident host)});
        push @nicks, $c->{nick} unless $seen{ lc $c->{nick} }++;
    }
    return @nicks > $BAN_MAX_NICKS ? () : @nicks;
}

sub weight {
    my ($marks, $now) = @_;
    return sum0(map {
        $_->{kind} eq 'ban' ? $BAN_WEIGHT : $KICK_WEIGHT * Profiler::Score::age_weight($_, $now)
    } @$marks);
}

sub counts {
    my ($marks, $now) = @_;
    return weight($marks, $now) >= $COUNTS_AT;
}

# "banned 1x, kicked 2x, last 2026-09-02 by alice (shamed)", with the
# latest kick or ban. @$marks are oldest first, as Store::marks gives them.
sub summary {
    my ($marks) = @_;
    my %n;
    $n{ $_->{kind} }++ for @$marks;
    my @counts = map { $n{$_} ? ($_ eq 'ban' ? 'banned' : 'kicked') . " $n{$_}x" : () } qw(ban kick);
    my $last = $marks->[-1];
    my $why = defined $last->{reason} && length $last->{reason} ? " ($last->{reason})" : '';
    return join(', ', @counts) . ', last ' . strftime('%Y-%m-%d', localtime $last->{time}) . " by $last->{by}$why";
}

1;
