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

# A fresh ban counts this much and a fresh kick KICK_WEIGHT, and both lose
# half of it every half-life (Profiler::Score::HALF_LIFE). Bans fade too,
# since bots kick whoever an op bans, so a ban is often a kick as well.
our $BAN_WEIGHT = 1;
our $KICK_WEIGHT = 0.5;

# A record counts from this weight: a ban in the last two half-lives, or a
# kick in the last one.
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

# Who a ban was for, from @$candidates ({ nick, ident, host }): one for each
# nick that matched, as it first matched. Empty when nobody matched or too
# many did.
sub banned {
    my ($mask, $candidates) = @_;
    my (%seen, @who);
    for my $c (@$candidates) {
        next unless mask_matches($mask, @$c{qw(nick ident host)});
        push @who, $c unless $seen{ lc $c->{nick} }++;
    }
    return @who > $BAN_MAX_NICKS ? () : @who;
}

# The kicks and bans that say something about $nick joining $channel: the
# ones from that channel, since a ban in #efnet says nothing about #chan, and
# not the ones they set on themselves.
sub in_channel {
    my ($marks, $nick, $channel) = @_;
    return [ grep { $_->{channel} eq lc $channel && lc($_->{by} // '') ne lc $nick } @$marks ];
}

sub weight {
    my ($marks, $now) = @_;
    return sum0(map {
        ($_->{kind} eq 'ban' ? $BAN_WEIGHT : $KICK_WEIGHT) * Profiler::Score::age_weight($_, $now)
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
