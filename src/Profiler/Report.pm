package Profiler::Report;

use strict;
use warnings;

use Profiler::Rules;
use Profiler::Store ();

# How many of the nicks someone changes between are named before "and N more".
our $NICKS_SHOWN = 3;

# The line to print about a judged join, as (word, text), or nothing when
# there's nothing worth saying. The word is one of the summaries the script
# colours, like SUSPECT. $job is the join (nick, ident, host, version and
# was, the old nick for a nick change) and $r is Profiler::Score::judge's
# result. $ctx holds:
#
#   count        sightings of the nick before this one
#   other_nicks  nicks they've switched with, when they do that often
#   min          the channel's min_trust
#   verbose      whether to report a join that's fine
#   hostinfo     the host lookup, with proxy set on a likely proxy
sub verdict_line {
    my ($job, $r, $ctx) = @_;
    my $hostinfo = $ctx->{hostinfo} // {};
    my $count = $ctx->{count} // 0;

    my $was = defined $job->{was} ? "was $job->{was}, " : '';
    my $proxy = '';
    if ($hostinfo->{proxy}) {
        my $owner = $hostinfo->{org} // $hostinfo->{netname} // 'unknown owner';
        $proxy = " on a likely VPN, proxy or hosting address ($hostinfo->{ip}, $owner, matched '$hostinfo->{proxy}')";
    }
    my $who = "$job->{nick} ($was$job->{ident}\@$job->{host}, client: $job->{version})$proxy";
    my $seen = $count ? "seen $count time(s) before" : 'never seen before';
    $seen .= ", judged on the latest $Profiler::Store::HISTORY_SIZE" if $count > $Profiler::Store::HISTORY_SIZE;
    $seen .= '; changes nicks often, also ' . nick_list(@{ $ctx->{other_nicks} }) if @{ $ctx->{other_nicks} // [] };
    my $min = $ctx->{min} // 0;
    my $score = sprintf('trust %+.2f (%s, match %+.2f, confidence %.2f)',
        @$r{qw(trust verdict match confidence)});
    my $why = join ' ', map { sprintf('%s=%+.2f', $_, $r->{parts}{$_}) } sort keys %{ $r->{parts} };
    $why = " [$why]" if $why;

    # Suspects are always shown, whatever the rules say, since they are the
    # whole point: an established nick being worn by somebody else.
    if ($r->{verdict} eq 'suspect') {
        my $when = $job->{netsplit} ? ' during a netsplit rejoin' : '';
        return ('SUSPECT', "$who doesn't match the history of $job->{nick}$when; $score, $seen$why. "
            . "Quarantined; /profiler accept $job->{nick} if it's really them");
    }
    # A likely proxy is worth a warning even from someone we know, so it
    # takes over whichever quieter word the join would have had.
    my $word = $proxy ? 'WARNING' : undef;
    # Same person by everything but the host, most likely. A quiet note
    # rather than a warning, so SUSPECT keeps meaning something.
    if ($r->{verdict} eq 'new host') {
        my $matches = what_matches($r, qw(ident realname version)) // 'nothing else contradicts';
        my $often = $r->{host_changes_often} ? ' (frequently changes hosts)' : '';
        return ($word // 'NEW HOST', "$job->{nick} (${was}$job->{ident}\@$job->{host})$proxy: $matches$often; $seen");
    }
    if (Profiler::Rules::below_minimum($r, $min)) {
        return ('WARNING', "$who has $score, under $min; $seen$why");
    }
    # A nick change is always reported, since irssi's own line doesn't say
    # whether the new nick fits.
    if ($word || $ctx->{verbose} || defined $job->{was}) {
        my %word = (consistent => 'CONFIDENT', mixed => 'MIXED', unknown => 'UNKNOWN');
        return ($word // $word{ $r->{verdict} }, "$who has $score; $seen");
    }
    return;
}

# "a, b, c" for the first few nicks, then how many more there are.
sub nick_list {
    my (@nicks) = @_;
    return join(', ', @nicks) if @nicks <= $NICKS_SHOWN;
    return join(', ', @nicks[0 .. $NICKS_SHOWN - 1]) . ' and ' . (@nicks - $NICKS_SHOWN) . ' more';
}

# "ident, client match" for the attributes that scored in favour, or undef
# when none did.
sub what_matches {
    my ($r, @attrs) = @_;
    my %label = (host => 'host', ident => 'ident', realname => 'realname', version => 'client');
    my @same = map { $label{$_} } grep { ($r->{parts}{$_} // 0) > 0 } @attrs;
    return undef unless @same;
    return join(', ', @same) . (@same == 1 ? ' matches' : ' match');
}

1;
