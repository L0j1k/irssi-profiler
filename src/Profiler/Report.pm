package Profiler::Report;

use strict;
use warnings;

use POSIX ();

use Profiler::Host;
use Profiler::Marks;
use Profiler::Rules;
use Profiler::Score ();
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
#   marks        the nick's kicks and bans, when they still count
#                (Profiler::Marks::counts), which always gets the line shown
sub verdict_line {
    my ($job, $r, $ctx) = @_;
    my $hostinfo = $ctx->{hostinfo} // {};
    my $count = $ctx->{count} // 0;

    my $was = defined $job->{was} ? "was $job->{was}, " : '';
    my $proxy = '';
    if ($hostinfo->{proxy}) {
        my $owner = $hostinfo->{org} // $hostinfo->{netname} // 'unknown owner';
        my $used = $r->{provider_seen} ? ", a provider they've used before" : '';
        $proxy = " on a likely VPN, proxy or hosting address ($hostinfo->{ip}, $owner, matched '$hostinfo->{proxy}'$used)";
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
        my $isp = $r->{new_isp} ? ": from an ISP they've never used, $r->{new_isp}{isp}, usually $r->{new_isp}{usual}" : '';
        return ('SUSPECT', "$who doesn't match the history of $job->{nick}$when$isp; $score, $seen$why. "
            . "Quarantined; /profiler accept $job->{nick} if it's really them");
    }
    # Too little recent history to judge, but what there is disagrees, which
    # is how someone picking up a long idle nick looks. It's held like a
    # suspect (see Profiler::Score::held).
    if ($r->{verdict} eq 'unknown' && Profiler::Score::held(@$r{qw(verdict match parts)})) {
        return ('WARNING', "$who doesn't match what little is left of $job->{nick}'s history; $score, $seen$why. "
            . "Quarantined; /profiler accept $job->{nick} if it's really them");
    }
    # A likely proxy the nick hasn't been on before is worth a warning even
    # from someone we know, so it takes over whichever quieter word the join
    # would have had. One they're always on is probably their own server,
    # and another address from a VPN provider they use is just a new exit.
    my $word = $proxy && !$r->{host_seen} && !$r->{provider_seen} ? 'WARNING' : undef;
    # Same person by everything but the host, most likely. A quiet note
    # rather than a warning, so SUSPECT keeps meaning something.
    if ($r->{verdict} eq 'new host') {
        my $matches = what_matches($r, qw(ident realname version)) // 'nothing else contradicts';
        my $often = $r->{host_changes_often} ? ' (frequently changes hosts)' : '';
        return ($word // 'NEW HOST', "$job->{nick} (${was}$job->{ident}\@$job->{host})$proxy: $matches$often; $seen");
    }
    # Under the minimum with nothing against them is someone we just haven't
    # seen much of, like a newcomer. Anything that disagrees could be a
    # troll on the nick, which is what WARNING is for.
    if (Profiler::Rules::below_minimum($r, $min)) {
        my $against = grep { $_ < 0 } values %{ $r->{parts} };
        return ($against ? 'WARNING' : $word // 'UNPROVEN', "$who has $score, under $min; $seen$why");
    }
    # A nick nobody has seen, on an address without a name, is how a lot of
    # trolls back on a proxy turn up. It's weak on its own, but worth a look.
    my $bare = !$count && Profiler::Host::kind($job->{host}) eq 'ip';
    $seen .= ', from a bare address with no reverse DNS' if $bare;
    # Kicks and bans are worth seeing every time the nick turns up.
    my $marked = @{ $ctx->{marks} // [] } > 0;
    $seen .= '; ' . Profiler::Marks::summary($ctx->{marks}) if $marked;
    # A nick change is always reported, since irssi's own line doesn't say
    # whether the new nick fits.
    if ($word || $ctx->{verbose} || defined $job->{was} || $bare || $marked) {
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

# Adds "looks like bob" to a join's verdict line, or makes a line of its own
# when the join didn't get one. Returns the verdict word (undef without a
# verdict line), "VARIANT <verdict>" for the variant's word, whose colour says
# how well the join fits bob's history, and the text.
sub variant_line {
    my ($job, $variant, $word, $text) = @_;
    my $v = $variant->{result};
    my $how = $variant->{linked} ? ", who they've switched nicks with before" : '';
    my $matches = what_matches($v, qw(host ident realname version)) // 'nothing contradicts';
    my $looks = sprintf('looks like %s%s: %s; trust %+.2f against their history', $variant->{nick}, $how, $matches, $v->{trust});
    return ($word, "VARIANT $v->{verdict}", defined $text ? "$text; $looks" : "$job->{nick} $looks");
}

# The warning for a join that looks like someone who was kicked, banned or
# caught juping (see Profiler::Evasion::best_match). It's JUPER when they
# juped, which is the worse of the two.
sub evader_line {
    my ($job, $evasion) = @_;
    my $r = $evasion->{result};
    my $matches = what_matches($r, qw(host ident realname version)) // 'nothing contradicts';
    my $word = (grep { $_->{kind} eq 'jupe' } @{ $evasion->{marks} }) ? 'JUPER' : 'EVADER';
    return ($word, sprintf('%s (%s@%s) looks like %s (%s): %s; match %+.2f against them', $job->{nick},
        $job->{ident}, $job->{host}, $evasion->{nick}, Profiler::Marks::summary($evasion->{marks}), $matches, $r->{match}));
}

# The note for when a nick's held joins were let into its history (see
# Profiler::Store::promote_if_moved). They can be months old, so it says when
# they were from.
sub moved_line {
    my ($job, $moved) = @_;
    my ($first, $last) = map { POSIX::strftime('%Y-%m-%d', localtime $_->{time}) } @$moved[0, -1];
    my $when = $first eq $last ? "on $first" : "from $first to $last";
    return ('MOVED', "$job->{nick} looks like they have a new usual host: " . @$moved . " held join(s) $when "
        . "now count toward their history. /profiler show $job->{nick} to check");
}

# The line for catching someone juping a nick (see Profiler::Jupe): $job is
# whoever holds it, $r what Profiler::Jupe::juper said, and $waiting the
# variant its owner is waiting on.
sub juper_line {
    my ($job, $r, $waiting) = @_;
    my $differs = what_differs($r, qw(ident realname version));
    return ('JUPER', sprintf("%s (%s@%s, client: %s) is sitting on %s's nick while %s, who fits %s's history, waits: "
        . '%s; match %+.2f against %s. Remembered as a juper', $job->{nick}, $job->{ident}, $job->{host},
        $job->{version}, $job->{nick}, $waiting, $job->{nick}, $differs, $r->{match}, $job->{nick}));
}

# "ident, client match" for the attributes that scored in favour, or undef
# when none did.
sub what_matches {
    my ($r, @attrs) = @_;
    return labelled([ grep { ($r->{parts}{$_} // 0) > 0 } @attrs ], 'matches', 'match');
}

# "ident doesn't match" for the attributes that scored against, or undef
# when none did.
sub what_differs {
    my ($r, @attrs) = @_;
    return labelled([ grep { ($r->{parts}{$_} // 0) < 0 } @attrs ], "doesn't match", "don't match");
}

sub labelled {
    my ($attrs, $one, $many) = @_;
    my %label = (host => 'host', ident => 'ident', realname => 'realname', version => 'client');
    return undef unless @$attrs;
    return join(', ', map { $label{$_} } @$attrs) . ' ' . (@$attrs == 1 ? $one : $many);
}

1;
