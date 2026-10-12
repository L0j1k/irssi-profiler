package Profiler::Diagnose;

use strict;
use warnings;

use List::Util qw(any max sum0);
use POSIX qw(ceil);

use Profiler::Score;

# Aggregate statistics about why sightings were judged suspect, for tuning
# the scoring against real data without anyone having to read the records.
# Only counts come out: no nicks, hosts or idents.

my @GAPS = (
    [ 86400,       'under a day' ],
    [ 7 * 86400,   'under a week' ],
    [ 30 * 86400,  'under a month' ],
    [ 182 * 86400, 'under six months' ],
    [ 365 * 86400, 'under a year' ],
);

my @HISTORY = ([ 5, '1-4' ], [ 20, '5-19' ], [ 100, '20-99' ]);

# The verdicts that get a sighting held in quarantine.
my %HELD = (suspect => 1, 'new host' => 1);

sub held { $HELD{ $_[0]{verdict} // '' } }

sub bucket {
    my ($value, $buckets, $last) = @_;
    for my $b (@$buckets) {
        return $b->[1] if $value < $b->[0];
    }
    return $last;
}

sub host_relation {
    my ($s, $before) = @_;
    my $best = max(0, map { Profiler::Score::similarity('host', $_, $s) } @$before);
    return $best >= 1 ? 'same' : $best > 0 ? 'near' : 'new';
}

sub ident_relation {
    my ($s, $before) = @_;
    return 'same' if any { $_->{ident} eq $s->{ident} } @$before;
    (my $bare = $s->{ident}) =~ s/^~//;
    return 'differs only by ~' if any { (my $b = $_->{ident}) =~ s/^~//; $b eq $bare } @$before;
    return 'new';
}

# Takes the decoded data file. For every sighting that was judged suspect,
# compares it with the accepted sightings that came before it in the same
# nick's history.
sub suspect_report {
    my ($data) = @_;
    my %r = (suspects => 0, nicks => 0, nicks_with_suspects => 0, owner_seen_after => 0,
        by_verdict => {}, by_change => {}, by_gap => {}, by_history => {}, by_outcome => {});
    my @per_nick;

    for my $p (values %{ $data->{users} }) {
        $r{nicks}++;
        my @sightings = sort { $a->{time} <=> $b->{time} } @{ $p->{sightings} };
        my $count = 0;

        for my $i (0 .. $#sightings) {
            my $s = $sightings[$i];
            next unless held($s);
            my @before = grep { !$_->{quarantined} && !held($_) } @sightings[0 .. $i - 1];
            next unless @before;
            $count++;

            $r{by_verdict}{ $s->{verdict} }++;
            $r{by_change}{ 'host ' . host_relation($s, \@before) . ', ident ' . ident_relation($s, \@before) }++;
            $r{by_gap}{ bucket($s->{time} - $before[-1]{time}, \@GAPS, 'a year or more') }++;
            $r{by_history}{ bucket(scalar @before, \@HISTORY, '100+') }++;
            $r{by_outcome}{ $s->{promoted} ? 'promoted' : $s->{quarantined} ? 'still quarantined' : 'accepted by hand' }++;

            # Did the usual person turn up again afterwards? That points to an
            # impostor or a second person sharing the nick, rather than a move.
            my @after = grep { !$_->{quarantined} && !held($_) } @sightings[$i + 1 .. $#sightings];
            $r{owner_seen_after}++ if any { host_relation($_, \@before) ne 'new' } @after;
        }
        if ($count) {
            $r{nicks_with_suspects}++;
            push @per_nick, $count;
        }
    }

    $r{suspects} = sum0(@per_nick);
    @per_nick = sort { $b <=> $a } @per_nick;
    for ([ top_1_percent => 0.01 ], [ top_10_percent => 0.10 ]) {
        my ($name, $share) = @$_;
        my $n = ceil(@per_nick * $share);
        $r{concentration}{$name} = sum0(@per_nick[0 .. $n - 1]);
    }
    return \%r;
}

1;
