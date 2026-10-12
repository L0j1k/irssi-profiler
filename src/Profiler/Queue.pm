package Profiler::Queue;

use strict;
use warnings;

# A throttled queue of whois requests for one server. Jobs come out at most one
# per `interval` seconds. When `burst_joins` joins land within `burst_window`
# seconds, which is what a netsplit rejoin looks like, the queue stops handing
# out jobs for `burst_pause` seconds after the latest join of the burst, then
# drains at the normal rate. At most `max_len` jobs wait at once.
sub new {
    my ($class, %opt) = @_;
    return bless {
        %opt,
        jobs         => [],
        keys         => {},
        joins        => [],
        paused_until => 0,
        next_at      => 0,
    }, $class;
}

# Returns true if the job was queued. Every call counts as a join for burst
# detection, even when the job itself is refused.
sub add {
    my ($self, $key, $job, $now) = @_;

    my $joins = $self->{joins};
    push @$joins, $now;
    shift @$joins while @$joins && $joins->[0] <= $now - $self->{burst_window};
    $self->{paused_until} = $now + $self->{burst_pause} if @$joins >= $self->{burst_joins};

    return 0 if $self->{keys}{$key};
    return 0 if @{ $self->{jobs} } >= $self->{max_len};
    push @{ $self->{jobs} }, [ $key, $job ];
    $self->{keys}{$key} = 1;
    return 1;
}

sub remove {
    my ($self, $key) = @_;
    return unless delete $self->{keys}{$key};
    $self->{jobs} = [ grep { $_->[0] ne $key } @{ $self->{jobs} } ];
}

sub paused {
    my ($self, $now) = @_;
    return $now < $self->{paused_until};
}

sub length {
    my ($self) = @_;
    return scalar @{ $self->{jobs} };
}

# The next job if one is due, otherwise undef.
sub take {
    my ($self, $now) = @_;
    return undef if $self->paused($now) || $now < $self->{next_at};
    my $entry = shift @{ $self->{jobs} } or return undef;
    delete $self->{keys}{ $entry->[0] };
    $self->{next_at} = $now + $self->{interval};
    return $entry->[1];
}

1;
