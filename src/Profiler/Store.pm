package Profiler::Store;

use strict;
use warnings;

use JSON::XS;

# One JSON file per network in the data directory, loaded the first time that
# network is used and kept in memory after that. Each file looks like:
#
#     {
#       "users": {
#         "<lowercased nick>": {
#           "nick": "Bob", "first_seen": ..., "last_seen": ...,
#           "sightings": [
#             { "time": ..., "host": ..., "ip": ..., "ident": ..., "realname": ...,
#               "server": ..., "version": ..., "channel": ..., "proxy": ...,
#               "verdict": "consistent", "quarantined": 0, "reviewed": 0 },
#             ...
#           ]
#         }
#       },
#       "hostinfo": { "<host>": { "checked": time, "ip": ..., "proxy": ... } }
#     }
#
# A sighting judged "suspect" is quarantined: kept for the record but left out
# of the history its nick is judged against, so an impostor can't train the
# profile toward themselves. /profiler accept or reject marks it reviewed.

# Observation fields kept in each sighting. Missing ones are left out.
my @FIELDS = qw(host ip ident realname server version channel proxy);

# Sightings kept per nick. The oldest go first.
our $MAX_SIGHTINGS = 200;

# Compact rather than pretty: it halves the size of a big file. Pipe it through
# jq to read it.
my $JSON = JSON::XS->new->canonical;

sub new {
    my ($class, $dir) = @_;
    return bless { dir => $dir, nets => {}, broken => {}, dirty => {} }, $class;
}

sub path {
    my ($self, $network) = @_;
    (my $name = lc $network) =~ s/[^a-z0-9._-]/_/g;
    return "$self->{dir}/$name.json";
}

# Dies if the file exists but cannot be read. The network stays marked broken
# so later calls die too and nothing ever saves over the file.
sub net {
    my ($self, $network) = @_;
    my $key = lc $network;
    die $self->{broken}{$key} if $self->{broken}{$key};
    return $self->{nets}{$key} if $self->{nets}{$key};

    my $path = $self->path($network);
    my $data = { users => {}, hostinfo => {} };
    if (-e $path) {
        $data = eval {
            open my $fh, '<', $path or die "$!\n";
            local $/;
            $JSON->decode(scalar <$fh>);
        };
        if (!$data) {
            $self->{broken}{$key} = "cannot parse $path: $@";
            die $self->{broken}{$key};
        }
    }
    return $self->{nets}{$key} = $data;
}

sub profile {
    my ($self, $network, $nick) = @_;
    return $self->net($network)->{users}{ lc $nick };
}

sub record {
    my ($self, $network, $obs, $now, $verdict) = @_;
    my $users = $self->net($network)->{users};
    $self->{dirty}{ lc $network } = 1;
    my $p = $users->{ lc $obs->{nick} } //= { first_seen => $now, sightings => [] };

    my %sighting = map { defined $obs->{$_} ? ($_ => $obs->{$_}) : () } @FIELDS;
    $sighting{channel} = lc $sighting{channel} if defined $sighting{channel};
    $sighting{time} = $now;
    $sighting{verdict} = $verdict;
    $sighting{quarantined} = $verdict eq 'suspect' ? 1 : 0;

    $p->{nick} = $obs->{nick};
    $p->{last_seen} = $now;
    push @{ $p->{sightings} }, \%sighting;
    splice @{ $p->{sightings} }, 0, @{ $p->{sightings} } - $MAX_SIGHTINGS
        if @{ $p->{sightings} } > $MAX_SIGHTINGS;
    return $p;
}

# Quarantined sightings nobody has looked at yet, oldest first, each as
# { nick => ..., sighting => ... }.
sub suspects {
    my ($self, $network) = @_;
    my @found;
    for my $p (values %{ $self->net($network)->{users} }) {
        push @found, map { { nick => $p->{nick}, sighting => $_ } }
            grep { $_->{quarantined} && !$_->{reviewed} } @{ $p->{sightings} };
    }
    return sort { $a->{sighting}{time} <=> $b->{sighting}{time} } @found;
}

# Let a nick's unreviewed suspect sightings count after all, say because they
# really did move. Returns how many changed.
sub accept {
    my ($self, $network, $nick) = @_;
    return $self->review($network, $nick, 0);
}

# Agree that a nick's unreviewed suspect sightings were someone else.
sub reject {
    my ($self, $network, $nick) = @_;
    return $self->review($network, $nick, 1);
}

sub review {
    my ($self, $network, $nick, $quarantined) = @_;
    my $p = $self->profile($network, $nick) or return 0;
    my @pending = grep { $_->{quarantined} && !$_->{reviewed} } @{ $p->{sightings} };
    $self->{dirty}{ lc $network } = 1 if @pending;
    for my $s (@pending) {
        $s->{quarantined} = $quarantined;
        $s->{reviewed} = 1;
    }
    return scalar @pending;
}

sub set_hostinfo {
    my ($self, $network, $host, $info, $now) = @_;
    $self->{dirty}{ lc $network } = 1;
    $self->net($network)->{hostinfo}{$host} = { %$info, checked => $now };
}

# The cached lookup for a host if it is younger than max_age seconds.
sub fresh_hostinfo {
    my ($self, $network, $host, $now, $max_age) = @_;
    my $info = $self->net($network)->{hostinfo}{$host} or return undef;
    return $now - $info->{checked} <= $max_age ? $info : undef;
}

# Writes to a temp file and renames it over the real one, so a crash halfway
# through never leaves a truncated file behind.
sub save {
    my ($self, $network) = @_;
    my $data = $self->net($network);
    my $path = $self->path($network);
    my $tmp = "$path.tmp";

    open my $fh, '>', $tmp or die "cannot write $tmp: $!\n";
    print $fh $JSON->encode($data);
    close $fh or die "cannot write $tmp: $!\n";
    rename $tmp, $path or die "cannot rename $tmp to $path: $!\n";
    delete $self->{dirty}{ lc $network };
}

# Saves every network changed since its last save and returns their names.
# The live script calls this on a timer, since rewriting a big file on every
# join would make irssi stutter.
sub save_dirty {
    my ($self) = @_;
    my @saved = sort keys %{ $self->{dirty} };
    $self->save($_) for @saved;
    return @saved;
}

1;
