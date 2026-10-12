package Profiler::Store;

use strict;
use warnings;

use JSON::PP;

# One JSON file per network in the data directory, loaded the first time that
# network is used and kept in memory after that. Each file looks like:
#
#     {
#       "users": {
#         "<lowercased nick>": {
#           "nick": "Bob", "first_seen": ..., "last_seen": ..., "sightings": N,
#           "hosts": {"<host>": count}, "ips": {...}, "idents": {...},
#           "realnames": {...}, "servers": {...}, "channels": {...},
#           "versions": {...}
#         }
#       },
#       "hostinfo": { "<host>": { "checked": time, "ip": ..., "proxy": ... } }
#     }

# Observation fields and the profile tables that count them.
my %TABLES = (
    host     => 'hosts',
    ip       => 'ips',
    ident    => 'idents',
    realname => 'realnames',
    server   => 'servers',
    channel  => 'channels',
    version  => 'versions',
);

my $JSON = JSON::PP->new->canonical->pretty;

sub new {
    my ($class, $dir) = @_;
    return bless { dir => $dir, nets => {}, broken => {} }, $class;
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
    my ($self, $network, $obs, $now) = @_;
    my $users = $self->net($network)->{users};
    my $p = $users->{ lc $obs->{nick} } //= { first_seen => $now, sightings => 0 };

    $p->{nick} = $obs->{nick};
    $p->{last_seen} = $now;
    $p->{sightings}++;
    for my $field (keys %TABLES) {
        my $value = $obs->{$field};
        next unless defined $value;
        $value = lc $value if $field eq 'channel';
        $p->{ $TABLES{$field} }{$value}++;
    }
    return $p;
}

sub set_hostinfo {
    my ($self, $network, $host, $info, $now) = @_;
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
}

1;
