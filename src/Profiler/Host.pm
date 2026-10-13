package Profiler::Host;

use strict;
use warnings;

# What kind of host name someone connects from, and whether it says who they
# are. IRC servers only show a host name when it resolves back to the
# address, so a name like irc.example.net means its owner controls that DNS.
# That's very hard to fake, unlike an ISP's generated names, which anyone on
# the same ISP can end up with.
#
#   ip        a bare address, no name
#   isp       a name an ISP or provider generated, like cpe-198-51-100-202...
#   irccloud  an IRCCloud account, id-NNN.<server>.irccloud.com
#   custom    a name somebody chose
#   other     anything without a dot

# Labels that mark a generated name even without digits in it.
my $ISP_WORD = qr/^(?:a?dsl|vdsl|dhcp|dyn|dynamic|pool|cable|res|resi|residential|broadband|static|ppp|pppoe|cust|customer|clients?|fios|ftth|mobile|wireless|lte)$/;

# A first label with this many digits was made from the address.
my $ISP_DIGITS = 4;

# Hosts repeat a lot, especially during an import, so answers are kept.
my (%kind_cache, %key_cache);

sub kind {
    my ($host) = @_;
    return $kind_cache{$host} //= classify(lc $host);
}

sub classify {
    my ($host) = @_;
    return 'ip' if $host =~ /^[\d.]+$/ || $host =~ /:/;
    return 'other' unless $host =~ /\./;
    if ($host =~ /\.irccloud\.com$/) {
        return $host =~ /^id-\d+\./ ? 'irccloud' : 'isp';
    }
    my ($first) = split /\./, $host;
    return 'isp' if ($first =~ tr/0-9//) >= $ISP_DIGITS;
    return 'isp' if grep { /$ISP_WORD/ } split /\./, $host;
    return 'custom';
}

# A key that's the same for two hosts only when they're the same person: the
# account number for IRCCloud, whichever of its servers they came through,
# and the name itself for a custom host. undef for any other kind.
sub solid_key {
    my ($host) = @_;
    return $key_cache{$host} if exists $key_cache{$host};
    return $key_cache{$host} = make_solid_key($host);
}

sub make_solid_key {
    my ($host) = @_;
    my $kind = kind($host);
    return 'irccloud:' . ($host =~ /^id-(\d+)\./i)[0] if $kind eq 'irccloud';
    return lc $host if $kind eq 'custom';
    return undef;
}

1;
