package Profiler::Host;

use strict;
use warnings;

use IO::Socket::SSL::PublicSuffix;

# What kind of host name someone connects from, and whether it says who they
# are. IRC servers only show a host name when it resolves back to the
# address, so a name like irc.example.net means its owner controls that DNS.
# That's very hard to fake, unlike an ISP's generated names, which anyone on
# the same ISP can end up with.
#
#   ip        a bare address, no name
#   spoof     a private address like 192.168.0.1, which nobody can really
#             connect from, so a server admin gave it to them
#   isp       a name an ISP or provider generated, like cpe-198-51-100-202...
#   irccloud  an IRCCloud connection, id-NNN.<server>.irccloud.com or just
#             <server>.irccloud.com with the account in the ident
#   custom    a name somebody chose
#   other     anything without a dot

# Labels that mark a generated name even without digits in it.
my $ISP_WORD = qr/^(?:a?dsl|vdsl|dhcp|dyn|dynamic|pool|cable|res|resi|residential|broadband|static|ppp|pppoe|cust|customer|clients?|fios|ftth|mobile|wireless|lte)$/;

# A name with this many digits ahead of its domain was made from the
# address. Counting across every label catches ones like Verizon's
# 226.sub-203-0-113.myvzw.com, where the first label alone is short.
my $ISP_DIGITS = 4;

# Hosts repeat a lot, especially during an import, so answers are kept.
my (%kind_cache, %key_cache, %domain_cache);

my $public_suffix = IO::Socket::SSL::PublicSuffix->default;

# The domain someone registered, like myvzw.com or example.co.uk, using the
# public suffix list that comes with IO::Socket::SSL.
sub registered_domain {
    my ($host) = @_;
    return $domain_cache{$host} //= scalar $public_suffix->public_suffix(lc $host, 1);
}

# The ISP's domain for a generated name, so two addresses from the same ISP
# can be told apart from a change of ISP. undef for any other kind of host.
sub isp_domain {
    my ($host) = @_;
    return kind($host) eq 'isp' ? registered_domain($host) : undef;
}

sub kind {
    my ($host) = @_;
    return $kind_cache{$host} //= classify(lc $host);
}

sub classify {
    my ($host) = @_;
    return 'spoof' if is_private($host);
    return 'ip' if $host =~ /^[\d.]+$/ || $host =~ /:/;
    return 'other' unless $host =~ /\./;
    return 'irccloud' if $host =~ /\.irccloud\.com$/;
    my $labels = substr($host, 0, length($host) - length(registered_domain($host) // ''));
    return 'isp' if ($labels =~ tr/0-9//) >= $ISP_DIGITS;
    return 'isp' if grep { /$ISP_WORD/ } split /\./, $host;
    return 'custom';
}

# 10/8, 172.16/12, 192.168/16, 127/8, and IPv6 unique local (fc00::/7),
# link local (fe80::/10) and loopback.
sub is_private {
    my ($host) = @_;
    if (my ($first, $second) = $host =~ /^(\d+)\.(\d+)\.\d+\.\d+$/) {
        return $first == 10 || $first == 127 || ($first == 192 && $second == 168)
            || ($first == 172 && $second >= 16 && $second <= 31);
    }
    return $host =~ /^(?:f[cd][0-9a-f]{0,2}|fe[89ab][0-9a-f]?):/ || $host eq '::1';
}

# A key that's the same for two connections only when they're the same
# person: the account number for IRCCloud, whichever of its servers they came
# through, and the host itself for a custom name or a spoof. undef for any
# other kind. IRCCloud gives the account as id-NNN in the host or as uidNNN
# or sidNNN in the ident, and users can't choose either.
sub solid_key {
    my ($host, $ident) = @_;
    return $key_cache{$host} if exists $key_cache{$host};
    my $kind = kind($host);
    # Not cached, since it can depend on the ident.
    if ($kind eq 'irccloud') {
        my ($account) = $host =~ /^id-(\d+)\./i;
        $account //= irccloud_account($ident);
        return defined $account ? "irccloud:$account" : undef;
    }
    return $key_cache{$host} = $kind eq 'custom' || $kind eq 'spoof' ? lc $host : undef;
}

# The IRCCloud account number in an ident, or undef. It's uidNNN on the free
# tier and sidNNN with a subscription, and older connections have it with a
# tilde, like ~sidNNN.
sub irccloud_account {
    my ($ident) = @_;
    my ($account) = ($ident // '') =~ /^~?[us]id(\d+)$/;
    return $account;
}

1;
