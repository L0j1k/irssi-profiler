package Profiler::Version;

use strict;
use warnings;

# What we record for someone who didn't answer CTCP VERSION in time. Lots of
# clients and bouncers never answer, and doing that every time is as
# consistent as answering the same way every time.
our $NO_REPLY = '(no reply)';

my $MAX_LENGTH = 200;

# The reply is whatever the other user's client chose to send, so control
# characters and runs of whitespace go before it is stored or printed.
sub clean {
    my ($raw) = @_;
    (my $v = $raw // '') =~ s/[\x00-\x1f\x7f]//g;
    $v =~ s/\s+/ /g;
    $v =~ s/^ | $//g;
    return length $v ? substr($v, 0, $MAX_LENGTH) : $NO_REPLY;
}

# The client name, which is the first word of nearly every VERSION reply, so
# an upgrade from "irssi v1.4.5" to "irssi v1.4.6" still looks like irssi.
sub client {
    my ($version) = @_;
    return $NO_REPLY if $version eq $NO_REPLY;
    my ($name) = $version =~ /^(\S+)/;
    return lc($name // '');
}

1;
