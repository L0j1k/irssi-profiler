package Profiler::Nick;

use strict;
use warnings;

# When someone's nick is taken (juped, or a ghost they haven't killed yet),
# they come back as bob_, bobbb, B0B` or bob|away. The skeleton boils all of
# those down to "bob", so we can find the profiles worth comparing a joiner
# with. It only picks candidates: whether it's really bob is still decided
# by host and ident.
#
# Steps, in order: lowercase, drop a "|suffix", strip junk characters from
# both ends and digits from the end, read leet digits as letters, and
# collapse repeated letters. Trailing digits go before leet, so bob2000 is
# bob rather than bobzooo.
my $JUNK = qr/[-_`^\[\]{}\\|]/;

sub skeleton {
    my ($nick) = @_;
    my $lower = lc $nick;
    (my $s = $lower) =~ s/\|.*//;
    $s =~ s/^$JUNK+//;
    $s =~ s/(?:$JUNK|\d)+$//;
    $s =~ tr/013457/oieast/;
    $s =~ s/(.)\1+/$1/g;
    # Nothing left means the nick was all junk, like "___". Keep it as it is
    # rather than lumping every such nick together.
    return length $s ? $s : $lower;
}

1;
