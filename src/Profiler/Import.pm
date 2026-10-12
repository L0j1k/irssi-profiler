package Profiler::Import;

use strict;
use warnings;

use File::Find ();
use POSIX ();

use Profiler::Score;

# Builds profiles from irssi logs laid out as
#
#     <logs>/<year>/<month>/<year>-<month>-<day>-<target>.log
#
# by replaying every join, oldest first, through the same judging the live
# script does. Each join is judged as of its own time, so decay and quarantine
# work out the same as if the profiler had been running back then.
#
# Logs only tell us nick, ident, host, channel and time, so imported sightings
# have no realname, server or version, and the scoring skips what's missing.
# Host names are not resolved and no registry whois is run: today's DNS says
# nothing about an old host, and thousands of whois queries would get us
# banned by the registries.

sub parse_path {
    my ($path) = @_;
    my ($y, $m, $d, $target) = $path =~ m{(?:^|/)(\d{4})-(\d\d)-(\d\d)-(.+)\.log$} or return undef;
    return { year => $y + 0, month => $m + 0, day => $d + 0, target => $target };
}

# 08:57:35-!- nick [ident@host] has joined #channel
sub parse_join {
    my ($line) = @_;
    my ($h, $mi, $s, $nick, $ident, $host, $channel) =
        $line =~ /^(\d\d):(\d\d)(?::(\d\d))?-!- (\S+) \[([^\]\@\s]+)\@([^\]\s]+)\] has joined (\S+)/
        or return undef;
    return {
        hour => $h + 0, min => $mi + 0, sec => ($s // 0) + 0,
        nick => $nick, ident => $ident, host => $host, channel => $channel,
    };
}

# A host written as an IPv4 or IPv6 address doubles as the ip, which is what
# lets nearby addresses count as partial matches.
sub literal_ip {
    my ($host) = @_;
    return $host if $host =~ /^\d{1,3}(\.\d{1,3}){3}$/;
    return $host if $host =~ /^[0-9a-f]*:[0-9a-f:]*:[0-9a-f.]*$/i;
    return undef;
}

# Channel logs grouped by day: [ ["YYYY-MM-DD", [paths...]], ... ] oldest
# first. Query logs (target not starting with # or &) are left out.
sub channel_logs_by_day {
    my ($logs) = @_;
    my %days;
    File::Find::find({ no_chdir => 1, wanted => sub {
        return unless -f $_;
        my $p = parse_path($_) or return;
        return unless $p->{target} =~ /^[#&]/;
        my $day = sprintf('%04d-%02d-%02d', @$p{qw(year month day)});
        push @{ $days{$day} }, [ $_, $p ];
    } }, $logs);
    return map { [ $_, [ sort { $a->[0] cmp $b->[0] } @{ $days{$_} } ] ] } sort keys %days;
}

# Replays the logs into the store. Arguments (named):
#
#   store, network   where profiles go
#   logs             the log directory for that network
#   recheck          seconds within which a rejoin of the same channel is
#                    skipped, as in the live script
#   on_month         optional callback, called with "YYYY-MM" as each month
#                    starts, for progress output
#
# Returns stats: joins, repeats, unparsed, unparsed_examples (up to 5 lines)
# and verdicts (counts per verdict).
sub replay {
    my (%arg) = @_;
    my ($store, $network) = @arg{qw(store network)};
    my %stats = (joins => 0, repeats => 0, unparsed => 0, unparsed_examples => [], verdicts => {});
    my %last_join;
    my $month = '';

    for my $entry (channel_logs_by_day($arg{logs})) {
        my ($day, $files) = @$entry;
        if (substr($day, 0, 7) ne $month) {
            $month = substr($day, 0, 7);
            $arg{on_month}->($month) if $arg{on_month};
        }

        my @joins;
        for my $f (@$files) {
            my ($path, $p) = @$f;
            open my $fh, '<', $path or die "cannot read $path: $!\n";
            while (my $line = <$fh>) {
                next unless $line =~ /-!- .* has joined /;
                my $j = parse_join($line);
                if (!$j) {
                    $stats{unparsed}++;
                    chomp $line;
                    push @{ $stats{unparsed_examples} }, "$path: $line" if @{ $stats{unparsed_examples} } < 5;
                    next;
                }
                $j->{time} = POSIX::mktime($j->{sec}, $j->{min}, $j->{hour},
                    $p->{day}, $p->{month} - 1, $p->{year} - 1900, 0, 0, -1);
                push @joins, $j;
            }
            close $fh;
        }

        # sort is stable, so joins in the same second keep their file order.
        for my $j (sort { $a->{time} <=> $b->{time} } @joins) {
            my $key = lc "$j->{channel}/$j->{nick}";
            if (defined $last_join{$key} && $j->{time} - $last_join{$key} < $arg{recheck}) {
                $stats{repeats}++;
                next;
            }
            $last_join{$key} = $j->{time};

            my $obs = {
                nick => $j->{nick}, ident => $j->{ident}, host => $j->{host},
                ip => literal_ip($j->{host}), channel => $j->{channel},
            };
            my $r = Profiler::Score::judge($store->profile($network, $j->{nick}), $obs, $j->{time});
            $store->record($network, $obs, $j->{time}, $r->{verdict});
            $stats{joins}++;
            $stats{verdicts}{ $r->{verdict} }++;
        }
    }
    return \%stats;
}

1;
