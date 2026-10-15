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
# 01:26 -!- nick [ident@host] has joined #channel     (older logs)
#
# Idents can contain "]" (EFnet allows it), so the ident is anything up to
# the first "@" and the host is what follows, up to the closing "]".
sub parse_join {
    my ($line) = @_;
    my ($h, $mi, $s, $nick, $ident, $host, $channel) =
        $line =~ /^(\d\d):(\d\d)(?::(\d\d))? ?-!- (\S+) \[([^\@\s]+)\@([^\]\s]+)\] has joined (\S+)/
        or return undef;
    return {
        hour => $h + 0, min => $mi + 0, sec => ($s // 0) + 0,
        nick => $nick, ident => $ident, host => $host, channel => $channel,
    };
}

# 01:33:23-!- old is now known as new
# 01:33 -!- old is now known as new                   (older logs)
sub parse_nick_change {
    my ($line) = @_;
    my ($h, $mi, $s, $old, $new) =
        $line =~ /^(\d\d):(\d\d)(?::(\d\d))? ?-!- (\S+) is now known as (\S+)/ or return undef;
    return { hour => $h + 0, min => $mi + 0, sec => ($s // 0) + 0, old => $old, new => $new };
}

# A host written as an IPv4 or IPv6 address doubles as the ip, which is what
# lets nearby addresses count as partial matches.
sub literal_ip {
    my ($host) = @_;
    return $host if $host =~ /^\d{1,3}(\.\d{1,3}){3}$/;
    return $host if $host =~ /^[0-9a-f]*:[0-9a-f:]*:[0-9a-f.]*$/i;
    return undef;
}

# Epoch time of a parsed line, from its hour/min/sec and the file's date.
# Log times are local.
sub line_time {
    my ($line, $p) = @_;
    return POSIX::mktime($line->{sec}, $line->{min}, $line->{hour},
        $p->{day}, $p->{month} - 1, $p->{year} - 1900, 0, 0, -1);
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
#   promote_after_sightings, promote_after_days
#                    optional, see Profiler::Score::promotable
#
# Returns stats: joins, repeats, promoted, nick_changes (lines, so one change
# seen in three channels counts three times), unparsed, unparsed_examples
# (up to 5 lines) and verdicts (counts per verdict).
sub replay {
    my (%arg) = @_;
    my ($store, $network) = @arg{qw(store network)};
    my $promote_count = $arg{promote_after_sightings} // $Profiler::Score::PROMOTE_AFTER_SIGHTINGS;
    my $promote_days = $arg{promote_after_days} // $Profiler::Score::PROMOTE_AFTER_DAYS;
    my %stats = (joins => 0, repeats => 0, promoted => 0, nick_changes => 0, unparsed => 0, unparsed_examples => [],
        verdicts => {});
    my %last_join;
    my $month = '';

    for my $entry (channel_logs_by_day($arg{logs})) {
        my ($day, $files) = @$entry;
        if (substr($day, 0, 7) ne $month) {
            # Committing once a month keeps the import fast.
            $store->flush;
            $month = substr($day, 0, 7);
            $arg{on_month}->($month) if $arg{on_month};
        }

        my @joins;
        for my $f (@$files) {
            my ($path, $p) = @$f;
            open my $fh, '<', $path or die "cannot read $path: $!\n";
            while (my $line = <$fh>) {
                # A nick change shows up in the log of every channel the
                # person was in, which just repeats the same link.
                if (my $n = parse_nick_change($line)) {
                    $store->link_nicks($network, $n->{old}, $n->{new}, line_time($n, $p));
                    $stats{nick_changes}++;
                    next;
                }
                next unless $line =~ /-!- .* has joined /;
                my $j = parse_join($line);
                if (!$j) {
                    $stats{unparsed}++;
                    chomp $line;
                    push @{ $stats{unparsed_examples} }, "$path: $line" if @{ $stats{unparsed_examples} } < 5;
                    next;
                }
                $j->{time} = line_time($j, $p);
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
            my $sighting = observe($store, $network, $obs, $j->{time});
            $stats{joins}++;
            $stats{verdicts}{ $sighting->{verdict} }++;
            $stats{promoted} += $store->promote_if_moved($network, $j->{nick}, $j->{time}, $promote_count, $promote_days);
        }
    }
    $store->flush;
    return \%stats;
}

# Judges one observation against the nick's history as of $time and records
# it. Returns the recorded sighting. Callers promote afterwards
# (Store::promote_if_moved), once they've done anything else to it.
sub observe {
    my ($store, $network, $obs, $time) = @_;
    my $r = Profiler::Score::judge($store->profile($network, $obs->{nick}), $obs, $time);
    return $store->record($network, $obs, $time, $r->{verdict})->{sightings}[-1];
}

1;
