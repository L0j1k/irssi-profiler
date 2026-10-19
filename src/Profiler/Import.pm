package Profiler::Import;

use strict;
use warnings;

use File::Find ();
use POSIX ();

use Profiler::Marks;
use Profiler::Score;

# A ban in the logs is matched to whoever joined the channel this long before
# it. Logs don't say who was in the channel, only who joined.
our $BAN_LOOKBACK = 7 * 86400;

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

# 17:25:00-!- nick was kicked from #channel by op [reason]
# The reason can hold brackets of its own, so it runs to the last "]".
sub parse_kick {
    my ($line) = @_;
    my ($h, $mi, $s, $nick, $channel, $by, $reason) =
        $line =~ /^(\d\d):(\d\d)(?::(\d\d))? ?-!- (\S+) was kicked from (\S+) by (\S+) \[(.*)\]\s*$/ or return undef;
    return { hour => $h + 0, min => $mi + 0, sec => ($s // 0) + 0,
        nick => $nick, channel => $channel, by => $by, reason => $reason };
}

# Channel modes that take an argument when set, and when unset. The limit
# only takes one when it's set.
my %ARG_WHEN = ('+' => qr/[beIklov]/, '-' => qr/[beIkov]/);

# 09:39:46-!- mode/#channel [+b *!*@mask] by op
# The masks added as bans, from any mix of modes like "+o-b+b nick m1 m2".
# undef when the line adds no ban. Lifted bans are left out on purpose: bans
# get lifted to keep the list short, not because they were wrong.
sub parse_bans {
    my ($line) = @_;
    my ($h, $mi, $s, $channel, $modes, $args, $by) =
        $line =~ /^(\d\d):(\d\d)(?::(\d\d))? ?-!- mode\/(\S+) \[([-+][a-zA-Z+-]*)(?: ([^\]]*))?\] by (\S+)/ or return undef;
    my @args = split ' ', $args // '';
    my ($sign, @masks) = ('+');
    for my $m (split //, $modes) {
        if ($m eq '+' || $m eq '-') { $sign = $m; next }
        my $arg = $m =~ $ARG_WHEN{$sign} ? shift @args : undef;
        push @masks, $arg if $sign eq '+' && $m eq 'b' && defined $arg;
    }
    return undef unless @masks;
    return { hour => $h + 0, min => $mi + 0, sec => ($s // 0) + 0, channel => $channel, by => $by, masks => \@masks };
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
#   marks_only       optional: record only kicks and bans, for adding them
#                    to a file that already has the joins
#
# A kick is matched to the latest join of that nick in that channel, for the
# ident and host it hit. A ban is matched to whoever joined the channel in
# the $BAN_LOOKBACK before it (see Profiler::Marks::banned).
#
# Returns stats: joins, repeats, promoted, nick_changes (lines, so one change
# seen in three channels counts three times), kicks, bans (masks set),
# unparsed, unparsed_examples (up to 5 lines) and verdicts (counts per
# verdict).
sub replay {
    my (%arg) = @_;
    my ($store, $network) = @arg{qw(store network)};
    my $promote_count = $arg{promote_after_sightings} // $Profiler::Score::PROMOTE_AFTER_SIGHTINGS;
    my $promote_days = $arg{promote_after_days} // $Profiler::Score::PROMOTE_AFTER_DAYS;
    my %stats = (joins => 0, repeats => 0, promoted => 0, nick_changes => 0, kicks => 0, bans => 0,
        unparsed => 0, unparsed_examples => [], verdicts => {});
    my %last_join;
    # Per lowercased channel: each nick's latest join, as { nick, ident, host,
    # time }, for kicks, and the joins within $BAN_LOOKBACK, oldest first, for
    # bans. Someone kicked long after joining still matches.
    my (%latest, %recent);
    my $month = '';

    for my $entry (channel_logs_by_day($arg{logs})) {
        my ($day, $files) = @$entry;
        if (substr($day, 0, 7) ne $month) {
            # Committing once a month keeps the import fast.
            $store->flush;
            $month = substr($day, 0, 7);
            $arg{on_month}->($month) if $arg{on_month};
        }

        # Joins, kicks and bans, each tagged with what it is.
        my @events;
        for my $f (@$files) {
            my ($path, $p) = @$f;
            open my $fh, '<', $path or die "cannot read $path: $!\n";
            while (my $line = <$fh>) {
                # A nick change shows up in the log of every channel the
                # person was in, which just repeats the same link.
                if (my $n = parse_nick_change($line)) {
                    next if $arg{marks_only};
                    $store->link_nicks($network, $n->{old}, $n->{new}, line_time($n, $p));
                    $stats{nick_changes}++;
                    next;
                }
                my $e;
                if ($e = parse_kick($line)) {
                    $e->{kind} = 'kick';
                }
                elsif ($e = parse_bans($line)) {
                    $e->{kind} = 'ban';
                }
                elsif ($line =~ /-!- .* has joined /) {
                    $e = parse_join($line);
                    if (!$e) {
                        $stats{unparsed}++;
                        chomp $line;
                        push @{ $stats{unparsed_examples} }, "$path: $line" if @{ $stats{unparsed_examples} } < 5;
                        next;
                    }
                    $e->{kind} = 'join';
                }
                else {
                    next;
                }
                $e->{time} = line_time($e, $p);
                push @events, $e;
            }
            close $fh;
        }

        # sort is stable, so events in the same second keep their file order.
        for my $e (sort { $a->{time} <=> $b->{time} } @events) {
            my $channel = lc $e->{channel};
            my $window = $recent{$channel} //= [];
            shift @$window while @$window && $e->{time} - $window->[0]{time} > $BAN_LOOKBACK;
            if ($e->{kind} eq 'kick') {
                my $last = $latest{$channel}{ lc $e->{nick} } // {};
                $store->record_kick($network, { %$e, ident => $last->{ident}, host => $last->{host} }, $e->{time});
                $stats{kicks}++;
                next;
            }
            if ($e->{kind} eq 'ban') {
                for my $mask (@{ $e->{masks} }) {
                    $store->record_ban($network, { %$e, mask => $mask }, $e->{time}, Profiler::Marks::banned($mask, $window));
                    $stats{bans}++;
                }
                next;
            }

            my $who = { map { $_ => $e->{$_} } qw(nick ident host time) };
            $latest{$channel}{ lc $e->{nick} } = $who;
            push @$window, $who;
            next if $arg{marks_only};
            my $key = lc "$e->{channel}/$e->{nick}";
            if (defined $last_join{$key} && $e->{time} - $last_join{$key} < $arg{recheck}) {
                $stats{repeats}++;
                next;
            }
            $last_join{$key} = $e->{time};

            my $obs = {
                nick => $e->{nick}, ident => $e->{ident}, host => $e->{host},
                ip => literal_ip($e->{host}), channel => $e->{channel},
            };
            my $sighting = observe($store, $network, $obs, $e->{time});
            $stats{joins}++;
            $stats{verdicts}{ $sighting->{verdict} }++;
            $stats{promoted} += $store->promote_if_moved($network, $e->{nick}, $e->{time}, $promote_count, $promote_days);
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
    return $store->record($network, $obs, $time, @$r{qw(verdict match parts)})->{sightings}[-1];
}

1;
