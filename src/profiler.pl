use strict;
use warnings;

use Irssi;
use File::Path qw(make_path);
use JSON::PP;
use POSIX ();

use lib Irssi::get_irssi_dir() . '/scripts/profiler-lib';
use Profiler::Queue;
use Profiler::Rules;
use Profiler::Score;
use Profiler::Store;
use Profiler::Version;
use Profiler::Whois;

our $VERSION = '0.10';
our %IRSSI = (
    authors     => 'l0j1k',
    name        => 'profiler',
    description => 'Builds a trust profile of everyone joining watched channels and warns about strangers.',
    license     => 'MIT',
);

# When someone joins a channel named in the rules file, we queue a whois and a
# CTCP VERSION on them. Once the whois is done and the VERSION reply is in (or
# has timed out) we look up their host with the system whois (in a child
# process, so irssi never blocks) to spot VPNs, proxies and hosting providers.
# Then we score them against what we saw of that nick before, print a warning
# in the channel if the score is under the rule's minimum, and add this
# sighting to their profile. Nothing is sent to the channel, and the user only
# gets the CTCP VERSION request.

my $rules = { watches => [], proxy_keywords => [] };
my $store;

# One throttled whois queue per server tag.
my %queues;

# Lookups in flight, keyed "tag/nick" lowercased. Each entry collects the whois
# fields and VERSION reply for that nick, plus every queued join (one per
# channel) that is waiting on them, so a nick joining two watched channels only
# gets asked once.
my %pending;

# When each "tag/channel/nick" was last profiled, so someone bouncing in and
# out of a channel is neither whois'ed again nor counted again for a while.
my %recent;

sub info {
    my ($text) = @_;
    Irssi::print("profiler: $text", MSGLEVEL_CLIENTCRAP);
}

sub irssi_path {
    my ($setting, $default) = @_;
    my $path = Irssi::settings_get_str($setting);
    return $path if defined $path && $path =~ /\S/;
    return Irssi::get_irssi_dir() . "/scripts/$default";
}

sub load_rules {
    my $path = irssi_path('profiler_rules_file', 'profiler.rules');
    my $fh;
    if (!open $fh, '<', $path) {
        $rules = { watches => [], proxy_keywords => [] };
        info("cannot read rules file $path ($!), watching nothing");
        return;
    }
    my ($loaded, $errors) = Profiler::Rules::parse(<$fh>);
    close $fh;
    info("$path $_") for @$errors;
    $rules = $loaded;
    info("loaded " . scalar(@{ $rules->{watches} }) . " watch rule(s) and "
        . scalar(@{ $rules->{proxy_keywords} }) . " extra proxy keyword(s) from $path");
}

sub open_store {
    my $dir = irssi_path('profiler_data_dir', 'profiler-data');
    make_path($dir) unless -d $dir;
    $store = Profiler::Store->new($dir);
}

sub proxy_keywords {
    return [ @Profiler::Whois::DEFAULT_PROXY_KEYWORDS, @{ $rules->{proxy_keywords} } ];
}

sub queue_for {
    my ($tag) = @_;
    return $queues{ lc $tag } //= Profiler::Queue->new(
        interval     => Irssi::settings_get_int('profiler_whois_interval'),
        burst_joins  => Irssi::settings_get_int('profiler_burst_joins'),
        burst_window => Irssi::settings_get_int('profiler_burst_window'),
        burst_pause  => Irssi::settings_get_int('profiler_burst_pause'),
        max_len      => Irssi::settings_get_int('profiler_queue_max'),
    );
}

sub recent_key {
    my ($tag, $channel, $nick) = @_;
    return lc("$tag/$channel/$nick");
}

sub on_join {
    my ($server, $channel, $nick, $address) = @_;
    return if lc $nick eq lc $server->{nick};
    return unless defined Profiler::Rules::min_trust_for($rules, $server->{tag}, $channel);

    my $now = time;
    my $rkey = recent_key($server->{tag}, $channel, $nick);
    return if $recent{$rkey} && $now - $recent{$rkey} < Irssi::settings_get_int('profiler_recheck');

    my ($ident, $host) = split /@/, $address, 2;
    my $job = {
        tag => $server->{tag}, channel => $channel, nick => $nick,
        ident => $ident, host => $host,
    };
    my $queue = queue_for($server->{tag});
    if (!$queue->add($rkey, $job, $now) && $queue->length >= Irssi::settings_get_int('profiler_queue_max')) {
        info("whois queue on $server->{tag} is full, not profiling $nick in $channel");
    }
}

sub tick {
    my $now = time;
    for my $tag (keys %queues) {
        my $job = $queues{$tag}->take($now) or next;
        my $server = Irssi::server_find_tag($job->{tag});
        next unless $server && $server->{connected};
        send_whois($server, $job);
    }
}

sub pending_key {
    my ($tag, $nick) = @_;
    return lc "$tag/$nick";
}

# The redirect keeps the whois replies out of the status window and hands them
# to our own signals below. The VERSION request goes out raw so it does not
# echo into a window either.
sub send_whois {
    my ($server, $job) = @_;
    my $key = pending_key($job->{tag}, $job->{nick});
    if ($pending{$key}) {
        push @{ $pending{$key}{jobs} }, $job;
        return;
    }
    my $entry = $pending{$key} = { jobs => [$job] };

    $server->redirect_event('whois', 1, $job->{nick}, 0, undef, {
        'event 311' => 'redir profiler_whois_user',
        'event 312' => 'redir profiler_whois_server',
        'event 318' => 'redir profiler_whois_end',
        'event 401' => 'redir profiler_whois_end',
        ''          => 'event empty',
    });
    $server->send_raw("WHOIS $job->{nick}");
    $server->send_raw("PRIVMSG $job->{nick} :\001VERSION\001");

    # The entry is checked by identity so a timer left over from an earlier
    # lookup of the same nick cannot cut a newer one short.
    Irssi::timeout_add_once(1000 * Irssi::settings_get_int('profiler_version_timeout'), sub {
        return unless $pending{$key} && $pending{$key} == $entry;
        $entry->{version} //= $Profiler::Version::NO_REPLY;
        finish_if_ready($key);
    }, undef);
}

# :server 311 me nick ident host * :realname
sub on_whois_user {
    my ($server, $data) = @_;
    my ($nick, $ident, $host, $realname) = $data =~ /^\S+ (\S+) (\S+) (\S+) \S+ :(.*)$/ or return;
    my $entry = $pending{ pending_key($server->{tag}, $nick) } or return;
    @$entry{qw(ident host realname)} = ($ident, $host, $realname);
}

# :server 312 me nick irc.server.name :server info
sub on_whois_server {
    my ($server, $data) = @_;
    my ($nick, $ircserver) = $data =~ /^\S+ (\S+) (\S+)/ or return;
    my $entry = $pending{ pending_key($server->{tag}, $nick) } or return;
    $entry->{server} = $ircserver;
}

# Both "end of whois" and "no such nick" land here. If they already left we
# still profile them from what the join told us.
sub on_whois_end {
    my ($server, $data) = @_;
    my ($nick) = $data =~ /^\S+ (\S+)/ or return;
    my $key = pending_key($server->{tag}, $nick);
    my $entry = $pending{$key} or return;
    $entry->{whois_done} = 1;
    finish_if_ready($key);
}

# We listen on the generic "ctcp reply" signal. Claiming "ctcp reply version"
# would mark the reply as handled, and we don't want to risk that hiding
# VERSION replies you asked for yourself.
sub on_ctcp_reply {
    my ($server, $args, $nick) = @_;
    my ($version) = $args =~ /^VERSION\b\s*(.*)$/is or return;
    my $key = pending_key($server->{tag}, $nick);
    my $entry = $pending{$key} or return;
    return if defined $entry->{version};
    $entry->{version} = Profiler::Version::clean($version);
    finish_if_ready($key);
}

sub finish_if_ready {
    my ($key) = @_;
    my $entry = $pending{$key} or return;
    return unless $entry->{whois_done} && defined $entry->{version};
    delete $pending{$key};

    my %found = map { defined $entry->{$_} ? ($_ => $entry->{$_}) : () } qw(ident host realname server version);
    look_up_host({ %$_, %found }) for @{ $entry->{jobs} };
}

sub look_up_host {
    my ($job) = @_;
    my $now = time;
    my $info = eval {
        $store->fresh_hostinfo($job->{tag}, $job->{host}, $now, Irssi::settings_get_int('profiler_hostinfo_max_age'));
    };
    return info($@) if $@;
    return judge($job, $info) if $info;

    my $keywords = proxy_keywords();
    my $timeout = Irssi::settings_get_int('profiler_lookup_timeout');
    my ($reader, $writer);
    if (!pipe $reader, $writer) {
        info("cannot create pipe for host lookup: $!");
        return judge($job, {});
    }
    my $pid = fork;
    if (!defined $pid) {
        info("cannot fork for host lookup: $!");
        close $reader;
        close $writer;
        return judge($job, {});
    }

    if ($pid == 0) {
        close $reader;
        my $res = Profiler::Whois::lookup($job->{host}, $keywords, $timeout);
        print $writer encode_json($res);
        close $writer;
        POSIX::_exit(0);
    }

    close $writer;
    Irssi::pidwait_add($pid);
    my $tag;
    $tag = Irssi::input_add(fileno($reader), INPUT_READ, sub {
        Irssi::input_remove($tag);
        my $json = do { local $/; <$reader> };
        close $reader;

        my $res = eval { decode_json($json // '') } || { error => 'host lookup died without an answer' };
        info("host lookup for $job->{host}: $res->{error}") if $res->{error};
        eval { $store->set_hostinfo($job->{tag}, $job->{host}, $res, time) };
        info($@) if $@;
        judge($job, $res);
    }, undef);
}

sub judge {
    my ($job, $hostinfo) = @_;
    my $obs = { %$job, ip => $hostinfo->{ip}, proxy => $hostinfo->{proxy} };
    my $now = time;
    $recent{ recent_key($job->{tag}, $job->{channel}, $job->{nick}) } = $now;

    my ($trust, $parts, $profile);
    eval {
        $profile = $store->profile($job->{tag}, $job->{nick});
        ($trust, $parts) = Profiler::Score::trust($profile, $obs);
        $store->record($job->{tag}, $obs, $now);
        $store->save($job->{tag});
        1;
    } or return info($@);

    my $server = Irssi::server_find_tag($job->{tag});
    my $say = sub {
        my ($text) = @_;
        return info($text) unless $server;
        $server->print($job->{channel}, "profiler: $text", MSGLEVEL_CLIENTCRAP);
    };

    my $who = "$job->{nick} ($job->{ident}\@$job->{host}, client: $job->{version})";
    my $seen = $profile ? "seen $profile->{sightings} time(s) before" : 'never seen before';
    my $min = Profiler::Rules::min_trust_for($rules, $job->{tag}, $job->{channel}) // 0;
    my $score = sprintf('%.2f', $trust);

    if ($trust < $min) {
        my $why = join ' ', map { sprintf('%s=%.2f', $_, $parts->{$_}) } sort keys %$parts;
        $say->("WARNING $who has trust $score, under $min; $seen" . ($why ? " [$why]" : ''));
    }
    elsif (Irssi::settings_get_bool('profiler_verbose')) {
        $say->("$who has trust $score; $seen");
    }

    if ($hostinfo->{proxy}) {
        my $owner = $hostinfo->{org} // $hostinfo->{netname} // 'unknown owner';
        $say->("WARNING $who is on a likely VPN, proxy or hosting address "
            . "($hostinfo->{ip}, $owner, matched '$hostinfo->{proxy}')");
    }
}

sub cmd_profiler {
    my ($data, $server) = @_;
    my ($subcmd, $arg) = ($data // '') =~ /^\s*(\S*)\s*(\S*)/;
    $subcmd = lc $subcmd;

    if ($subcmd eq 'reload') {
        load_rules();
    }
    elsif ($subcmd eq '' || $subcmd eq 'list') {
        info("watching:");
        info("  (nothing)") unless @{ $rules->{watches} };
        info("  $_->{text}") for @{ $rules->{watches} };
        for my $tag (sort keys %queues) {
            my $q = $queues{$tag};
            info("$tag: " . $q->length . " whois queued" . ($q->paused(time) ? ', paused after a burst of joins' : ''));
        }
    }
    elsif ($subcmd eq 'show' && length $arg) {
        return info("/profiler show needs an active server") unless $server;
        my $p = eval { $store->profile($server->{tag}, $arg) };
        return info($@) if $@;
        return info("no profile for $arg on $server->{tag}") unless $p;
        info("$p->{nick} on $server->{tag}: $p->{sightings} sighting(s), first "
            . localtime($p->{first_seen}) . ", last " . localtime($p->{last_seen}));
        for my $table (qw(hosts ips idents realnames servers channels versions)) {
            my $counts = $p->{$table} or next;
            info("  $table: " . join(', ', map { "$_ x$counts->{$_}" }
                sort { $counts->{$b} <=> $counts->{$a} } keys %$counts));
        }
    }
    else {
        info("usage: /profiler [list|reload|show <nick>]");
    }
}

Irssi::settings_add_str('profiler', 'profiler_rules_file', '');
Irssi::settings_add_str('profiler', 'profiler_data_dir', '');
Irssi::settings_add_int('profiler', 'profiler_whois_interval', 3);
Irssi::settings_add_int('profiler', 'profiler_burst_joins', 8);
Irssi::settings_add_int('profiler', 'profiler_burst_window', 10);
Irssi::settings_add_int('profiler', 'profiler_burst_pause', 60);
Irssi::settings_add_int('profiler', 'profiler_queue_max', 100);
Irssi::settings_add_int('profiler', 'profiler_recheck', 600);
Irssi::settings_add_int('profiler', 'profiler_hostinfo_max_age', 7 * 24 * 3600);
Irssi::settings_add_int('profiler', 'profiler_lookup_timeout', 20);
Irssi::settings_add_int('profiler', 'profiler_version_timeout', 10);
Irssi::settings_add_bool('profiler', 'profiler_verbose', 0);

Irssi::signal_add('message join', \&on_join);
Irssi::signal_add('redir profiler_whois_user', \&on_whois_user);
Irssi::signal_add('redir profiler_whois_server', \&on_whois_server);
Irssi::signal_add('redir profiler_whois_end', \&on_whois_end);
Irssi::signal_add('ctcp reply', \&on_ctcp_reply);
Irssi::command_bind('profiler', \&cmd_profiler);
Irssi::timeout_add(500, \&tick, undef);

open_store();
load_rules();
