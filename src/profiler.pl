use strict;
use warnings;

use Irssi;
use File::Path qw(make_path);
use JSON::PP;
use POSIX ();
use Symbol ();

# irssi keeps one perl for its whole life, and /script unload only throws away
# this script's own package. Our modules would stay loaded, so after an upgrade
# `use` would quietly keep the old code. Forget them so a load reads the
# installed files.
BEGIN {
    for my $file (grep { m{^Profiler/} } keys %INC) {
        (my $package = $file) =~ s{\.pm$}{};
        $package =~ s{/}{::}g;
        Symbol::delete_package($package);
        delete $INC{$file};
    }
}

use lib Irssi::get_irssi_dir() . '/scripts/profiler-lib';
use Profiler::Evasion;
use Profiler::Marks;
use Profiler::Queue;
use Profiler::Report;
use Profiler::Rules;
use Profiler::Score;
use Profiler::Store;
use Profiler::Variants;
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

# Our lines are drawn like a nick that parts or quits, so they stand out from
# the channel without shouting. Going through the theme keeps them in step
# with whatever colours the user has, and keeps % in the text literal. A line
# about someone leads with a one-word summary in its own colour, so it can be
# read at a glance.
my %WORD_COLOUR = (
    WARNING     => '%R',
    EVADER      => '%R',
    UNPROVEN    => '%M',
    SUSPECT     => '%Y',
    MIXED       => '%C',
    CONFIDENT   => '%G',
    'NEW HOST'  => '%w',
    UNKNOWN     => '%w',
    MOVED       => '%w',
);

# "looks like bob" leads with VARIANT, coloured by how well the join fits
# bob's history. It comes after the join's own word, or alone.
my %VARIANT_COLOUR = (
    'VARIANT consistent' => '%G',
    'VARIANT mixed'      => '%C',
);

sub word_format {
    my (@words) = @_;
    (my $name = lc join '_', @words) =~ tr/ /_/;
    return "profiler_$name";
}

# The colours have to be in the format, since % in the text is kept literal,
# so there's a format for every pair of words a line can lead with.
sub coloured { my ($word, $colour) = @_; (my $shown = $word) =~ s/ (consistent|mixed)$//; "$colour$shown%n" }
my %ONE_WORD = (%WORD_COLOUR, %VARIANT_COLOUR);
Irssi::theme_register([
    profiler_line => '{channick profiler: $0}',
    (map { word_format($_) => '{channick profiler:} ' . coloured($_, $ONE_WORD{$_}) . ' {channick $0}' } sort keys %ONE_WORD),
    map {
        my $word = $_;
        map { word_format($word, $_) => '{channick profiler:} ' . coloured($word, $WORD_COLOUR{$word}) . ' '
            . coloured($_, $VARIANT_COLOUR{$_}) . ' {channick $0}' } sort keys %VARIANT_COLOUR
    } sort keys %WORD_COLOUR,
]);

# Prints one of our lines in a channel's window, or in the status window when
# there's no channel or the server has gone. @words, for a line about
# someone, is one of %WORD_COLOUR's, then one of %VARIANT_COLOUR's, or both.
sub say_in {
    my ($tag, $channel, $text, @words) = @_;
    my $format = @words ? word_format(@words) : 'profiler_line';
    my $server = defined $tag ? Irssi::server_find_tag($tag) : undef;
    return $server->printformat($channel, MSGLEVEL_CLIENTCRAP, $format, $text) if $server && defined $channel;
    Irssi::printformat(MSGLEVEL_CLIENTCRAP, $format, $text);
}

sub info {
    my ($text) = @_;
    # Perl errors end in a newline, which irssi would print as an empty line.
    $text =~ s/\s+$//;
    say_in(undef, undef, $text);
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
    enqueue($server, $channel, $nick, $address);
}

# Queues someone in a watched channel for profiling, unless they were profiled
# there recently. $was is the nick they changed from, for a nick change.
sub enqueue {
    my ($server, $channel, $nick, $address, $was) = @_;
    my $now = time;
    my $rkey = recent_key($server->{tag}, $channel, $nick);
    return if $recent{$rkey} && $now - $recent{$rkey} < Irssi::settings_get_int('profiler_recheck');

    my ($ident, $host) = split /@/, $address, 2;
    my $job = {
        tag => $server->{tag}, channel => $channel, nick => $nick,
        ident => $ident, host => $host, was => $was,
    };
    my $queue = queue_for($server->{tag});
    if (!$queue->add($rkey, $job, $now) && $queue->length >= Irssi::settings_get_int('profiler_queue_max')) {
        info("whois queue on $server->{tag} is full, not profiling $nick in $channel");
    }
    # Riding a netsplit back in is the classic way to grab someone's nick, so
    # a suspect verdict says so when the join came in a burst.
    $job->{netsplit} = $queue->paused($now) ? 1 : 0;
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

    # irssi's binding reads an empty failure signal as none. Its docs pass
    # undef, which works but warns.
    $server->redirect_event('whois', 1, $job->{nick}, 0, '', {
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
    # If the end of the whois never comes, say the server went away
    # mid-reply, judge on what we have, as for someone who already left.
    # Otherwise the nick waits for good and later joins queue up behind it.
    Irssi::timeout_add_once(1000 * Irssi::settings_get_int('profiler_whois_timeout'), sub {
        return unless $pending{$key} && $pending{$key} == $entry;
        $entry->{whois_done} = 1;
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
        eval { $store->set_hostinfo($job->{tag}, $job->{host}, $res, time); $store->flush };
        info($@) if $@;
        judge($job, $res);
    }, undef);
}

sub judge {
    my ($job, $hostinfo) = @_;
    my $obs = { %$job, ip => $hostinfo->{ip}, proxy => $hostinfo->{proxy}, provider => Profiler::Whois::provider($hostinfo) };
    my $now = time;
    $recent{ recent_key($job->{tag}, $job->{channel}, $job->{nick}) } = $now;

    local $Profiler::Score::HALF_LIFE = 86400 * Irssi::settings_get_int('profiler_half_life_days');
    my ($r, $count, $promoted, $variant, $evasion, @other_nicks, @marks);
    eval {
        my $profile = $store->profile($job->{tag}, $job->{nick});
        $count = $profile ? $profile->{total} : 0;
        $r = Profiler::Score::judge($profile, $obs, $now);
        my $own = $store->all_marks($job->{tag})->{ lc $job->{nick} } // [];
        @marks = @$own if Profiler::Marks::counts($own, $now);
        $evasion = Profiler::Evasion::best_match($store, $job->{tag}, $job->{nick}, $obs, $now);
        # A nick we barely know, or one that doesn't fit its own history, may
        # be someone familiar on a jupe-driven variant like bob_.
        $variant = Profiler::Variants::best_match($store, $job->{tag}, $job->{nick}, $obs, $now)
            if $r->{verdict} eq 'unknown' || $r->{verdict} eq 'suspect';
        @other_nicks = Profiler::Variants::changes_nicks_often($store, $job->{tag}, $job->{nick}, $job->{was} // ());
        $store->record($job->{tag}, $obs, $now, $r->{verdict});
        $promoted = $store->promote_if_moved($job->{tag}, $job->{nick}, $now,
            Irssi::settings_get_int('profiler_promote_after_sightings'),
            Irssi::settings_get_int('profiler_promote_after_days'));
        $store->flush;
        1;
    } or return info($@);

    my $say = sub { say_in($job->{tag}, $job->{channel}, @_) };

    my ($word, $text) = Profiler::Report::verdict_line($job, $r, {
        count       => $count,
        other_nicks => \@other_nicks,
        min         => Profiler::Rules::min_trust_for($rules, $job->{tag}, $job->{channel}) // 0,
        verbose     => Irssi::settings_get_bool('profiler_verbose'),
        hostinfo    => $hostinfo,
        marks       => \@marks,
    });
    if ($variant) {
        my $variant_word;
        ($word, $variant_word, $text) = Profiler::Report::variant_line($job, $variant, $word, $text);
        $say->($text, grep { defined } $word, $variant_word);
    }
    elsif ($word) {
        $say->($text, $word);
    }

    if ($evasion) {
        my ($evader_word, $evader_text) = Profiler::Report::evader_line($job, $evasion);
        $say->($evader_text, $evader_word);
    }

    if ($promoted) {
        $say->("$job->{nick} looks like they have a new usual host: $promoted quarantined sighting(s) like this one "
            . "now count toward their history. /profiler show $job->{nick} to check", 'MOVED');
    }
}

# Someone was kicked from a watched channel. irssi gives the kicker's
# address, not theirs, so who it hit comes from the nick's latest sighting.
sub on_kick {
    my ($server, $channel, $nick, $kicker, undef, $reason) = @_;
    return unless defined Profiler::Rules::min_trust_for($rules, $server->{tag}, $channel);
    eval {
        my $p = $store->profile($server->{tag}, $nick);
        my $last = $p ? $p->{sightings}[-1] : {};
        $store->record_kick($server->{tag}, { nick => $nick, ident => $last->{ident}, host => $last->{host},
            channel => $channel, by => $kicker, reason => $reason }, time);
        $store->flush;
        1;
    } or info($@);
}

# A ban was set in a watched channel, or turned up when irssi read the ban
# list on joining it. It's matched to whoever is in the channel now.
sub on_ban_new {
    my ($channel, $ban) = @_;
    my $tag = $channel->{server}{tag};
    return unless defined Profiler::Rules::min_trust_for($rules, $tag, $channel->{name});
    my @here = map {
        my ($ident, $host) = split /@/, $_->{host} // '', 2;
        { nick => $_->{nick}, ident => $ident, host => $host }
    } $channel->nicks;
    (my $by = $ban->{setby} // '') =~ s/!.*//;
    eval {
        $store->record_ban($tag, { channel => $channel->{name}, mask => $ban->{ban}, by => $by }, $ban->{time},
            Profiler::Marks::banned($ban->{ban}, [ grep { defined $_->{host} } @here ]));
        $store->flush;
        1;
    } or info($@);
}

# Someone in a watched channel changed nick. That's the same connection, so
# the two nicks are the same person, and the variant search uses the link.
# It's also the easy way to wear someone's nick without ever joining as it,
# so the new nick is profiled in each watched channel like a join.
sub on_nick {
    my ($server, $new, $old, $address) = @_;
    return if lc $new eq lc $server->{nick};
    my @watched = grep {
        defined Profiler::Rules::min_trust_for($rules, $server->{tag}, $_->{name})
            && ($_->nick_find($new) || $_->nick_find($old))
    } $server->channels;
    return unless @watched;
    eval { $store->link_nicks($server->{tag}, $old, $new, time); $store->flush; 1 } or info($@);
    enqueue($server, $_->{name}, $new, $address, $old) for @watched;
}

# irssi calls this when the script is unloaded, which includes quitting.
# Everything is committed as it happens, so this just closes the databases.
sub UNLOAD {
    eval { $store->close; 1 } or info($@);
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
        info(scalar(keys %pending) . " lookup(s) waiting on whois or VERSION replies");
    }
    elsif ($subcmd eq 'show' && length $arg) {
        return info("/profiler show needs an active server") unless $server;
        my ($p, @marks) = eval { ($store->profile($server->{tag}, $arg), $store->marks($server->{tag}, $arg)) };
        return info($@) if $@;
        info("$arg on $server->{tag}: " . Profiler::Marks::summary(\@marks)
            . '; ' . join(', ', map { $_->{ident} ? "$_->{ident}\@$_->{host}" : '(address unknown)' } @marks)) if @marks;
        return info("no profile for $arg on $server->{tag}") unless $p;

        my @history = Profiler::Score::history($p);
        my $held = @{ $p->{sightings} } - @history;
        info("$p->{nick} on $server->{tag}: $p->{total} sighting(s), first "
            . localtime($p->{first_seen}) . ", last " . localtime($p->{last_seen})
            . "; of the latest " . @{ $p->{sightings} } . ", " . @history . " counted"
            . ($held ? " and $held quarantined" : ''));
        for my $field (qw(host ip ident realname server version channel)) {
            my %counts;
            $counts{ $_->{$field} }++ for grep { defined $_->{$field} } @history;
            next unless %counts;
            info("  $field: " . join(', ', map { "$_ x$counts{$_}" }
                sort { $counts{$b} <=> $counts{$a} } keys %counts));
        }
    }
    elsif ($subcmd eq 'suspects') {
        return info("/profiler suspects needs an active server") unless $server;
        my @found = eval { $store->suspects($server->{tag}) };
        return info($@) if $@;
        info("no suspect sightings waiting on $server->{tag}") unless @found;
        for my $f (@found) {
            my $s = $f->{sighting};
            info(sprintf('%s  %s in %s as %s@%s, client: %s', scalar localtime($s->{time}), $f->{nick},
                $s->{channel} // '?', $s->{ident} // '?', $s->{host} // '?', $s->{version} // '?'));
        }
    }
    elsif (($subcmd eq 'accept' || $subcmd eq 'reject') && length $arg) {
        return info("/profiler $subcmd needs an active server") unless $server;
        my $n = eval {
            my $n = $subcmd eq 'accept' ? $store->accept($server->{tag}, $arg) : $store->reject($server->{tag}, $arg);
            $store->flush;
            $n;
        };
        return info($@) if $@;
        info($subcmd eq 'accept'
            ? "$n suspect sighting(s) of $arg now count toward their history"
            : "$n suspect sighting(s) of $arg stay quarantined");
    }
    else {
        info("usage: /profiler [list|reload|show <nick>|suspects|accept <nick>|reject <nick>]");
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
Irssi::settings_add_int('profiler', 'profiler_whois_timeout', 60);
Irssi::settings_add_int('profiler', 'profiler_half_life_days', 90);
Irssi::settings_add_int('profiler', 'profiler_promote_after_sightings', $Profiler::Score::PROMOTE_AFTER_SIGHTINGS);
Irssi::settings_add_int('profiler', 'profiler_promote_after_days', $Profiler::Score::PROMOTE_AFTER_DAYS);
Irssi::settings_add_bool('profiler', 'profiler_verbose', 0);

Irssi::signal_add('message join', \&on_join);
Irssi::signal_add('message nick', \&on_nick);
Irssi::signal_add('message kick', \&on_kick);
Irssi::signal_add('ban new', \&on_ban_new);
Irssi::signal_add('redir profiler_whois_user', \&on_whois_user);
Irssi::signal_add('redir profiler_whois_server', \&on_whois_server);
Irssi::signal_add('redir profiler_whois_end', \&on_whois_end);
Irssi::signal_add('ctcp reply', \&on_ctcp_reply);
Irssi::command_bind('profiler', \&cmd_profiler);
Irssi::timeout_add(500, \&tick, undef);

open_store();
load_rules();
