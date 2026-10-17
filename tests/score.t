use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use Test::More;

use Profiler::Score;
use Profiler::Version;

my $NOW = 1_000_000_000;
my $DAY = 86400;

my %bob = (
    host     => 'host.example.net',
    ip       => '10.10.10.2',
    ident    => '~bob',
    realname => 'Bob Smith',
    server   => 'irc.example.net',
    version  => 'irssi v1.4.5',
    channel  => '#chan',
);

my %troll = (
    host     => 'troll.example.org',
    ip       => '192.0.2.66',
    ident    => 'lol',
    realname => 'u mad',
    server   => 'irc.example.net',
    version  => 'mIRC v7.71',
    channel  => '#chan',
);

# A profile with $n sightings matching %overrides on top of bob, $age_days old.
sub profile_of {
    my ($n, %opt) = @_;
    my $age = ($opt{age_days} // 0) * $DAY;
    my %fields = (%bob, %{ $opt{with} // {} });
    return { sightings => [ map { { %fields, time => $NOW - $age } } 1 .. $n ] };
}

sub judge { Profiler::Score::judge($_[0], $_[1], $NOW) }

subtest 'familiarity' => sub {
    is(Profiler::Score::familiarity(0), 0, 'never seen');
    is(Profiler::Score::familiarity(3), 0.5, 'seen K times is halfway');
};

subtest 'no profile' => sub {
    my $r = judge(undef, \%bob);
    is($r->{verdict}, 'unknown', 'unknown');
    is($r->{trust}, 0, 'zero trust');
};

subtest 'the usual person is consistent' => sub {
    my $r = judge(profile_of(10), \%bob);
    is($r->{verdict}, 'consistent', 'verdict');
    ok($r->{match} > 0.5, "match $r->{match}");
    ok($r->{trust} > 0.5 && $r->{trust} < 1, "trust $r->{trust}");
};

subtest 'channel names match whatever their case' => sub {
    # The store keeps channels lowercased, and joins arrive as typed.
    my $r = judge(profile_of(10), { %bob, channel => '#CHAN' });
    is($r->{parts}{channel}, judge(profile_of(10), \%bob)->{parts}{channel}, '#CHAN is #chan');
};

subtest 'more history means more trust' => sub {
    my $t3 = judge(profile_of(3), \%bob)->{trust};
    my $t30 = judge(profile_of(30), \%bob)->{trust};
    ok($t3 < $t30, "$t3 < $t30");
};

subtest 'a perfect match is a full match however thin the history' => sub {
    # How much history there is goes into confidence. Counting it in the
    # match too would square it in the trust.
    for my $n (3, 30) {
        my $r = judge(profile_of($n), \%bob);
        ok(abs($r->{match} - 1) < 1e-9, "$n sightings: match $r->{match}");
        ok(abs($r->{trust} - $r->{confidence}) < 1e-9, "$n sightings: trust $r->{trust} is the confidence");
    }
};

subtest 'an attribute with little history does not drag down a well supported match' => sub {
    # Imported sightings have no realname, server or version, so those come
    # from a few live sightings while ident and channel have hundreds.
    my %logged = map { $_ => $bob{$_} } qw(host ip ident channel);
    my $history = { sightings => [
        (map { { %logged, time => $NOW - $_ * $DAY } } 1 .. 200),
        (map { { %bob, time => $NOW - $_ * $DAY } } 1 .. 2),
    ] };
    my $r = judge($history, { %bob, host => '192.0.2.9', ip => '192.0.2.9', proxy => 'acme hosting' });
    ok(abs($r->{match} - 1) < 1e-9, "match $r->{match}");
};

subtest 'a contradicted ident, realname or client is never consistent' => sub {
    for my $attr (qw(ident realname version)) {
        my $r = judge(profile_of(20), { %bob, $attr => 'something else' });
        ok($r->{match} > 0, "$attr: everything else matches, match $r->{match}");
        is($r->{verdict}, 'mixed', "$attr: but it's only mixed");
    }
};

subtest 'whether the nick has used this host before' => sub {
    ok(judge(profile_of(3), \%bob)->{host_seen}, 'the usual host');
    ok(!judge(profile_of(3), { %bob, host => 'elsewhere.example.org' })->{host_seen}, 'a new one');
    my $held = profile_of(3);
    push @{ $held->{sightings} }, { %bob, host => 'held.example.org', time => $NOW, quarantined => 1 };
    ok(!judge($held, { %bob, host => 'held.example.org' })->{host_seen}, 'one only seen in quarantine is new');
};

subtest 'another address from the same ISP is a partial match, a new ISP is suspect' => sub {
    # Verizon hands out addresses from all over, so hank is never on the
    # same /24 twice.
    my %hank = (ident => '~debian', realname => '---', version => $Profiler::Version::NO_REPLY, channel => '#chan');
    my @hosts = map { "$_.sub-174-1$_-$_.myvzw.com" } 10 .. 29;
    my $history = { sightings => [ map { { %hank, host => $hosts[$_], time => $NOW - $_ * $DAY } } 0 .. $#hosts ] };

    my $r = judge($history, { %hank, host => '226.sub-203-0-113.myvzw.com' });
    ok($r->{parts}{host} > 0, "a new Verizon address counts for them ($r->{parts}{host})");
    is($r->{verdict}, 'consistent', 'and they are consistent');
    ok(!$r->{new_isp}, 'not a new ISP');

    $r = judge($history, { %hank, host => '1-2-3-4dyn.telia.it' });
    is($r->{verdict}, 'suspect', 'a residential ISP they have never used is suspect');
    is_deeply($r->{new_isp}, { isp => 'telia.it', usual => 'myvzw.com' }, 'and says which');

    push @{ $history->{sightings} }, { %hank, host => '9-9-9-9dyn.telia.it', time => $NOW - 40 * $DAY };
    $r = judge($history, { %hank, host => '1-2-3-4dyn.telia.it' });
    ok(!$r->{new_isp}, 'not once they have used it before');

    my $bouncer = { sightings => [ map { { %hank, host => 'box.example.org', time => $NOW - $_ * $DAY } } 1 .. 20 ] };
    ok(!judge($bouncer, { %hank, host => '1-2-3-4dyn.telia.it' })->{new_isp},
        'someone who has only used their own server has no usual ISP to leave');
};

subtest 'bare addresses are compared by who they belong to' => sub {
    # atsu1 comes from all over one provider's IPv6 space.
    my %atsu = (ident => '~atsu1', channel => '#chan');
    my @addrs = map { sprintf '2a02:21b4:9a%02x:c020::%x', $_, $_ } 1 .. 10;
    my $history = { sightings => [ map {
        { %atsu, host => $addrs[$_], ip => $addrs[$_], provider => 'example telecom', time => $NOW - $_ * $DAY }
    } 0 .. $#addrs ] };

    my $r = judge($history, { %atsu, host => '2a02:21b4:9bff:1::1', ip => '2a02:21b4:9bff:1::1', provider => 'example telecom' });
    ok($r->{parts}{host} > 0, "another address from the same provider counts for them ($r->{parts}{host})");
    ok(!$r->{new_isp}, 'not a new provider');

    $r = judge($history, { %atsu, host => '198.51.100.9', ip => '198.51.100.9', provider => 'other net' });
    is($r->{verdict}, 'suspect', 'a provider they have never used is suspect');
    is_deeply($r->{new_isp}, { isp => 'other net', usual => 'example telecom' }, 'and says which');

    ok(!judge($history, { %atsu, host => '198.51.100.9', ip => '198.51.100.9', provider => 'other net', proxy => 'vpn' })
        ->{new_isp}, 'not from a VPN, which is no residential ISP');

    my %bouncer = (%atsu, host => 'box.example.org', provider => 'hosting co');
    my $own = { sightings => [ map { { %bouncer, time => $NOW - $_ * $DAY } } 1 .. 10 ] };
    ok(!judge($own, { %atsu, host => '198.51.100.9', ip => '198.51.100.9', provider => 'other net' })->{new_isp},
        "their own server's hosting company is not their usual provider");

    my $imported = { sightings => [ map { { %atsu, host => $addrs[$_], ip => $addrs[$_], time => $NOW - $_ * $DAY } } 0 .. 9 ] };
    ok(!judge($imported, { %atsu, host => '198.51.100.9', ip => '198.51.100.9', provider => 'other net' })->{new_isp},
        'history without providers can say nothing about them');
};

subtest 'a jupe troll on an established nick is suspect' => sub {
    my $r = judge(profile_of(20), \%troll);
    is($r->{verdict}, 'suspect', 'verdict');
    ok($r->{trust} < -0.3, "trust $r->{trust} is clearly negative");
    ok($r->{parts}{ident} < 0, 'ident contradicts');
    ok($r->{parts}{channel} > 0, 'channel still matches');
};

subtest 'a stranger on a barely known nick is unknown, not suspect' => sub {
    my $r = judge(profile_of(1), \%troll);
    is($r->{verdict}, 'unknown', 'not enough history to call it');
};

subtest 'a copycat matching everything but the host is not consistent' => sub {
    my %copycat = (%bob, host => 'troll.example.org', ip => '192.0.2.66');
    my $copy = judge(profile_of(20), \%copycat);
    my $real = judge(profile_of(20), \%bob);
    isnt($copy->{verdict}, 'consistent', "verdict $copy->{verdict}");
    ok($copy->{trust} < $real->{trust} / 2, 'far below the real thing');
};

subtest 'a new host is called out separately when nothing else contradicts' => sub {
    # Logs give only host, ident and channel, which is where this shows up.
    my %logged = map { $_ => $bob{$_} } qw(host ip ident channel);
    my $history = sub {
        my (@hosts) = @_;
        my $i = 0;
        return { sightings => [ map { { %logged, host => $_, ip => '172.16.' . $i++ . '.1', time => $NOW } } @hosts ] };
    };
    my %elsewhere = (%logged, host => 'elsewhere.example.org', ip => '192.0.2.9');

    my $r = judge($history->(('host.example.net') x 20), \%elsewhere);
    is($r->{verdict}, 'new host', 'everything but the host matches');
    ok(!$r->{host_changes_often}, 'from someone who sticks to one host');

    is(judge($history->(('host.example.net') x 20), { %elsewhere, ident => 'lol' })->{verdict},
        'suspect', 'a new ident as well is suspect');
    is(judge($history->(('host.example.net') x 20), { %elsewhere, channel => '#elsewhere' })->{verdict},
        'new host', 'an unusual channel says nothing about who it is');

    my $hopper = $history->((('host.example.net') x 15), map { "hop$_.example.net" } 1 .. 5);
    $r = judge($hopper, \%elsewhere);
    is($r->{verdict}, 'new host', 'a host hopper on yet another host');
    ok($r->{host_changes_often}, 'is noted as changing hosts often');
};

subtest 'only host, ident, realname or client can make a suspect' => sub {
    # Live, from a known nick on a proxy (so the host is skipped) whose ident
    # we didn't get to compare, in a channel they'd never been seen in.
    my %logged = map { $_ => $bob{$_} } qw(host ip ident channel);
    my $history = { sightings => [ map { { %logged, time => $NOW } } 1 .. 20 ] };
    my %proxied = (%logged, host => '192.0.2.9', ip => '192.0.2.9', proxy => 'acme hosting');
    delete $proxied{ident};

    my $r = judge($history, { %proxied, channel => '#elsewhere' });
    ok($r->{match} < 0, "only the channel disagrees, match $r->{match}");
    is($r->{verdict}, 'mixed', 'which is not enough to call it suspect');

    is(judge($history, { %proxied, channel => '#elsewhere', ident => 'lol' })->{verdict},
        'suspect', 'a contradicting ident still is');
};

subtest 'an established custom or irccloud host is solid' => sub {
    my $history = sub {
        my (%who) = @_;
        return { sightings => [ map { { %who, time => $NOW - $_ * 86400 } } 1 .. 6 ] };
    };

    # On a hosting company's address, in a channel they've never been seen in.
    my %gus = (host => 'gus.example.org', ident => '~gus', channel => '#other');
    my $r = judge($history->(%gus), { %gus, channel => '#chan', proxy => 'acme hosting' });
    ok(defined $r->{parts}{host}, 'the host counts even on a proxy');
    is($r->{verdict}, 'consistent', "and outweighs the new channel ($r->{verdict}, match $r->{match})");

    my %craig = (host => 'id-100001.helmsley.irccloud.com', ident => 'sid100001', channel => '#chan');
    $r = judge($history->(%craig), { %craig, host => 'id-100001.charlton.irccloud.com' });
    is($r->{verdict}, 'consistent', 'irccloud through another server is the same account');
    $r = judge($history->(%craig), { %craig, host => 'tinside.irccloud.com' });
    is($r->{verdict}, 'consistent', 'and so is one with the account only in the ident');
    $r = judge($history->(%craig), { %craig, host => 'tinside.irccloud.com', ident => 'uid100001' });
    ok($r->{parts}{ident} > 0, 'a lapsed subscription (sid to uid) is the same ident');
    is($r->{verdict}, 'consistent', 'and the same account');
    ok(judge($history->(%craig), { %craig, ident => 'uid100002' })->{parts}{ident} < 0, 'another account is not');

    # Everyone on an IRCCloud server shares its host and addresses.
    my %shared = (host => 'hampstead.irccloud.com', ip => '192.0.2.10', ident => 'uid100003');
    my $host = sub { Profiler::Score::similarity('host', $_[0], \%shared) };
    is($host->({ %shared, ident => 'uid100002' }), 0, 'two accounts on one IRCCloud server are two people');
    is($host->({ %shared, host => 'id-100002.ilkley.irccloud.com' }), 0, 'and so are two id- hosts');
    is($host->({ %shared, host => 'id-100003.ilkley.irccloud.com' }), 1, 'one account on two servers is one');
    is($host->({ %shared, ident => '~bob' }), 0, 'a server host with no account says nothing');

    $r = judge($history->(%gus), { %gus, ident => 'lol' });
    isnt($r->{verdict}, 'consistent', 'someone else on a shared box is not');

    $r = judge($history->(%gus), { %gus, host => 'elsewhere.example.org', proxy => 'acme hosting' });
    is($r->{verdict}, 'new host', 'a different custom host is a new host');

    my %isp = (host => 'cpe-198-51-100-202.san.res.example.com', ident => '~bob', channel => '#other');
    my $plain = judge($history->(%isp), { %isp, channel => '#chan' });
    my $solid = judge($history->(%gus), { %gus, channel => '#chan' });
    ok($plain->{match} < $solid->{match}, 'an ISP host match counts for less');

    # Their usual ISP host lately, and another host once, two years ago. Back
    # on that one, it's no worse for being a custom name than an ISP's.
    my $back_on = sub {
        my ($host) = @_;
        my $h = $history->(%isp);
        push @{ $h->{sightings} }, { %isp, host => $host, time => $NOW - 730 * 86400 };
        return judge($h, { %isp, host => $host })->{match};
    };
    my $old_solid = $back_on->('box.example.org');
    my $old_isp = $back_on->('cpe-198-51-100-7.elsewhere.example.net');
    # They can come out equal, and hash order changes the rounding.
    ok($old_solid >= $old_isp - 1e-9, "a solid host seen long ago doesn't drag the match down ($old_solid >= $old_isp)");
};

subtest 'contradicting an attribute that always varies costs little' => sub {
    my $varied = { sightings => [ map { { %bob, ident => "id$_", time => $NOW } } 1 .. 10 ] };
    my $stable = profile_of(10);
    my %obs = (%bob, ident => 'brandnew');
    my $loose = judge($varied, \%obs)->{parts}{ident};
    my $strict = judge($stable, \%obs)->{parts}{ident};
    ok($loose < 0 && $strict < 0, 'both negative');
    ok($loose > $strict / 5, "varied ident ($loose) costs far less than stable ($strict)");
};

subtest 'nearby address gets partial credit' => sub {
    my %obs = (%bob, host => '10.10.10.3', ip => '10.10.10.3');
    my $near = judge(profile_of(5), \%obs)->{parts}{host};
    my $exact = judge(profile_of(5), \%bob)->{parts}{host};
    ok($near > 0 && $near < $exact, "near $near between 0 and exact $exact");

    %obs = (%bob, host => '10.10.11.3', ip => '10.10.11.3');
    ok(judge(profile_of(5), \%obs)->{parts}{host} < 0, 'another /24 contradicts');
};

subtest 'host is not judged on a proxy address with no name of its own' => sub {
    my $r = judge(profile_of(10), { %troll, host => '192.0.2.66', proxy => 'vpn' });
    ok(!exists $r->{parts}{host}, 'no host part');
};

subtest 'an upgraded client gets partial credit' => sub {
    my $upgraded = judge(profile_of(5), { %bob, version => 'irssi v1.4.6' })->{parts}{version};
    my $exact = judge(profile_of(5), \%bob)->{parts}{version};
    ok($upgraded > 0 && $upgraded < $exact, "upgraded $upgraded, exact $exact");
};

subtest 'never answering VERSION is consistent too' => sub {
    my $silent = profile_of(5, with => { version => $Profiler::Version::NO_REPLY });
    ok(judge($silent, { %bob, version => $Profiler::Version::NO_REPLY })->{parts}{version} > 0, 'matches');
};

subtest 'attributes missing on either side are skipped' => sub {
    my $from_logs = { sightings => [ map { { host => $bob{host}, ident => $bob{ident}, channel => '#chan', time => $NOW } } 1 .. 10 ] };
    my $r = judge($from_logs, \%bob);
    ok(!exists $r->{parts}{realname}, 'no realname history, no realname part');
    is($r->{verdict}, 'consistent', 'judged on what we have');

    $r = judge(profile_of(10), { host => $bob{host}, ident => $bob{ident}, channel => '#chan' });
    ok(!exists $r->{parts}{version}, 'nothing observed, no part');
    is($r->{verdict}, 'consistent', 'still consistent');
};

subtest 'old history fades' => sub {
    my $fresh = judge(profile_of(10), \%bob)->{confidence};
    my $stale = judge(profile_of(10, age_days => 180), \%bob)->{confidence};
    ok($stale < $fresh, "stale $stale < fresh $fresh");
    is(judge(profile_of(20, age_days => 730), \%troll)->{verdict}, 'unknown',
        'two-year-old history is too faint to call anyone an impostor');
};

subtest 'quarantined sightings do not count' => sub {
    my $p = profile_of(20);
    push @{ $p->{sightings} }, map { { %troll, time => $NOW, quarantined => 1 } } 1 .. 10;
    is(judge($p, \%troll)->{verdict}, 'suspect', 'troll does not train the profile');
};

subtest 'hosts in the same dynamic ISP pool are near matches' => sub {
    my $p = profile_of(5, with => { host => 'cpe-198-51-100-202.san.res.rr.com', ip => undef });
    my %obs = (%bob, ip => undef);
    my $pool = judge($p, { %obs, host => 'cpe-203-0-113-17.san.res.rr.com' })->{parts}{host};
    my $exact = judge($p, { %obs, host => 'cpe-198-51-100-202.san.res.rr.com' })->{parts}{host};
    ok($pool > 0 && $pool < $exact, "pool $pool between 0 and exact $exact");
    my $isp = judge($p, { %obs, host => 'cpe-203-0-113-17.nyc.res.rr.com' })->{parts}{host};
    ok($isp > 0 && $isp < $exact, "another pool at the same ISP is near too ($isp)");
    ok(judge($p, { %obs, host => 'cpe-203-0-113-17.nyc.res.example.net' })->{parts}{host} < 0, 'another ISP contradicts');

    ok(Profiler::Score::same_pool('d203-0-113-220.bchsia.telus.net', 'd203-0-113-9.bchsia.telus.net'), 'telus');
    ok(!Profiler::Score::same_pool('bob.users.example.net', 'troll.users.example.net'), 'named vhosts are not a pool');
    ok(!Profiler::Score::same_pool('a1.example', 'b2.example'), 'needs more than a bare domain');
    ok(!Profiler::Score::same_pool('cpe-1.example.net', 'cpe-1.example.net.evil'), 'rest must match exactly');
};

subtest 'promotable: a move, or a second home that matches everything but the host' => sub {
    my $day = sub { $NOW + $_[0] * $DAY };
    my %new = (%bob, host => 'new.isp.example', ip => '198.51.100.7');
    my $moved = sub {
        my (@quarantined_days) = @_;
        return { sightings => [
            (map { { %bob, time => $day->($_) } } 0 .. 19),
            (map { { %new, time => $day->($_), quarantined => 1 } } @quarantined_days),
        ] };
    };
    my $n = sub { my @p = Profiler::Score::promotable($_[0], 5, 7); scalar @p };

    is($n->($moved->(20, 22, 24, 26, 28)), 5, 'five over eight days get promoted');
    is($n->($moved->(20, 21, 22, 23, 24)), 0, 'not if it spans under seven days');
    is($n->($moved->(20, 23, 26, 29)), 0, 'not with only four');

    # A second home: the old host keeps turning up, and the new one matches
    # everything else about the usual person.
    my $back = sub {
        my (%change) = @_;
        my $p = $moved->(20, 22, 24, 26, 28);
        $_->{quarantined} and @$_{ keys %change } = values %change for @{ $p->{sightings} };
        push @{ $p->{sightings} }, { %bob, time => $day->(25) };
        return $p;
    };
    is($n->($back->()), 5, 'a second host alongside the old one, matching everything else');
    is($n->($back->(version => 'irssi v1.2.3')), 5, 'same client at another version still matches');
    is($n->($back->(ident => '~troll')), 0, 'not alongside the old habit with another ident');
    is($n->($back->(realname => 'lol')), 0, 'not alongside the old habit with another realname');
    is($n->($back->(version => 'mIRC v7.77')), 0, 'not alongside the old habit with another client');

    my $moved_and_changed = $moved->(20, 22, 24, 26, 28);
    $_->{quarantined} and $_->{ident} = 'newbox' for @{ $moved_and_changed->{sightings} };
    is($n->($moved_and_changed), 5, 'a full move may change the ident too');

    my $scattered = $moved->(20, 22, 24, 26, 28);
    my $i = 0;
    $_->{quarantined} and $_->{host} = 'troll' . $i++ . '.example' and $_->{ip} = "203.0.$i.1"
        for @{ $scattered->{sightings} };
    is($n->($scattered), 0, 'not if the quarantined sightings disagree with each other');

    my $reviewed = $moved->(20, 22, 24, 26, 28);
    $_->{quarantined} and $_->{reviewed} = 1 for @{ $reviewed->{sightings} };
    is($n->($reviewed), 0, 'rejected sightings stay rejected');
};

subtest 'same_subnet' => sub {
    ok(Profiler::Score::same_subnet('10.10.10.2', '10.10.10.3'), 'same /24');
    ok(!Profiler::Score::same_subnet('10.10.10.2', '10.10.11.2'), 'different /24');
    ok(Profiler::Score::same_subnet('2001:db8:1:2::1', '2001:db8:1:2:ffff::9'), 'same /64');
    ok(!Profiler::Score::same_subnet('2001:db8:1:2::1', '2001:db8:1:3::1'), 'different /64');
    ok(!Profiler::Score::same_subnet('10.10.10.2', '2001:db8::1'), 'mixed families');
    ok(!Profiler::Score::same_subnet('not.an.ip', '10.10.10.2'), 'not an address');
};

done_testing;
