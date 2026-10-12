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

subtest 'more history means more trust' => sub {
    my $t3 = judge(profile_of(3), \%bob)->{trust};
    my $t30 = judge(profile_of(30), \%bob)->{trust};
    ok($t3 < $t30, "$t3 < $t30");
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

subtest 'host is not judged on a proxy address' => sub {
    my $r = judge(profile_of(10), { %troll, proxy => 'vpn' });
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

subtest 'same_subnet' => sub {
    ok(Profiler::Score::same_subnet('10.10.10.2', '10.10.10.3'), 'same /24');
    ok(!Profiler::Score::same_subnet('10.10.10.2', '10.10.11.2'), 'different /24');
    ok(Profiler::Score::same_subnet('2001:db8:1:2::1', '2001:db8:1:2:ffff::9'), 'same /64');
    ok(!Profiler::Score::same_subnet('2001:db8:1:2::1', '2001:db8:1:3::1'), 'different /64');
    ok(!Profiler::Score::same_subnet('10.10.10.2', '2001:db8::1'), 'mixed families');
    ok(!Profiler::Score::same_subnet('not.an.ip', '10.10.10.2'), 'not an address');
};

done_testing;
