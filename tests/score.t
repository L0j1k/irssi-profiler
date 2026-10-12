use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use Test::More;

use Profiler::Score;

sub near { my ($got, $want, $name) = @_; ok(abs($got - $want) < 1e-9, $name) or diag("got $got, want $want") }

# A profile where every attribute has been seen $n times with the same value.
sub steady_profile {
    my ($n) = @_;
    return {
        hosts     => { 'host.example.net' => $n },
        ips       => { '10.10.10.2' => $n },
        idents    => { '~bob' => $n },
        realnames => { 'Bob Smith' => $n },
        servers   => { 'irc.example.net' => $n },
        channels  => { '#chan' => $n },
        versions  => { 'irssi v1.4.5' => $n },
    };
}

my %same = (
    host     => 'host.example.net',
    ip       => '10.10.10.2',
    ident    => '~bob',
    realname => 'Bob Smith',
    server   => 'irc.example.net',
    channel  => '#chan',
    version  => 'irssi v1.4.5',
);

subtest 'familiarity' => sub {
    near(Profiler::Score::familiarity(0), 0, 'never seen');
    near(Profiler::Score::familiarity(3), 0.5, 'seen K times is halfway');
    ok(Profiler::Score::familiarity(100) < 1, 'never reaches 1');
};

subtest 'unknown user has zero trust' => sub {
    my ($trust) = Profiler::Score::trust(undef, \%same);
    is($trust, 0, 'no profile');
};

subtest 'trust grows with repeat sightings and approaches 1' => sub {
    my ($t1) = Profiler::Score::trust(steady_profile(1), \%same);
    my ($t3) = Profiler::Score::trust(steady_profile(3), \%same);
    my ($t50) = Profiler::Score::trust(steady_profile(50), \%same);
    near($t3, 0.5, 'every attribute halfway gives 0.5');
    ok($t1 < $t3 && $t3 < $t50, 'monotonic');
    ok($t50 > 0.9 && $t50 < 1, 'close to but under 1');
};

subtest 'a stranger using a known nick scores low' => sub {
    my %stranger = (
        host => 'other.isp.example', ip => '192.0.2.9', ident => 'x',
        realname => 'X', server => 'irc.other.net', channel => '#chan',
    );
    my ($trust, $parts) = Profiler::Score::trust(steady_profile(10), \%stranger);
    is($parts->{host}, 0, 'host part zero');
    near($trust, $Profiler::Score::WEIGHTS{channel} * Profiler::Score::familiarity(10), 'only the channel counts');
};

subtest 'nearby IP gets partial host credit' => sub {
    my %obs = (%same, host => '10.10.10.3', ip => '10.10.10.3');
    my (undef, $parts) = Profiler::Score::trust(steady_profile(2), \%obs);
    near($parts->{host}, $Profiler::Score::WEIGHTS{host} * Profiler::Score::familiarity(2 * $Profiler::Score::SUBNET_CREDIT),
        'half credit per nearby sighting');

    %obs = (%same, host => '10.10.11.3', ip => '10.10.11.3');
    (undef, $parts) = Profiler::Score::trust(steady_profile(2), \%obs);
    is($parts->{host}, 0, 'different /24 gets nothing');
};

subtest 'hostname match without a resolved IP' => sub {
    my %obs = (%same, ip => undef);
    my (undef, $parts) = Profiler::Score::trust(steady_profile(3), \%obs);
    near($parts->{host}, $Profiler::Score::WEIGHTS{host} * 0.5, 'exact hostname counts');
};

subtest 'proxy hosts earn no host credit' => sub {
    my %obs = (%same, proxy => 'vpn');
    my (undef, $parts) = Profiler::Score::trust(steady_profile(50), \%obs);
    is($parts->{host}, 0, 'exact match on a proxy counts for nothing');

    %obs = (%same, host => '10.10.10.3', ip => '10.10.10.3', proxy => 'vpn');
    (undef, $parts) = Profiler::Score::trust(steady_profile(50), \%obs);
    is($parts->{host}, 0, 'nor does a nearby proxy address');
};

subtest 'missing whois fields score zero rather than failing' => sub {
    my %obs = (host => 'host.example.net', ip => undef, ident => '~bob', channel => '#chan');
    my (undef, $parts) = Profiler::Score::trust(steady_profile(3), \%obs);
    is($parts->{realname}, 0, 'no realname');
    is($parts->{server}, 0, 'no server');
};

subtest 'client version' => sub {
    my $w = $Profiler::Score::WEIGHTS{version};
    my (undef, $parts) = Profiler::Score::trust(steady_profile(3), \%same);
    near($parts->{version}, $w * 0.5, 'exact version');

    (undef, $parts) = Profiler::Score::trust(steady_profile(4), { %same, version => 'irssi v1.4.6' });
    near($parts->{version}, $w * Profiler::Score::familiarity(4 * $Profiler::Score::CLIENT_CREDIT),
        'an upgrade of the same client gets partial credit');

    (undef, $parts) = Profiler::Score::trust(steady_profile(4), { %same, version => 'HexChat 2.16.1' });
    is($parts->{version}, 0, 'a different client gets nothing');

    my $silent = { %{ steady_profile(3) }, versions => { $Profiler::Version::NO_REPLY => 3 } };
    (undef, $parts) = Profiler::Score::trust($silent, { %same, version => $Profiler::Version::NO_REPLY });
    near($parts->{version}, $w * 0.5, 'never answering is consistent too');
};

subtest 'weights add up to 1' => sub {
    my $sum = 0;
    $sum += $_ for values %Profiler::Score::WEIGHTS;
    near($sum, 1, 'sum');
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
