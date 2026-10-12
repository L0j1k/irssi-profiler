use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use File::Temp qw(tempdir);
use POSIX ();
use Test::More;

use Profiler::Import;
use Profiler::Store;

# Log times are local time, so pin the zone for predictable epochs.
$ENV{TZ} = 'UTC';
POSIX::tzset();

my $LOGS = "$FindBin::Bin/fixtures/logs/EFNet";

subtest 'parse_path' => sub {
    is_deeply(Profiler::Import::parse_path("$LOGS/2024/05/2024-05-05-#chan.log"),
        { year => 2024, month => 5, day => 5, target => '#chan' }, 'channel log');
    is_deeply(Profiler::Import::parse_path('/x/2024-05-05-carol.log'),
        { year => 2024, month => 5, day => 5, target => 'carol' }, 'query log');
    is(Profiler::Import::parse_path('/x/notes.txt'), undef, 'not a log');
};

subtest 'parse_join' => sub {
    is_deeply(Profiler::Import::parse_join('08:57:35-!- EVE2_ [~Maceve@192.0.2.26] has joined #chan'),
        { hour => 8, min => 57, sec => 35, nick => 'EVE2_', ident => '~Maceve', host => '192.0.2.26', channel => '#chan' },
        'join');
    is_deeply(Profiler::Import::parse_join('01:26 -!- bob [~bob@cpe-192-0-2-202.example.net] has joined #2600'),
        { hour => 1, min => 26, sec => 0, nick => 'bob', ident => '~bob', host => 'cpe-192-0-2-202.example.net', channel => '#2600' },
        'older format: no seconds, space before -!-');
    is(Profiler::Import::parse_join('15:10 -!- \\\\\\\\\\ [~m@192.0.2.82] has joined #2600')->{nick}, '\\\\\\\\\\',
        'odd nicks');
    is(Profiler::Import::parse_join('06:05:46-!- walter [~walter@192.0.2.1] has quit [Ping timeout]'),
        undef, 'quit is not a join');
    is(Profiler::Import::parse_join('21:43:58<+bob> someone has joined #chan [x@y]'), undef, 'chat is not a join');
    is(Profiler::Import::parse_join('22:00:00-!- broken [no-at-sign] has joined #chan'), undef, 'malformed');
};

subtest 'replaying a log directory' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    my @months;
    my $stats = Profiler::Import::replay(
        store    => $store,
        network  => 'EFNet',
        logs     => $LOGS,
        recheck  => 600,
        on_month => sub { push @months, $_[0] },
    );

    is($stats->{joins}, 5, 'joins replayed');
    is($stats->{repeats}, 1, 'rejoin within the recheck window skipped');
    is($stats->{unparsed}, 1, 'malformed join line counted');
    like($stats->{unparsed_examples}[0], qr/broken/, 'and shown');
    is($stats->{verdicts}{suspect}, 1, 'one suspect');
    is($stats->{promoted}, 0, 'a single impostor join is not a move');
    is_deeply(\@months, ['2024-05'], 'progress per month');

    my $bob = $store->profile('efnet', 'bob');
    my @s = @{ $bob->{sightings} };
    is(scalar @s, 5, 'query logs are skipped');
    is_deeply([ map { $_->{channel} } @s[0, 1] ], ['#other', '#chan'], 'joins across channels merged by time');
    is($s[0]{time}, POSIX::mktime(0, 0, 7, 5, 4, 124), 'time from file date and line');
    is($s[0]{ip}, '192.0.2.10', 'literal address used as ip');

    my $troll = $s[-1];
    is($troll->{ident}, 'lol', 'last sighting is the impostor');
    is($troll->{verdict}, 'suspect', 'judged suspect');
    ok($troll->{quarantined}, 'quarantined');
};

subtest 'host names are not resolved' => sub {
    my $logs = tempdir(CLEANUP => 1);
    mkdir "$logs/2024";
    mkdir "$logs/2024/01";
    open my $fh, '>', "$logs/2024/01/2024-01-01-#c.log" or die $!;
    print $fh "10:00:00-!- bob [~bob\@host.example.net] has joined #c\n";
    close $fh;

    my $store = Profiler::Store->new(tempdir(CLEANUP => 1));
    Profiler::Import::replay(store => $store, network => 'efnet', logs => $logs, recheck => 600);
    my $s = $store->profile('efnet', 'bob')->{sightings}[0];
    is($s->{host}, 'host.example.net', 'host kept');
    ok(!exists $s->{ip}, 'no ip');
};

done_testing;
