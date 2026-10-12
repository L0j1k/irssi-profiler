use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use File::Temp qw(tempdir);
use Test::More;

use Profiler::Store;

my %obs = (
    nick     => 'Bob',
    host     => 'host.example.net',
    ip       => '10.10.10.2',
    ident    => '~bob',
    realname => 'Bob Smith',
    server   => 'irc.example.net',
    channel  => '#CHAN',
    version  => 'irssi v1.4.5',
);

subtest 'recording and reloading sightings' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);

    is($store->profile('EFnet', 'bob'), undef, 'unknown nick');
    $store->record('EFnet', \%obs, 1000);
    $store->record('EFnet', { %obs, realname => undef, server => undef }, 2000);
    $store->save('EFnet');

    ok(-f "$dir/efnet.json", 'one file per network, lowercased');

    my $p = Profiler::Store->new($dir)->profile('efnet', 'BOB');
    is($p->{nick}, 'Bob', 'display nick kept');
    is($p->{sightings}, 2, 'sightings');
    is($p->{first_seen}, 1000, 'first seen');
    is($p->{last_seen}, 2000, 'last seen');
    is($p->{hosts}{'host.example.net'}, 2, 'host count');
    is($p->{ips}{'10.10.10.2'}, 2, 'ip count');
    is($p->{realnames}{'Bob Smith'}, 1, 'missing values are not counted');
    is($p->{channels}{'#chan'}, 2, 'channels lowercased');
    is($p->{versions}{'irssi v1.4.5'}, 2, 'client versions counted');
};

subtest 'odd network names make safe file names' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    $store->record('../My Net', \%obs, 1);
    $store->save('../My Net');
    ok(-f "$dir/.._my_net.json", 'slashes and spaces replaced');
};

subtest 'host lookups are cached with an age' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $store = Profiler::Store->new($dir);
    $store->set_hostinfo('efnet', 'host.example.net', { ip => '10.10.10.2', proxy => undef }, 1000);
    is($store->fresh_hostinfo('efnet', 'host.example.net', 1500, 600)->{ip}, '10.10.10.2', 'fresh');
    is($store->fresh_hostinfo('efnet', 'host.example.net', 1700, 600), undef, 'stale');
    is($store->fresh_hostinfo('efnet', 'other', 1500, 600), undef, 'unknown host');
};

subtest 'a corrupt file is reported and never overwritten' => sub {
    my $dir = tempdir(CLEANUP => 1);
    open my $fh, '>', "$dir/efnet.json" or die $!;
    print $fh "{ not json";
    close $fh;

    my $store = Profiler::Store->new($dir);
    eval { $store->profile('efnet', 'bob') };
    like($@, qr/cannot parse .*efnet\.json/, 'load error names the file');

    eval { $store->record('efnet', \%obs, 1) };
    like($@, qr/cannot parse/, 'still refuses on later use');
    eval { $store->save('efnet') };
    like($@, qr/cannot parse/, 'save refuses too');

    open $fh, '<', "$dir/efnet.json" or die $!;
    is(scalar <$fh>, '{ not json', 'file untouched');
};

done_testing;
