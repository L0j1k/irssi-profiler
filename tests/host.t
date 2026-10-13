use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use Test::More;

use Profiler::Host;

subtest 'kinds of host' => sub {
    my %want = (
        '198.51.100.7'                             => 'ip',
        '2001:db8::1'                              => 'ip',
        'cpe-198-51-100-202.san.res.example.com'    => 'isp',
        'c-198-51-100-7.hsd1.ca.example.net'       => 'isp',
        'p5b3c1d2e.dip0.example.de'                => 'isp',
        'host86-1-2-3.range86-1.example.com'       => 'isp',
        'dynamic.example.net'                      => 'isp',
        'customer.dsl.example.net'                 => 'isp',
        'id-100001.helmsley.irccloud.com'          => 'irccloud',
        'ID-100001.Charlton.IRCCloud.com'          => 'irccloud',
        'ip-198-51-100-7.tinside.irccloud.com'     => 'isp',
        'irc.example.net'                          => 'custom',
        'gus.example.org'                        => 'custom',
        'box2.example.org'                         => 'custom',
        'localhost'                                => 'other',
        '192.168.0.1'                              => 'spoof',
        '10.1.2.3'                                 => 'spoof',
        '172.16.0.9'                               => 'spoof',
        '172.31.255.1'                             => 'spoof',
        '127.0.0.1'                                => 'spoof',
        'fd00::1'                                  => 'spoof',
        'fe80::1'                                  => 'spoof',
        '172.32.0.1'                               => 'ip',
        '11.1.2.3'                                 => 'ip',
    );
    is(Profiler::Host::kind($_), $want{$_}, "$_ is $want{$_}") for sort keys %want;
};

subtest 'solid keys say when two hosts are the same person' => sub {
    is(Profiler::Host::solid_key('id-100001.helmsley.irccloud.com'),
        Profiler::Host::solid_key('id-100001.charlton.irccloud.com'), 'one irccloud account, any server');
    isnt(Profiler::Host::solid_key('id-100001.helmsley.irccloud.com'),
        Profiler::Host::solid_key('id-100002.helmsley.irccloud.com'), 'another account');
    is(Profiler::Host::solid_key('IRC.Example.net'), 'irc.example.net', 'a custom host is itself');
    is(Profiler::Host::solid_key('192.168.0.1'), '192.168.0.1', 'so is a spoof');
    is(Profiler::Host::solid_key($_), undef, "$_ is not solid")
        for '198.51.100.7', 'cpe-198-51-100-202.san.res.example.com', 'localhost';
};

done_testing;
