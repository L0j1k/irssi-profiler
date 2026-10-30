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
        '226.sub-203-0-113.myvzw.com'             => 'isp',
        '1-2-3-4dyn.telia.it'                      => 'isp',
        'id-100001.helmsley.irccloud.com'          => 'irccloud',
        'ID-100001.Charlton.IRCCloud.com'          => 'irccloud',
        'tinside.irccloud.com'                     => 'irccloud',
        '2604:9cc0:180a:1::8'                      => 'injected',
        '2604:9cc0:180a::1'                        => 'injected',
        '2604:9cc0:180b::1'                        => 'ip',
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

subtest 'the ISP behind a generated name' => sub {
    is(Profiler::Host::isp_domain('226.sub-203-0-113.myvzw.com'), 'myvzw.com', 'a .com');
    is(Profiler::Host::isp_domain('1-2-3-4dyn.telia.it'), 'telia.it', 'a country domain');
    is(Profiler::Host::isp_domain('host86-1-2-3.range86-1.example.co.uk'), 'example.co.uk', 'one with two parts');
    is(Profiler::Host::isp_domain('irc.example.net'), undef, 'none for a custom name');
    is(Profiler::Host::isp_domain('198.51.100.7'), undef, 'or an address');
};

subtest 'solid keys say when two hosts are the same person' => sub {
    is(Profiler::Host::solid_key('id-100001.helmsley.irccloud.com'),
        Profiler::Host::solid_key('id-100001.charlton.irccloud.com'), 'one irccloud account, any server');
    isnt(Profiler::Host::solid_key('id-100001.helmsley.irccloud.com'),
        Profiler::Host::solid_key('id-100002.helmsley.irccloud.com'), 'another account');
    is(Profiler::Host::solid_key('tinside.irccloud.com', 'uid100001'),
        Profiler::Host::solid_key('id-100001.helmsley.irccloud.com', 'sid100001'),
        'an irccloud host without the account in it has it in the ident');
    is(Profiler::Host::solid_key('tinside.irccloud.com', '~bob'), undef, 'or it is not solid');
    is(Profiler::Host::solid_key('tinside.irccloud.com'), undef, 'nor without an ident');
    is(Profiler::Host::solid_key('irc.example.net', 'uid100001'), 'irc.example.net',
        'a uid ident means nothing off irccloud');
    is(Profiler::Host::solid_key('IRC.Example.net'), 'irc.example.net', 'a custom host is itself');
    is(Profiler::Host::solid_key('192.168.0.1'), '192.168.0.1', 'so is a spoof');
    is(Profiler::Host::solid_key($_), undef, "$_ is not solid")
        for '198.51.100.7', 'cpe-198-51-100-202.san.res.example.com', 'localhost';
};

subtest 'injected irc: the account identifies the user, not the shared range' => sub {
    is(Profiler::Host::solid_key('2604:9cc0:180a:1::8', 'sid000108'), 'injected:000108', 'the sid account');
    is(Profiler::Host::solid_key('2604:9cc0:180a:1::10', 'uid000116'), 'injected:000116', 'and a uid account');
    is(Profiler::Host::solid_key('2604:9cc0:180a:1::8', 'sid000108'),
        Profiler::Host::solid_key('2604:9cc0:180a:9::99', 'sid000108'), 'the same account anywhere in the range');
    is(Profiler::Host::solid_key('2604:9cc0:180a:1::8', 'uid000108'),
        Profiler::Host::solid_key('2604:9cc0:180a:1::8', 'sid000108'), 'uid and sid of one account are the same user');
    isnt(Profiler::Host::solid_key('2604:9cc0:180a:1::8', 'sid000108'),
        Profiler::Host::solid_key('2604:9cc0:180a:1::9', 'sid000109'), 'another account in the range differs');

    ok(Profiler::Host::account_only('2604:9cc0:180a:1::8'), 'the range is account-only, like irccloud');
    ok(Profiler::Host::account_only('hampstead.irccloud.com'), 'as is irccloud');
    ok(!Profiler::Host::account_only('1.2.3.4'), 'a plain address is not');
    ok(!Profiler::Host::account_only('heelys.club'), 'nor a custom host');
};

done_testing;
