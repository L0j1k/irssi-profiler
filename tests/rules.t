use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../src";

use Test::More;

use Profiler::Rules;

subtest 'watch lines' => sub {
    my ($rules, $errors) = Profiler::Rules::parse(
        "# comment\n",
        "\n",
        "efnet #CHAN 0.6\n",
        "EFnet #a,#B 0.3\n",
        "* * 0.1\n",
    );
    is_deeply($errors, [], 'no errors');
    is(scalar @{ $rules->{watches} }, 3, 'three watches');
    is_deeply($rules->{watches}[1]{channels}, ['#a', '#b'], 'channels split and lowercased');
    is($rules->{watches}[1]{network}, 'efnet', 'network lowercased');
};

subtest 'bad watch lines are reported with their line number' => sub {
    my ($rules, $errors) = Profiler::Rules::parse(
        "efnet #CHAN 1.5\n",
        "efnet #CHAN high\n",
        "efnet #CHAN\n",
        "efnet #ok 0.5\n",
    );
    is(scalar @$errors, 3, 'three errors');
    like($errors->[0], qr/^line 1: /, 'out of range trust');
    like($errors->[1], qr/^line 2: /, 'non-numeric trust');
    like($errors->[2], qr/^line 3: /, 'missing trust');
    is(scalar @{ $rules->{watches} }, 1, 'good line still loaded');
};

subtest 'proxy keyword lines' => sub {
    my ($rules, $errors) = Profiler::Rules::parse(
        "proxy Some Hoster GmbH\n",
        "proxy\n",
    );
    is_deeply($rules->{proxy_keywords}, ['some hoster gmbh'], 'keyword is the rest of the line, lowercased');
    is(scalar @$errors, 1, 'empty proxy line is an error');
    like($errors->[0], qr/^line 2: /, 'error names the line');
};

subtest 'min_trust_for' => sub {
    my ($rules) = Profiler::Rules::parse(
        "efnet #chan,#other 0.6\n",
        "* #chan 0.8\n",
        "libera * 0.2\n",
    );
    is(Profiler::Rules::min_trust_for($rules, 'EFnet', '#CHAN'), 0.8, 'strictest matching rule wins');
    is(Profiler::Rules::min_trust_for($rules, 'efnet', '#other'), 0.6, 'exact network and channel');
    is(Profiler::Rules::min_trust_for($rules, 'libera', '#anything'), 0.2, 'channel wildcard');
    is(Profiler::Rules::min_trust_for($rules, 'efnet', '#nope'), undef, 'unwatched channel');
};

done_testing;
