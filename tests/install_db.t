use strict;
use warnings;

use FindBin;
use File::Temp qw(tempdir);
use Test::More;

my $script = "$FindBin::Bin/../scripts/install_db.sh";

sub write_file { my ($path, $text) = @_; open my $fh, '>', $path or die "$path: $!"; print $fh $text; close $fh }
sub read_file { my ($path) = @_; open my $fh, '<', $path or die "$path: $!"; local $/; <$fh> }

# Runs the script and returns its exit status and everything it printed.
sub run {
    my $out = `'$script' @_ 2>&1`;
    return ($? >> 8, $out);
}

sub setup {
    my $tmp = tempdir(CLEANUP => 1);
    mkdir "$tmp/build";
    mkdir "$tmp/irssi";
    mkdir "$tmp/irssi/scripts";
    mkdir "$tmp/irssi/scripts/profiler-data";
    write_file("$tmp/build/efnet.sqlite", 'new');
    return ($tmp, "$tmp/irssi/scripts/profiler-data");
}

subtest 'installs the new file, keeps the old one, and clears the old WAL' => sub {
    my ($tmp, $data) = setup();
    write_file("$data/efnet.sqlite", 'old');
    write_file("$data/efnet.sqlite-wal", 'stale');
    write_file("$data/efnet.sqlite-shm", 'stale');
    my ($status, $out) = run("--from '$tmp/build' EFNet '$tmp/irssi'");
    is $status, 0, 'succeeds' or diag $out;
    is read_file("$data/efnet.sqlite"), 'new', 'new database in place';
    is read_file("$data/efnet.sqlite.old"), 'old', 'old database kept';
    ok !-e "$data/efnet.sqlite-wal", 'stale WAL removed';
    ok !-e "$data/efnet.sqlite-shm", 'stale shared memory file removed';
    like $out, qr/installed .*efnet\.sqlite/, 'says what it did';
};

subtest 'installs when there is no database yet' => sub {
    my ($tmp, $data) = setup();
    my ($status, $out) = run("--from '$tmp/build' EFNet '$tmp/irssi'");
    is $status, 0, 'succeeds' or diag $out;
    is read_file("$data/efnet.sqlite"), 'new', 'new database in place';
    ok !-e "$data/efnet.sqlite.old", 'no old copy made';
};

subtest 'refuses while something has the live database open' => sub {
    my ($tmp, $data) = setup();
    write_file("$data/efnet.sqlite", 'old');
    write_file("$data/efnet.sqlite-wal", 'live');
    open my $held, '<', "$data/efnet.sqlite-wal" or die $!;
    my ($status, $out) = run("--from '$tmp/build' EFNet '$tmp/irssi'");
    close $held;
    isnt $status, 0, 'fails';
    like $out, qr/efnet\.sqlite-wal is open in pid $$ \(perl/, 'names the process';
    like $out, qr{/script unload profiler}, 'says how to close it';
    is read_file("$data/efnet.sqlite"), 'old', 'live database untouched';
    is read_file("$data/efnet.sqlite-wal"), 'live', 'live WAL untouched';
};

subtest 'refuses while the import is still writing' => sub {
    my ($tmp, $data) = setup();
    open my $held, '<', "$tmp/build/efnet.sqlite" or die $!;
    my ($status, $out) = run("--from '$tmp/build' EFNet '$tmp/irssi'");
    close $held;
    isnt $status, 0, 'fails';
    like $out, qr/build\/efnet\.sqlite is open in pid $$/, 'names the process';
    ok !-e "$data/efnet.sqlite", 'nothing installed';
};

subtest 'refuses an import that left a WAL behind' => sub {
    my ($tmp, $data) = setup();
    write_file("$tmp/build/efnet.sqlite-wal", 'unfinished');
    my ($status, $out) = run("--from '$tmp/build' EFNet '$tmp/irssi'");
    isnt $status, 0, 'fails';
    like $out, qr/efnet\.sqlite-wal/, 'names the WAL';
    ok !-e "$data/efnet.sqlite", 'nothing installed';
};

subtest 'complains about a missing import' => sub {
    my ($tmp, $data) = setup();
    my ($status, $out) = run("--from '$tmp/build' Undernet '$tmp/irssi'");
    isnt $status, 0, 'fails';
    like $out, qr/no import at .*build\/undernet\.sqlite/, 'says which file it looked for';
};

subtest 'complains without a network' => sub {
    my ($status, $out) = run('');
    isnt $status, 0, 'fails';
    like $out, qr/usage:/, 'shows usage';
};

done_testing;
