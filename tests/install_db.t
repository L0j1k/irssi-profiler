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

sub backups { my ($data) = @_; sort glob "$data/efnet.sqlite.*-*.old" }

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
    my @kept = backups($data);
    is scalar @kept, 1, 'one backup made';
    like $kept[0], qr/\/efnet\.sqlite\.\d{4}-\d\d-\d\d-\d{6}\.old$/, 'named for when it was replaced';
    is read_file($kept[0]), 'old', 'old database kept';
    ok !-e "$data/efnet.sqlite-wal", 'stale WAL removed';
    ok !-e "$data/efnet.sqlite-shm", 'stale shared memory file removed';
    like $out, qr/installed .*efnet\.sqlite/, 'says what it did';
    like $out, qr/kept the old one as .*efnet\.sqlite\.\d{4}-\d\d-\d\d-\d{6}\.old/, 'says where the old one went';
};

subtest 'a second install keeps every earlier backup' => sub {
    my ($tmp, $data) = setup();
    write_file("$data/efnet.sqlite", 'first');
    write_file("$data/efnet.sqlite.old", 'older still');
    my ($status, $out) = run("--from '$tmp/build' EFNet '$tmp/irssi'");
    is $status, 0, 'first install succeeds' or diag $out;
    sleep 1;
    write_file("$tmp/build/efnet.sqlite", 'newer');
    ($status, $out) = run("--from '$tmp/build' EFNet '$tmp/irssi'");
    is $status, 0, 'second install succeeds' or diag $out;
    is read_file("$data/efnet.sqlite"), 'newer', 'newest database in place';
    is_deeply [ map { read_file($_) } backups($data) ], [ 'first', 'new' ], 'both replaced databases kept, oldest first';
    is read_file("$data/efnet.sqlite.old"), 'older still', 'a backup from before dated names left alone';
};

subtest 'refuses rather than overwrite a backup' => sub {
    my ($tmp, $data) = setup();
    write_file("$data/efnet.sqlite", 'old');
    # Every name the script could pick in the next few seconds is taken.
    my @taken = map { my @t = localtime(time + $_); sprintf "$data/efnet.sqlite.%04d-%02d-%02d-%02d%02d%02d.old",
        $t[5] + 1900, $t[4] + 1, @t[3, 2, 1, 0] } 0 .. 3;
    write_file($_, 'backup') for @taken;
    my ($status, $out) = run("--from '$tmp/build' EFNet '$tmp/irssi'");
    isnt $status, 0, 'fails';
    like $out, qr/efnet\.sqlite\.\d{4}-\d\d-\d\d-\d{6}\.old already exists/, 'names the backup in the way';
    is read_file("$data/efnet.sqlite"), 'old', 'live database untouched';
    is read_file($_), 'backup', 'backup untouched' for @taken;
};

subtest 'installs when there is no database yet' => sub {
    my ($tmp, $data) = setup();
    my ($status, $out) = run("--from '$tmp/build' EFNet '$tmp/irssi'");
    is $status, 0, 'succeeds' or diag $out;
    is read_file("$data/efnet.sqlite"), 'new', 'new database in place';
    is_deeply [ backups($data) ], [], 'no old copy made';
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
