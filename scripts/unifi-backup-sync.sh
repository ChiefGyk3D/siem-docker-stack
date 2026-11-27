#!/bin/sh
# unifi-backup-sync.sh - copy the UniFi OS auto-backups of a Pi to a NAS share and print backup
# health as InfluxDB line protocol on stdout. Issue #228. Same fail-closed style as
# pfsense-update-metric.sh.
#
# Usage: unifi-backup-sync.sh [--dry-run]
#
# Runs as ROOT (it mounts the share and reads a root-only credentials file), normally from the
# systemd unit in docs/systemd/. It never deletes anything from the source. On the NAS it only
# ever (1) adds new files, each verified by size and SHA-256 before it gets its final name, and
# (2) removes copies older than RETENTION_DAYS whose name matches the exact autobackup pattern
# (never the newest copy, never after a failed copy). There is no mirroring and no --delete.
# Logs go to stderr (the journal); stdout carries only metric lines.
#
# Link and race safety. The source folder is owned by a container uid and the NAS share may be
# writable by another principal, so: a source that is a symlink, a hard-linked file or not a plain
# file is refused; each source file is opened ONCE (descriptor 3), its type, device, inode, link
# count, size and time must equal what the path showed before the open and again after the copy,
# it is copied from that descriptor to a root-only staging file, and the staged copy (never the
# source path again) is what gets checksummed and uploaded. On the NAS the destination must not
# be a symlink, must resolve physically under the mount point and sit on its device; prune
# candidates must be plain files (never followed) on that device with the exact backup name. The
# share is mounted without nosymfollow (the cifs driver rejects it in -o), then bind-remounted with
# it and the mount table is checked before anything is written to the share.
#
# Settings (environment; systemd EnvironmentFile=):
#   UNIFI_BACKUP_SRC       source folder (default: the UniFi OS rootless container volume path)
#   NAS_MOUNT_POINT        existing empty directory to mount on     (default /mnt/unifi-backup-nas)
#   NAS_SHARE              //host/share, needed unless NAS_USE_EXISTING_MOUNT=1
#   NAS_USE_EXISTING_MOUNT 1 = use an already mounted NAS_MOUNT_POINT and never unmount it
#   NAS_DEST_SUBDIR        one folder name on the share            (default unifi-autobackup)
#   SMB_CREDENTIALS_FILE   root-owned, mode 600     (default /etc/unifi-backup-sync/smb-credentials)
#   SMB_VERS               SMB protocol version                    (default 3.0)
#   RETENTION_DAYS         whole days, 1 to 3650                   (default 90)
#   STATE_DIRECTORY        set by systemd (StateDirectory=); holds the file last-success
# The credentials file is never read or printed by this script; only its path is handed to mount.
#
# Success (exit 0):
#   unifi_backup_newest_age_seconds,where=local|nas value=<n>i
#   unifi_backup_count,where=local|nas value=<n>i
#   unifi_backup_sync_last_success_timestamp value=<epoch>i
#   unifi_backup_sync_success value=1i
#   unifi_backup_sync_result_code value=0i
# Failure (exit 1): only unifi_backup_sync_success value=0i, unifi_backup_sync_result_code value=<n>i
# and, when a previous success is on record, the old last-success timestamp. Never zero-valued
# ages or counts after a failure, so a broken run cannot look healthy.
# Result codes: 0 ok, 1 bad setting or precondition, 2 source missing, empty or unreadable,
# 3 mount, unmount or destination problem, 4 copy failed, 5 size or checksum mismatch, 6 prune failed,
# 7 unexpected internal error, 8 interrupted by a signal, 9 state file could not be written.
#
# --dry-run mounts the share read-only, prints what it would copy and prune on stderr, and changes
# nothing (no copy, no prune, no state, no metrics).
#
# There are no test hooks: the command paths below are fixed lines. The tests rewrite those lines
# in a scratch copy of this file.

PATH=/usr/bin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077

id_bin=/usr/bin/id
date_bin=/usr/bin/date
stat_bin=/usr/bin/stat
perl_bin=/usr/bin/perl
env_bin=/usr/bin/env
df_bin=/usr/bin/df
mv_bin=/usr/bin/mv
rm_bin=/usr/bin/rm
mkdir_bin=/usr/bin/mkdir
sha256_bin=/usr/bin/sha256sum
mount_bin=/usr/bin/mount
umount_bin=/usr/bin/umount
mountpoint_bin=/usr/bin/mountpoint
mountinfo_file=/proc/self/mountinfo
root_uid=0

rc_code=7
we_mounted=0
partial=""
staged=""
stage_dir=""
dry_run=0
now=0
state_file=""
local_count=0
local_newest=0
nas_count=0
nas_newest=0

log() {
    printf 'unifi-backup-sync: %s\n' "$*" >&2
}

# Record the result code and leave through the EXIT trap, which unmounts and prints the metrics.
fail() {
    rc_code=$1
    shift
    log "$*"
    exit 1
}

is_uint() {
    case "$1" in
        0) return 0 ;;
        "" | 0* | *[!0-9]*) return 1 ;;
    esac
    [ "${#1}" -le 11 ]
}

# Only the last success time is persisted; it must be a canonical number or it is ignored.
read_last_success() {
    [ -n "$state_file" ] && [ -f "$state_file" ] && [ ! -L "$state_file" ] || return 1
    read -r last_success < "$state_file" || return 1
    is_uint "$last_success" || return 1
    printf '%s\n' "$last_success"
}

on_exit() {
    trap - EXIT
    if [ -n "$partial" ]; then
        "$rm_bin" -f -- "$partial" 2>/dev/null
        partial=""
    fi
    if [ -n "$staged" ]; then
        "$rm_bin" -f -- "$staged" 2>/dev/null
        staged=""
    fi
    if [ "$we_mounted" -eq 1 ]; then
        we_mounted=0
        if ! "$umount_bin" -- "$NAS_MOUNT_POINT"; then
            log "unmount failed"
            [ "$rc_code" -ne 0 ] || rc_code=3
        fi
    fi
    if [ "$dry_run" -eq 1 ]; then
        [ "$rc_code" -eq 0 ] && exit 0
        exit 1
    fi
    if [ "$rc_code" -eq 0 ]; then
        if ! write_state; then
            rc_code=9
        fi
    fi
    if [ "$rc_code" -eq 0 ]; then
        printf 'unifi_backup_newest_age_seconds,where=local value=%si\n' "$((now - local_newest))"
        printf 'unifi_backup_newest_age_seconds,where=nas value=%si\n' "$((now - nas_newest))"
        printf 'unifi_backup_count,where=local value=%si\n' "$local_count"
        printf 'unifi_backup_count,where=nas value=%si\n' "$nas_count"
        printf 'unifi_backup_sync_last_success_timestamp value=%si\n' "$now"
        printf 'unifi_backup_sync_success value=1i\n'
        printf 'unifi_backup_sync_result_code value=0i\n'
        exit 0
    fi
    if old=$(read_last_success); then
        printf 'unifi_backup_sync_last_success_timestamp value=%si\n' "$old"
    fi
    printf 'unifi_backup_sync_success value=0i\n'
    printf 'unifi_backup_sync_result_code value=%si\n' "$rc_code"
    exit 1
}

trap 'on_exit' EXIT
trap 'rc_code=8; exit 1' HUP INT TERM

write_state() {
    [ -n "$state_file" ] || return 1
    printf '%s\n' "$now" > "$state_file.tmp" || return 1
    "$mv_bin" -f -- "$state_file.tmp" "$state_file" || return 1
}

# ---------------------------------------------------------------- arguments and settings
case "$#" in
    0) ;;
    1)
        case "$1" in
            --dry-run) dry_run=1 ;;
            *) fail 1 "unknown argument" ;;
        esac
        ;;
    *) fail 1 "usage: unifi-backup-sync.sh [--dry-run]" ;;
esac

src_dir=${UNIFI_BACKUP_SRC-/home/uosserver/.local/share/containers/storage/volumes/uosserver_var_lib_unifi/_data/backup/autobackup}
NAS_MOUNT_POINT=${NAS_MOUNT_POINT-/mnt/unifi-backup-nas}
nas_share=${NAS_SHARE-}
use_existing=${NAS_USE_EXISTING_MOUNT-0}
dest_subdir=${NAS_DEST_SUBDIR-unifi-autobackup}
creds_file=${SMB_CREDENTIALS_FILE-/etc/unifi-backup-sync/smb-credentials}
smb_vers=${SMB_VERS-3.0}
retention_days=${RETENTION_DAYS-90}
max_bytes=${MAX_BACKUP_BYTES-1073741824}
min_free=${MIN_FREE_BYTES-268435456}
max_files=1000

# An absolute path of plain characters: no "..", no empty or "." parts, no leading "-".
is_abs_path() {
    case "$1" in
        /*) ;;
        *) return 1 ;;
    esac
    case "$1" in
        *[!A-Za-z0-9_./-]* | *//* | */./* | */../* | */. | */.. | *"/") return 1 ;;
    esac
    [ "${#1}" -le 400 ]
}

is_abs_path "$src_dir" || fail 1 "UNIFI_BACKUP_SRC must be a plain absolute path"
is_abs_path "$NAS_MOUNT_POINT" || fail 1 "NAS_MOUNT_POINT must be a plain absolute path"
case "$use_existing" in
    0 | 1) ;;
    *) fail 1 "NAS_USE_EXISTING_MOUNT must be 0 or 1" ;;
esac
case "$dest_subdir" in
    "" | . | .. | *[!A-Za-z0-9_.-]* | -* ) fail 1 "NAS_DEST_SUBDIR must be one plain folder name" ;;
esac
case "$smb_vers" in
    [123].[0-9] | [123].[0-9][0-9]) ;;
    *) fail 1 "SMB_VERS must look like 3.0" ;;
esac
if ! is_uint "$retention_days" || [ "$retention_days" -lt 1 ] || [ "$retention_days" -gt 3650 ]; then
    fail 1 "RETENTION_DAYS must be a whole number from 1 to 3650"
fi
if ! is_uint "$max_bytes" || [ "$max_bytes" -lt 1 ]; then
    fail 1 "MAX_BACKUP_BYTES must be a whole number of bytes from 1 to 99999999999"
fi
if ! is_uint "$min_free"; then
    fail 1 "MIN_FREE_BYTES must be a whole number of bytes"
fi
if [ "$use_existing" -eq 0 ]; then
    case "$nas_share" in
        //[A-Za-z0-9]*/[A-Za-z0-9]*) ;;
        *) fail 1 "NAS_SHARE must look like //host/share" ;;
    esac
    case "$nas_share" in
        *[!A-Za-z0-9_./-]*) fail 1 "NAS_SHARE has unexpected characters" ;;
    esac
    is_abs_path "$creds_file" || fail 1 "SMB_CREDENTIALS_FILE must be a plain absolute path"
fi

me=$("$id_bin" -u 2>/dev/null) || fail 1 "cannot determine the user id"
is_uint "$me" || fail 1 "unexpected user id"
[ "$me" -eq "$root_uid" ] || fail 1 "must run as root"
now=$("$date_bin" +%s 2>/dev/null) || fail 1 "date failed"
is_uint "$now" || fail 1 "unexpected date output"

# State directory: owned by root, private, not a symlink (systemd StateDirectory= gives that).
if [ "$dry_run" -eq 0 ]; then
    case "${STATE_DIRECTORY-}" in
        /*) ;;
        *) fail 1 "STATE_DIRECTORY is not set (run it from the systemd unit)" ;;
    esac
    is_abs_path "$STATE_DIRECTORY" || fail 1 "STATE_DIRECTORY must be a plain absolute path"
    if [ ! -d "$STATE_DIRECTORY" ] || [ -L "$STATE_DIRECTORY" ]; then fail 1 "state directory missing"; fi
    state_meta=$("$stat_bin" -c '%u %a' -- "$STATE_DIRECTORY" 2>/dev/null) || fail 1 "cannot stat the state directory"
    [ "$state_meta" = "$root_uid 700" ] || fail 1 "state directory must be owned by root, mode 700"
    state_file=$STATE_DIRECTORY/last-success
    # Private staging area on the local disk: the source is copied here through one open
    # descriptor, and only this copy is checksummed and uploaded.
    stage_dir=$STATE_DIRECTORY/stage
    if [ ! -d "$stage_dir" ]; then
        "$mkdir_bin" -m 700 -- "$stage_dir" || fail 1 "cannot create the staging directory"
    fi
    if [ ! -d "$stage_dir" ] || [ -L "$stage_dir" ]; then fail 1 "staging directory is not a plain directory"; fi
    stage_meta=$("$stat_bin" -c '%u %a' -- "$stage_dir" 2>/dev/null) || fail 1 "cannot stat the staging directory"
    [ "$stage_meta" = "$root_uid 700" ] || fail 1 "staging directory must be owned by root, mode 700"
fi

# ---------------------------------------------------------------- names and times
is_digits() { # <value> <min length> <max length>
    case "$1" in
        "" | *[!0-9]*) return 1 ;;
    esac
    [ "${#1}" -ge "$2" ] && [ "${#1}" -le "$3" ]
}

# autobackup_<version>_<date>_<time>_<epoch>.unf, nothing else.
valid_name() {
    case "$1" in
        autobackup_*_*_*_*.unf) ;;
        *) return 1 ;;
    esac
    case "$1" in
        *[!A-Za-z0-9._-]*) return 1 ;;
    esac
    vn_rest=${1#autobackup_}
    vn_rest=${vn_rest%.unf}
    vn_ver=${vn_rest%%_*}
    vn_rest=${vn_rest#*_}
    vn_date=${vn_rest%%_*}
    vn_rest=${vn_rest#*_}
    vn_time=${vn_rest%%_*}
    vn_epoch=${vn_rest#*_}
    case "$vn_epoch" in
        *_*) return 1 ;;
    esac
    case "$vn_ver" in
        [0-9]*) ;;
        *) return 1 ;;
    esac
    is_digits "$vn_date" 8 8 && is_digits "$vn_time" 3 6 && is_digits "$vn_epoch" 1 13
}

regular_file() {
    [ -f "$1" ] && [ ! -L "$1" ]
}

file_mtime() {
    fm=$("$stat_bin" -c %Y -- "$1" 2>/dev/null) || return 1
    is_uint "$fm" || return 1
    [ "$fm" -le $((now + 300)) ] || return 1
    printf '%s\n' "$fm"
}

file_size() {
    fs=$("$stat_bin" -c %s -- "$1" 2>/dev/null) || return 1
    is_uint "$fs" || return 1
    printf '%s\n' "$fs"
}

file_dev() {
    fd=$("$stat_bin" -c %d -- "$1" 2>/dev/null) || return 1
    is_uint "$fd" || return 1
    printf '%s\n' "$fd"
}

# The perl helper (perl-base is Essential on Debian, so /usr/bin/perl is always there) does every
# operation that must be bound to ONE opened object: staging a source file, hashing a file, the
# upload and rename, and the prune. It runs with a cleared environment (no PERL5OPT, PERL5LIB or
# locale from the caller). Exit codes: 0 ok; 10-13, 17, 18, 21-23, 31 and 33 mean the object was
# not the one that was checked; 20 the folder is not the checked folder; 24 the hash tool failed;
# 25 too large; 26 the final name exists; the rest are I/O errors.
run_helper() { # <op> <args...>; the perl program comes on stdin
    helper_op=$1
    shift
    "$env_bin" -i PATH=/usr/bin:/bin LC_ALL=C "$perl_bin" - "$helper_op" "$sha256_bin" "$@" <<'PERL'
use strict; use Fcntl; use IO::Handle;
$SIG{PIPE} = 'IGNORE';
my ($op, $shabin, @a) = @ARGV;
my $BUF = 1048576;
sub bye { exit $_[0] }

# The destination (or staging) folder is opened ONCE with O_DIRECTORY|O_NOFOLLOW and must be the
# folder the script checked (device and inode). Names are then used only below that open folder
# (/proc/self/fd/<n>/<name>), so a swapped path component cannot redirect an operation.
sub open_dir {
    my ($path, $dev, $ino) = @_;
    sysopen(my $d, $path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW) or bye(20);
    my @s = stat($d) or bye(20);
    bye(20) unless $s[0] == $dev && $s[1] == $ino;
    return ($d, "/proc/self/fd/" . fileno($d) . "/");
}

# SHA-256 of at most $max+1 bytes read from ONE open handle, through sha256sum whose exit status
# is checked. Returns (hash, bytes read); any failure of the read or of sha256sum ends the helper.
sub hash_fh {
    my ($fh, $max) = @_;
    pipe(my $r1, my $w1) or bye(24);
    pipe(my $r2, my $w2) or bye(24);
    my $pid = fork();
    bye(24) unless defined $pid;
    if (!$pid) {
        close $w1; close $r2;
        open(STDIN, "<&", $r1) or exit 127;
        open(STDOUT, ">&", $w2) or exit 127;
        exec($shabin) or exit 127;
    }
    close $r1; close $w2;
    my ($left, $got, $buf) = ($max + 1, 0, "");
    while ($left > 0) {
        my $n = sysread($fh, $buf, $left > $BUF ? $BUF : $left);
        if (!defined $n) { kill 9, $pid; waitpid($pid, 0); bye(21); }
        last if $n == 0;
        $got += $n; $left -= $n;
        for (my $o = 0; $o < $n; ) {
            my $w = syswrite($w1, $buf, $n - $o, $o);
            if (!defined $w) { kill 9, $pid; waitpid($pid, 0); bye(24); }
            $o += $w;
        }
    }
    close $w1;
    my $line = <$r2>;
    waitpid($pid, 0);
    bye(24) if $? != 0;
    bye(24) unless defined $line && $line =~ /^([0-9a-f]{64})[ \t]/;
    return ($1, $got);
}

sub same_file { my ($x, $y) = @_; return $x->[0] == $y->[0] && $x->[1] == $y->[1]; }

if ($op eq "stage") {
    # stage SRC DST DEV INO SIZE MTIME: copy a source file through one open descriptor.
    my ($src, $dst, $dev, $ino, $size, $mtime) = @a;
    sysopen(my $in, $src, O_RDONLY | O_NOFOLLOW | O_NONBLOCK) or exit 10;
    my @s = stat($in) or exit 11;
    exit 12 unless -f $in;
    exit 13 unless $s[0] == $dev && $s[1] == $ino && $s[3] == 1 && $s[7] == $size && $s[9] == $mtime;
    sysopen(my $out, $dst, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600) or exit 14;
    my ($left, $got, $buf) = ($size + 1, 0, "");
    while ($left > 0) {
        my $n = sysread($in, $buf, $left > $BUF ? $BUF : $left);
        exit 15 unless defined $n;
        last if $n == 0;
        $got += $n; $left -= $n;
        for (my $o = 0; $o < $n; ) { my $w = syswrite($out, $buf, $n - $o, $o); exit 16 unless defined $w; $o += $w; }
    }
    close($out) or exit 16;
    my @t = stat($in) or exit 17;
    exit 18 unless -f $in && $got == $size && $t[0] == $dev && $t[1] == $ino && $t[3] == 1 && $t[7] == $size && $t[9] == $mtime;
    exit 0;
}

if ($op eq "hash") {
    # hash DIR DDEV DINO NAME MAX: hash one plain file below a checked folder; prints "hash".
    my ($dir, $ddev, $dino, $name, $max) = @a;
    my ($d, $pre) = open_dir($dir, $ddev, $dino);
    sysopen(my $f, $pre . $name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK) or bye(21);
    my @s = stat($f) or bye(21);
    bye(22) unless -f $f && $s[3] == 1;
    bye(25) if $s[7] > $max;
    my ($h, $got) = hash_fh($f, $max);
    # test-hook: after-hash
    my @t = stat($f) or bye(23);
    bye(23) unless same_file(\@s, \@t) && $t[7] == $s[7] && $t[9] == $s[9] && $got == $s[7];
    my @n = lstat($pre . $name);
    bye(23) unless @n && same_file(\@s, \@n);
    print "$h\n";
    exit 0;
}

if ($op eq "publish") {
    # publish DIR DDEV DINO SDIR SDEV SINO SNAME NAME SIZE MTIME SHA MAX: upload a staged file to
    # a new partial file, verify it through the SAME open handle, set its time, rename it into
    # place and confirm the final name is that same file.
    my ($dir, $ddev, $dino, $sdir, $sdev, $sino, $sname, $name, $size, $mtime, $sha, $max) = @a;
    my ($d, $pre) = open_dir($dir, $ddev, $dino);
    my ($sd, $spre) = open_dir($sdir, $sdev, $sino);
    sysopen(my $in, $spre . $sname, O_RDONLY | O_NOFOLLOW | O_NONBLOCK) or bye(21);
    my @is = stat($in) or bye(21);
    bye(22) unless -f $in && $is[3] == 1 && $is[7] == $size;
    my $pn = ".partial-$name";
    unlink($pre . $pn);    # a leftover or planted name is removed as a name, never followed
    my @e = lstat($pre . $name);
    bye(26) if @e;
    sysopen(my $out, $pre . $pn, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600) or bye(27);
    my ($left, $got, $buf) = ($size + 1, 0, "");
    while ($left > 0) {
        my $n = sysread($in, $buf, $left > $BUF ? $BUF : $left);
        bye(28) unless defined $n;
        last if $n == 0;
        $got += $n; $left -= $n;
        for (my $o = 0; $o < $n; ) { my $w = syswrite($out, $buf, $n - $o, $o); bye(28) unless defined $w; $o += $w; }
    }
    bye(28) unless $got == $size;
    $out->sync or bye(28);
    # test-hook: after-upload-write
    sysseek($out, 0, 0) or bye(28);
    my ($h, $got2) = hash_fh($out, $max);
    bye(29) unless $h eq $sha && $got2 == $size;
    my @os = stat($out) or bye(28);
    bye(29) unless -f $out && $os[3] == 1 && $os[7] == $size;
    utime($mtime, $mtime, $out) or bye(30);
    my @pn = lstat($pre . $pn);
    bye(31) unless @pn && same_file(\@os, \@pn);
    @e = lstat($pre . $name);
    bye(26) if @e;
    # test-hook: before-rename
    rename($pre . $pn, $pre . $name) or bye(32);
    my @fin = lstat($pre . $name);
    bye(33) unless @fin && same_file(\@os, \@fin);
    exit 0;
}

if ($op eq "prune") {
    # prune DIR DDEV DINO NAME INO MTIME: remove one old plain file below a checked folder, only
    # if the opened file is the one that was chosen (inode and time) and is on the same device.
    my ($dir, $ddev, $dino, $name, $ino, $mtime) = @a;
    my ($d, $pre) = open_dir($dir, $ddev, $dino);
    sysopen(my $f, $pre . $name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK) or bye(21);
    my @s = stat($f) or bye(21);
    bye(22) unless -f $f && $s[3] == 1 && $s[0] == $ddev;
    bye(23) unless $s[1] == $ino && $s[9] == $mtime;
    # test-hook: before-unlink
    my @n = lstat($pre . $name);
    bye(23) unless @n && same_file(\@s, \@n);
    unlink($pre . $name) or bye(34);
    exit 0;
}

exit 99;
PERL
}

# True when the helper's exit code says an object was not the one that was checked.
helper_says_changed() {
    case "$1" in
        10 | 11 | 12 | 13 | 17 | 18 | 20 | 22 | 23 | 26 | 29 | 31 | 33) return 0 ;;
    esac
    return 1
}

# Type, device, inode, link count, size and mtime of a path (a symlink is not followed).
meta_of() {
    "$stat_bin" -c '%F|%d|%i|%h|%s|%Y' -- "$1" 2>/dev/null
}

# Device and inode of a folder, as "dev ino".
dir_id() {
    di=$(meta_of "$1") || return 1
    IFS='|' read -r di_type di_dev di_ino _ _ _ <<EOF
$di
EOF
    [ "$di_type" = "directory" ] || return 1
    if ! is_uint "$di_dev" || ! is_uint "$di_ino"; then
        return 1
    fi
    printf '%s %s\n' "$di_dev" "$di_ino"
}

# SHA-256 of one plain file below a folder, through the helper (one open file, the exit status of
# sha256sum checked, bound to the checked folder). Prints the hash; any failure returns nonzero
# and prints nothing, so a failed read can never yield a hash that is compared as if valid.
helper_hash() { # <folder> <name> <max bytes>
    hh_id=$(dir_id "$1") || return 1
    read -r hh_dev hh_ino <<EOF
$hh_id
EOF
    hh_out=$(run_helper hash "$1" "$hh_dev" "$hh_ino" "$2" "$3") || return 1
    case "$hh_out" in
        "" | *[!0-9a-f]*) return 1 ;;
    esac
    [ "${#hh_out}" -eq 64 ] || return 1
    printf '%s\n' "$hh_out"
}

# Free bytes on the filesystem of a path.
free_bytes() {
    fb_out=$("$df_bin" -Pk -- "$1" 2>/dev/null) || return 1
    fb_avail=""
    while read -r _ _ _ fb_a _; do
        fb_avail=$fb_a
    done <<EOF
$fb_out
EOF
    is_uint "$fb_avail" || return 1
    printf '%s\n' "$((fb_avail * 1024))"
}

# Count and newest mtime of the valid backups in a folder: sets scan_count and scan_newest.
scan_dir() {
    scan_count=0
    scan_newest=0
    for sd_f in "$1"/*.unf; do
        [ -e "$sd_f" ] || [ -L "$sd_f" ] || continue
        sd_n=${sd_f##*/}
        valid_name "$sd_n" || continue
        regular_file "$sd_f" || continue
        sd_t=$(file_mtime "$sd_f") || return 1
        scan_count=$((scan_count + 1))
        [ "$sd_t" -le "$scan_newest" ] || scan_newest=$sd_t
    done
    return 0
}

# ---------------------------------------------------------------- source
[ -d "$src_dir" ] || fail 2 "source folder is missing"
[ ! -L "$src_dir" ] || fail 2 "source folder is a symlink; refusing"
scan_dir "$src_dir" || fail 2 "a source file has an unreadable or future time"
[ "$scan_count" -gt 0 ] || fail 2 "source folder has no autobackup .unf files"
[ "$scan_count" -le "$max_files" ] || fail 2 "source folder has more than $max_files backup files"
local_count=$scan_count
local_newest=$scan_newest

# ---------------------------------------------------------------- mount
# Read the options of the mount on NAS_MOUNT_POINT from the mount table and set mount_opts (empty
# when the mount is not listed). Octal escapes are not decoded: the path has plain characters only.
read_mount_opts() {
    mount_opts=""
    mo_phys=$(cd -P -- "$NAS_MOUNT_POINT" 2>/dev/null && pwd -P) || return 1
    [ -r "$mountinfo_file" ] || return 1
    while read -r _ _ _ _ mo_mp mo_o _; do
        if [ "$mo_mp" = "$mo_phys" ]; then
            mount_opts=$mo_o
        fi
    done < "$mountinfo_file"
    return 0
}

[ -d "$NAS_MOUNT_POINT" ] || fail 1 "NAS_MOUNT_POINT does not exist"
if [ "$use_existing" -eq 1 ]; then
    "$mountpoint_bin" -q -- "$NAS_MOUNT_POINT" || fail 3 "NAS_USE_EXISTING_MOUNT is set but nothing is mounted there"
    # The script cannot choose the options of a mount it did not make, so it reads them from
    # mountinfo and refuses unless symlinks are not followed. nosuid, nodev and noexec are
    # recommended: a missing one is logged, not fatal.
    read_mount_opts || fail 3 "cannot read the mount table"
    [ -n "$mount_opts" ] || fail 3 "the existing mount is not in the mount table"
    case ",$mount_opts," in
        *,nosymfollow,*) ;;
        *) fail 3 "the existing mount lacks the nosymfollow option; refusing" ;;
    esac
    for em_want in nosuid nodev noexec; do
        case ",$mount_opts," in
            *",$em_want,"*) ;;
            *) log "warning: the existing mount lacks $em_want (recommended)" ;;
        esac
    done
else
    if "$mountpoint_bin" -q -- "$NAS_MOUNT_POINT"; then
        fail 3 "something is already mounted on NAS_MOUNT_POINT (set NAS_USE_EXISTING_MOUNT=1 to use it)"
    fi
    regular_file "$creds_file" || fail 1 "credentials file is missing or not a regular file"
    creds_meta=$("$stat_bin" -c '%u %a' -- "$creds_file" 2>/dev/null) || fail 1 "cannot stat the credentials file"
    [ "$creds_meta" = "$root_uid 600" ] || fail 1 "credentials file must be owned by root, mode 600"
    if [ "$dry_run" -eq 1 ]; then
        mode=ro
    else
        mode=rw
    fi
    log "mounting the share ($mode)"
    we_mounted=1
    # Step 1: the cifs driver rejects nosymfollow inside -o ("Unknown parameter"), so the share is
    # mounted without it. Step 2: a bind remount sets the VFS flag. Step 3: the result is read back
    # from the mount table; nothing touches the share before that check passes. Any failure leaves
    # through fail, whose exit trap unmounts.
    "$mount_bin" -t cifs -o "$mode,credentials=$creds_file,vers=$smb_vers,uid=0,gid=0,file_mode=0600,dir_mode=0700,nosuid,nodev,noexec" -- "$nas_share" "$NAS_MOUNT_POINT" || fail 3 "mount failed"
    "$mount_bin" -o remount,bind,nosymfollow "$NAS_MOUNT_POINT" || fail 3 "could not make the mount refuse symlinks (bind remount failed)"
    read_mount_opts || fail 3 "cannot read the mount table"
    [ -n "$mount_opts" ] || fail 3 "the new mount is not in the mount table"
    # The mode must be listed exactly once, as a whole token, and be the one that was asked for:
    # a listing with both ro and rw, or with neither, or with the other one, is not accepted.
    om_modes=0
    om_seen=""
    for om_m in ro rw; do
        case ",$mount_opts," in
            *",$om_m,"*)
                om_modes=$((om_modes + 1))
                om_seen=$om_m
                ;;
        esac
    done
    if [ "$om_modes" -ne 1 ] || [ "$om_seen" != "$mode" ]; then
        fail 3 "the mount is missing the required option $mode (exactly one of ro or rw must be listed, and it must be the requested one); refusing"
    fi
    for om_want in nosymfollow nosuid nodev noexec; do
        case ",$mount_opts," in
            *",$om_want,"*) ;;
            *) fail 3 "the mount is missing the required option $om_want after the remount; refusing" ;;
        esac
    done
fi

dest=$NAS_MOUNT_POINT/$dest_subdir
if [ ! -d "$dest" ]; then
    if [ "$dry_run" -eq 1 ]; then
        log "dry run: $dest does not exist yet and would be created"
    else
        "$mkdir_bin" -m 700 -- "$dest" || fail 4 "cannot create the destination folder"
    fi
fi

# The destination must be a real folder on the mounted share itself: not a symlink, resolving
# physically to a place under the mount point, on the same device as the mount point.
mp_dev=$(file_dev "$NAS_MOUNT_POINT") || fail 3 "cannot stat the mount point"
if [ -e "$dest" ] || [ -L "$dest" ]; then
    if [ ! -d "$dest" ] || [ -L "$dest" ]; then fail 3 "destination is a symlink or not a folder; refusing"; fi
    mp_phys=$(cd -P -- "$NAS_MOUNT_POINT" 2>/dev/null && pwd -P) || fail 3 "cannot resolve the mount point"
    dest_phys=$(cd -P -- "$dest" 2>/dev/null && pwd -P) || fail 3 "cannot resolve the destination"
    [ "$dest_phys" = "${mp_phys%/}/$dest_subdir" ] || fail 3 "destination resolves outside the mount point; refusing"
    dest_dev=$(file_dev "$dest") || fail 3 "cannot stat the destination"
    [ "$dest_dev" = "$mp_dev" ] || fail 3 "destination is on another device than the mount point; refusing"
    # Only the service account may write the folder: owned by root and not writable by group or
    # others. On CIFS the mode is the one this mount gives (dir_mode), so this proves nothing about
    # the server's own permissions; on an existing mount of another kind it is a real check.
    dest_perm=$("$stat_bin" -c '%u %a' -- "$dest" 2>/dev/null) || fail 3 "cannot stat the destination"
    read -r dp_uid dp_mode <<EOF
$dest_perm
EOF
    is_uint "$dp_mode" || fail 3 "cannot read the destination mode"
    dp_mode=$((dp_mode % 1000))
    if [ "$dp_uid" != "$root_uid" ] || [ $(((dp_mode / 10 % 10) & 2)) -ne 0 ] || [ $((dp_mode % 10 & 2)) -ne 0 ]; then
        fail 3 "destination must be owned by root and not writable by group or others; refusing"
    fi
fi

dest_id=""
dest_dev_id=""
dest_ino_id=""
if [ -d "$dest" ]; then
    dest_id=$(dir_id "$dest") || fail 3 "cannot read the identity of the destination"
    read -r dest_dev_id dest_ino_id <<EOF
$dest_id
EOF
fi

stage_dev=""
stage_ino=""
if [ "$dry_run" -eq 0 ]; then
    stage_id=$(dir_id "$stage_dir") || fail 1 "cannot read the identity of the staging directory"
    read -r stage_dev stage_ino <<EOF
$stage_id
EOF
fi

# ---------------------------------------------------------------- copy
copy_rc=0
for f in "$src_dir"/*.unf; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    name=${f##*/}
    valid_name "$name" || continue
    if [ -L "$f" ] || [ ! -f "$f" ]; then
        [ "$copy_rc" -ne 0 ] || copy_rc=2
        log "source $name is a symlink or not a plain file; refusing it"
        continue
    fi
    target=$dest/$name
    pre=$(meta_of "$f") || pre=""
    IFS='|' read -r s_type s_dev s_ino s_nl s_size s_mtime <<EOF
$pre
EOF
    if [ "$s_type" != "regular file" ] || [ "$s_nl" != 1 ] || ! is_uint "$s_size" || ! is_uint "$s_mtime"; then
        [ "$copy_rc" -ne 0 ] || copy_rc=2
        log "source $name has more than one hard link or unreadable metadata; refusing it"
        continue
    fi
    if [ "$s_size" -gt "$max_bytes" ]; then
        [ "$copy_rc" -ne 0 ] || copy_rc=2
        log "source $name is larger than MAX_BACKUP_BYTES; refusing it"
        continue
    fi
    if [ "$dry_run" -eq 1 ]; then
        if [ -e "$target" ] || [ -L "$target" ]; then
            log "dry run: $name already exists on the NAS (its content is compared in a real run)"
        else
            log "dry run: would copy $name"
        fi
        continue
    fi
    free=$(free_bytes "$stage_dir") || free=0
    if [ "$free" -lt $((s_size + min_free)) ]; then
        [ "$copy_rc" -ne 0 ] || copy_rc=4
        log "not enough free space in the state directory for $name; refusing it"
        continue
    fi
    # Stage through the one-open helper (identity bound to the opened file, no FIFO hang, at most
    # size+1 bytes, so an endless file cannot fill the disk) into a root-only file.
    staged=$stage_dir/current
    partial=$dest/.partial-$name
    "$rm_bin" -f -- "$staged"
    run_helper stage "$f" "$staged" "$s_dev" "$s_ino" "$s_size" "$s_mtime"
    helper_rc=$?
    step_rc=0
    post=$(meta_of "$f") || post=""
    stg_size=$(file_size "$staged") || stg_size=""
    stg_sha=$(helper_hash "$stage_dir" current "$max_bytes") || stg_sha=""
    if [ "$post" != "$pre" ] || helper_says_changed "$helper_rc"; then
        step_rc=5
        log "source $name is not the file that was checked (changed, swapped or replaced); refusing it"
    elif [ "$helper_rc" -ne 0 ]; then
        step_rc=4
        log "reading $name failed"
    elif [ "$stg_size" != "$s_size" ] || [ -z "$stg_sha" ]; then
        step_rc=5
        log "verification of the staged copy of $name failed (size or checksum)"
    elif [ -e "$target" ] || [ -L "$target" ]; then
        # Never overwrite and never delete. An existing copy must hold exactly the same bytes; it
        # is hashed through one open file, and the hash counts only if the name still shows that
        # same file afterwards.
        tgt_sha=$(helper_hash "$dest" "$name" "$max_bytes") || tgt_sha=""
        if [ -z "$tgt_sha" ] || [ "$tgt_sha" != "$stg_sha" ]; then
            step_rc=5
            log "existing copy of $name differs from the source or could not be verified; left untouched (move it aside by hand to re-copy)"
        else
            step_rc=-1
        fi
    else
        # Upload, verify, set the time, rename and confirm, all in one helper bound to the opened
        # destination folder and to the partial file's own open handle.
        run_helper publish "$dest" "$dest_dev_id" "$dest_ino_id" "$stage_dir" "$stage_dev" "$stage_ino" current "$name" "$s_size" "$s_mtime" "$stg_sha" "$max_bytes"
        pub_rc=$?
        if [ "$pub_rc" -ne 0 ]; then
            if helper_says_changed "$pub_rc" || [ "$pub_rc" -eq 29 ]; then
                step_rc=5
                log "publishing $name failed its checks (rc $pub_rc); the final name is not a verified copy of the source"
            else
                step_rc=4
                log "upload of $name failed (rc $pub_rc)"
            fi
        fi
    fi
    "$rm_bin" -f -- "$staged"
    staged=""
    if [ "$step_rc" -gt 0 ]; then
        [ "$copy_rc" -ne 0 ] || copy_rc=$step_rc
        "$rm_bin" -f -- "$partial"
        partial=""
        continue
    fi
    partial=""
    if [ "$step_rc" -eq 0 ]; then
        log "copied and verified $name"
    fi
done

# ---------------------------------------------------------------- prune
prune_rc=0
if [ "$copy_rc" -eq 0 ] && [ -d "$dest" ]; then
    scan_dir "$dest" || fail 6 "a NAS file has an unreadable or future time"
    protect=$scan_newest
    limit=$((retention_days * 86400))
    for f in "$dest"/*.unf; do
        [ -e "$f" ] || continue
        name=${f##*/}
        valid_name "$name" || continue
        cand=$(meta_of "$f") || cand=""
        IFS='|' read -r c_type c_dev c_ino c_nl _ c_mtime <<EOF
$cand
EOF
        [ "$c_type" = "regular file" ] || continue
        if ! is_uint "$c_mtime" || ! is_uint "$c_ino" || [ "$c_mtime" -gt $((now + 300)) ]; then
            prune_rc=6
            continue
        fi
        if [ "$c_mtime" -eq "$protect" ] || [ $((now - c_mtime)) -le "$limit" ]; then
            continue
        fi
        if [ "$c_dev" != "$mp_dev" ] || [ "$c_nl" != 1 ]; then
            prune_rc=6
            log "prune candidate $name is on another device or has several links; left alone"
            continue
        fi
        if [ "$dry_run" -eq 1 ]; then
            log "dry run: would remove $name (older than $retention_days days)"
        elif run_helper prune "$dest" "$dest_dev_id" "$dest_ino_id" "$name" "$c_ino" "$c_mtime"; then
            log "removed $name (older than $retention_days days)"
        else
            prune_rc=6
            log "could not remove $name (it was not the file chosen, or the folder changed)"
        fi
    done
fi

[ "$copy_rc" -eq 0 ] || fail "$copy_rc" "sync failed; nothing was pruned"
[ "$prune_rc" -eq 0 ] || fail "$prune_rc" "prune failed"

if [ "$dry_run" -eq 1 ]; then
    rc_code=0
    exit 0
fi

# ---------------------------------------------------------------- result
scan_dir "$dest" || fail 6 "a NAS file has an unreadable or future time"
[ "$scan_count" -gt 0 ] || fail 5 "no verified copy is on the NAS"
nas_count=$scan_count
nas_newest=$scan_newest
rc_code=0
# Falling off the end runs the EXIT trap, which unmounts and prints the metrics.
