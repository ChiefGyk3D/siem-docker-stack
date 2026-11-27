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
# share is mounted with nosymfollow.
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
dd_bin=/usr/bin/dd
perl_bin=/usr/bin/perl
df_bin=/usr/bin/df
mv_bin=/usr/bin/mv
rm_bin=/usr/bin/rm
touch_bin=/usr/bin/touch
mkdir_bin=/usr/bin/mkdir
sha256_bin=/usr/bin/sha256sum
mount_bin=/usr/bin/mount
umount_bin=/usr/bin/umount
mountpoint_bin=/usr/bin/mountpoint
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

# One-open copy helper (perl-base is Essential on Debian, so /usr/bin/perl is always there). It
# opens the source ONCE with O_NOFOLLOW|O_NONBLOCK (a symlink is not followed, a FIFO does not
# block), requires the open file itself (fstat) to be a plain file with the device, inode, size and
# time the path showed before and a link count of 1, copies at most size+1 bytes from that one
# descriptor into a new root-only file (O_EXCL|O_NOFOLLOW), and checks the descriptor again after
# the read. Exit 0 = copied; 10 to 13, 17 and 18 = the file is not what was checked; other = I/O.
run_copy_helper() { # <src> <dst> <dev> <ino> <size> <mtime>; the perl program comes on stdin
    "$perl_bin" - "$@" <<'PERL'
use strict; use Fcntl; my ($src, $dst, $dev, $ino, $size, $mtime) = @ARGV;
sysopen(my $in, $src, O_RDONLY | O_NOFOLLOW | O_NONBLOCK) or exit 10;
my @s = stat($in) or exit 11;
exit 12 unless -f $in;
exit 13 unless $s[0] == $dev && $s[1] == $ino && $s[3] == 1 && $s[7] == $size && $s[9] == $mtime;
sysopen(my $out, $dst, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600) or exit 14;
my ($left, $got, $buf) = ($size + 1, 0, "");
while ($left > 0) {
    my $n = sysread($in, $buf, $left > 1048576 ? 1048576 : $left);
    exit 15 unless defined $n;
    last if $n == 0;
    $got += $n; $left -= $n;
    for (my $o = 0; $o < $n; ) { my $w = syswrite($out, $buf, $n - $o, $o); exit 16 unless defined $w; $o += $w; }
}
close($out) or exit 16;
my @t = stat($in) or exit 17;
exit 18 unless -f $in && $got == $size && $t[0] == $dev && $t[1] == $ino && $t[3] == 1 && $t[7] == $size && $t[9] == $mtime;
exit 0;
PERL
}

# True when the helper's exit code says the opened file was not the file that was checked.
helper_says_changed() {
    case "$1" in
        10 | 11 | 12 | 13 | 17 | 18) return 0 ;;
    esac
    return 1
}

# Type, device, inode, link count, size and mtime of a path (a symlink is not followed).
meta_of() {
    "$stat_bin" -c '%F|%d|%i|%h|%s|%Y' -- "$1" 2>/dev/null
}

# SHA-256 of a plain file, read by dd with O_NOFOLLOW and O_NONBLOCK and bounded to <max>+1
# bytes, so a symlink, a FIFO swapped in or an endless file cannot hang or mislead the read. A
# read that fails or is cut short gives a different hash, never a matching one.
sha_of_file() { # <path> <max bytes>
    shs=$("$dd_bin" if="$1" iflag=nofollow,nonblock,count_bytes bs=1M count="$(($2 + 1))" status=none 2>/dev/null | "$sha256_bin" 2>/dev/null)
    read -r fh _ <<EOF || return 1
$shs
EOF
    case "$fh" in
        "" | *[!0-9a-f]*) return 1 ;;
    esac
    [ "${#fh}" -eq 64 ] || return 1
    printf '%s\n' "$fh"
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
[ -d "$NAS_MOUNT_POINT" ] || fail 1 "NAS_MOUNT_POINT does not exist"
if [ "$use_existing" -eq 1 ]; then
    "$mountpoint_bin" -q -- "$NAS_MOUNT_POINT" || fail 3 "NAS_USE_EXISTING_MOUNT is set but nothing is mounted there"
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
    "$mount_bin" -t cifs -o "$mode,credentials=$creds_file,vers=$smb_vers,uid=0,gid=0,file_mode=0600,dir_mode=0700,nosuid,nodev,noexec,nosymfollow" -- "$nas_share" "$NAS_MOUNT_POINT" || fail 3 "mount failed"
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
    IFS='|' read -r s_type _ _ s_nl s_size s_mtime <<EOF
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
    # Stage through the one-open helper above (identity bound to the opened file, no FIFO hang,
    # at most size+1 bytes, so an endless file cannot fill the disk) into a root-only file.
    staged=$stage_dir/current
    partial=$dest/.partial-$name
    "$rm_bin" -f -- "$staged"
    IFS='|' read -r _ s_dev s_ino _ _ _ <<EOF
$pre
EOF
    run_copy_helper "$f" "$staged" "$s_dev" "$s_ino" "$s_size" "$s_mtime"
    helper_rc=$?
    step_rc=0
    post=$(meta_of "$f") || post=""
    stg_size=$(file_size "$staged") || stg_size=""
    stg_sha=$(sha_of_file "$staged" "$max_bytes") || stg_sha=""
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
        # Never overwrite and never delete. An existing copy must hold exactly the same bytes.
        tgt_sha=""
        if regular_file "$target"; then
            tgt_sha=$(sha_of_file "$target" "$max_bytes") || tgt_sha=""
        fi
        if [ -z "$tgt_sha" ] || [ "$tgt_sha" != "$stg_sha" ]; then
            step_rc=5
            log "existing copy of $name differs from the source; left untouched (move it aside by hand to re-copy)"
        else
            step_rc=-1
        fi
    else
        # Upload the staged copy to a fresh partial file: a leftover or planted partial name (a
        # symlink included) is removed as a name, never followed, and dd must create the new file
        # exclusively (conv=excl, O_EXCL) and without following.
        "$rm_bin" -f -- "$partial"
        if ! "$dd_bin" if="$staged" iflag=nofollow of="$partial" oflag=nofollow conv=excl bs=1M status=none; then
            step_rc=4
            log "upload of $name failed"
        else
            up_meta=$(meta_of "$partial") || up_meta=""
            IFS='|' read -r u_type u_dev u_ino u_nl u_size _ <<EOF
$up_meta
EOF
            dst_sha=$(sha_of_file "$partial" "$max_bytes") || dst_sha=""
            if [ "$u_type" != "regular file" ] || [ "$u_nl" != 1 ] || [ "$u_size" != "$s_size" ] || [ "$dst_sha" != "$stg_sha" ]; then
                step_rc=5
                log "verification of the uploaded $name failed (type, size or checksum); not published"
            elif ! "$touch_bin" -h -d "@$s_mtime" -- "$partial"; then
                # Keep the backup's own time: the age metric and the retention use it.
                step_rc=4
                log "could not set the time of the copy of $name"
            else
                fin_meta=$(meta_of "$partial") || fin_meta=""
                IFS='|' read -r f_type f_dev f_ino _ _ _ <<EOF
$fin_meta
EOF
                if [ "$f_type" != "regular file" ] || [ "$f_dev" != "$u_dev" ] || [ "$f_ino" != "$u_ino" ]; then
                    step_rc=5
                    log "the partial copy of $name was replaced during the upload; not published"
                elif ! "$mv_bin" -T -- "$partial" "$target"; then
                    step_rc=4
                    log "could not finalize the copy of $name"
                fi
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
        regular_file "$f" || continue
        t=$(file_mtime "$f") || { prune_rc=6; continue; }
        if [ "$t" -eq "$protect" ] || [ $((now - t)) -le "$limit" ]; then
            continue
        fi
        cand_dev=$(file_dev "$f") || cand_dev=""
        if [ "$cand_dev" != "$mp_dev" ]; then
            prune_rc=6
            log "prune candidate $name is on another device than the mount point; left alone"
            continue
        fi
        if [ "$dry_run" -eq 1 ]; then
            log "dry run: would remove $name (older than $retention_days days)"
        elif "$rm_bin" -f -- "$f"; then
            log "removed $name (older than $retention_days days)"
        else
            prune_rc=6
            log "could not remove $name"
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
