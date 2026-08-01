#!/bin/sh
set -eu

for command in losetup dmsetup mkfs.ext4 mount umount; do
    command -v "$command" >/dev/null
done
if [ -z "${VOT_STRICT_TEST_BIN:-}" ]; then
    command -v cargo >/dev/null
fi

if [ "$(id -u)" -eq 0 ]; then
    privilege=""
else
    sudo -n true
    privilege="sudo -n"
fi

work=$(mktemp -d)
name="vot-strict-$$"
mount_point="$work/mount"
image="$work/device.img"
loop=""
mounted=0
mapped=0

cleanup() {
    if [ "$mounted" -eq 1 ]; then
        $privilege umount "$mount_point" || true
    fi
    if [ "$mapped" -eq 1 ]; then
        $privilege dmsetup remove "$name" || true
    fi
    if [ -n "$loop" ]; then
        $privilege losetup -d "$loop" || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

mkdir "$mount_point"
truncate -s 128M "$image"
loop=$($privilege losetup --find --show "$image")
sectors=$($privilege blockdev --getsz "$loop")
echo "0 $sectors flakey $loop 0 3600 1" | $privilege dmsetup create "$name"
mapped=1
$privilege dmsetup mknodes "$name" || true
mapper="/dev/mapper/$name"
if [ ! -b "$mapper" ]; then
    device_number=$($privilege dmsetup info -c --noheadings -o major,minor "$name" | tr -d ' ')
    major=${device_number%,*}
    minor=${device_number#*,}
    $privilege mkdir -p /dev/mapper
    $privilege mknod "$mapper" b "$major" "$minor"
fi
$privilege mkfs.ext4 -q "$mapper"
$privilege mount -t ext4 "$mapper" "$mount_point"
mounted=1
$privilege chown "$(id -u):$(id -g)" "$mount_point"

payload="$mount_point/payload"
dd if=/dev/zero of="$payload" bs=4096 count=1 status=none
sync

# Populate the page cache while the mapping is healthy. Then make dm-flakey
# corrupt the first byte of every read bio during an immediate down interval.
dd if="$payload" of=/dev/null bs=4096 count=1 status=none
$privilege dmsetup suspend "$name"
echo "0 $sectors flakey $loop 0 1 3600 5 corrupt_bio_byte 1 r 1 0" | \
    $privilege dmsetup reload "$name"
$privilege dmsetup resume "$name"
sleep 2

if [ -n "${VOT_STRICT_TEST_BIN:-}" ]; then
    VOT_STORAGE_RUNNER=1 VOT_STRICT_TEST_FILE="$payload" \
        "$VOT_STRICT_TEST_BIN" \
        direct_read_detects_corruption_hidden_by_buffered_cache --ignored --exact
else
    VOT_STORAGE_RUNNER=1 VOT_STRICT_TEST_FILE="$payload" \
        cargo test -p vot-commit-strict --test backing_corruption \
        direct_read_detects_corruption_hidden_by_buffered_cache -- --ignored --exact
fi
