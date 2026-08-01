#!/bin/sh
set -eu

root=${VOT_BENCH_ROOT:?VOT_BENCH_ROOT must name the storage filesystem under test}
mkdir -p "$root"
fs_type=$(findmnt -T "$root" -n -o FSTYPE)
case "$fs_type" in
    overlay|tmpfs)
        echo "storage benchmark refuses $fs_type at $root" >&2
        exit 1
        ;;
esac

echo "storage filesystem: $fs_type"
cargo run --release --locked -p vot-commit-posix \
    --example measure_balanced -- 256 7
