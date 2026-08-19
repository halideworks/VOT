#!/bin/sh
set -eu

test "$#" -gt 0

missing=
for package do
  if ! dpkg-query -W -f='${db:Status-Abbrev}\n' "$package" 2>/dev/null \
    | grep -q '^ii '
  then
    missing="$missing $package"
  fi
done
test -n "$missing" || exit 0

# Hosted-runner mirrors occasionally accept a connection and stop answering.
# Skip apt entirely when the image already has every package. Otherwise bound
# the index refresh, then retry short installs so partial downloads survive a
# stalled mirror instead of one attempt spending the whole job's useful time.
sudo timeout --kill-after=10s 180s apt-get \
  -o Acquire::Retries=3 \
  -o Acquire::http::Timeout=20 \
  -o Acquire::https::Timeout=20 \
  update
for attempt in 1 2 3; do
  # Package names are fixed workflow inputs; intentional splitting drops the
  # empty prefix and hands apt only the packages absent from this image.
  # shellcheck disable=SC2086
  if sudo timeout --kill-after=10s 180s apt-get \
    -o Acquire::Retries=0 \
    -o Acquire::http::Timeout=20 \
    -o Acquire::https::Timeout=20 \
    -o DPkg::Lock::Timeout=60 \
    install -y --no-install-recommends $missing
  then
    exit 0
  fi
  test "$attempt" -lt 3 || exit 1
done
