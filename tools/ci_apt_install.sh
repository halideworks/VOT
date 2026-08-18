#!/bin/sh
set -eu

test "$#" -gt 0

# Hosted-runner mirrors occasionally accept a connection and stop answering.
# Bound both apt phases; Acquire retries transient failures inside that bound.
sudo timeout --kill-after=10s 180s apt-get \
  -o Acquire::Retries=3 \
  -o Acquire::http::Timeout=20 \
  -o Acquire::https::Timeout=20 \
  update
sudo timeout --kill-after=10s 180s apt-get \
  -o Acquire::Retries=3 \
  -o Acquire::http::Timeout=20 \
  -o Acquire::https::Timeout=20 \
  -o DPkg::Lock::Timeout=60 \
  install -y "$@"
