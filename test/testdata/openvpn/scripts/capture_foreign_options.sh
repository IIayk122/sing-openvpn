#!/bin/sh
set -eu

output=/interop/logs/client-foreign.env
temporary="$output.tmp"
env | LC_ALL=C sort | grep '^foreign_option_' > "$temporary" || true
mv "$temporary" "$output"
