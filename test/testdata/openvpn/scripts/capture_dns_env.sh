#!/bin/sh
set -eu

output=/interop/logs/client-dns.env
temporary="$output.tmp"
env | LC_ALL=C sort | grep '^dns_' > "$temporary"
mv "$temporary" "$output"
