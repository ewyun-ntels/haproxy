#!/bin/sh
set -eu
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/global-lb-endpoint.XXXXXX")
trap 'rm -f "$test_dir/test" "$test_dir/snapshot.o"; rmdir "$test_dir"' EXIT HUP INT TERM
flags='-Iinclude -DUSE_GLOBAL_LB -ffunction-sections -fdata-sections -Wno-address-of-packed-member -g -O1'
${CC:-cc} $flags -c src/global_lb.c -o "$test_dir/snapshot.o"
if [ "${SANITIZE:-0}" = 1 ]; then
    flags="$flags -fsanitize=address,undefined -fno-omit-frame-pointer"
fi
${CC:-cc} $flags tests/unit/global-lb-endpoint.c "$test_dir/snapshot.o" -Wl,--gc-sections -o "$test_dir/test"
"$test_dir/test"
