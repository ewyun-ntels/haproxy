#!/bin/sh
# UD-007 r3-config-parser-20260904; compile/test parser internals in isolation.
# Run from the source root. Set SANITIZE=1 to enable ASan/UBSan.
set -eu
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/global-lb-unit.XXXXXX")
trap 'rm -f "$test_dir/tools.o" "$test_dir/cfgparse.o" "$test_dir/test"; rmdir "$test_dir"' EXIT HUP INT TERM
flags='-Iinclude -DUSE_GLOBAL_LB -ffunction-sections -fdata-sections -Wno-address-of-packed-member -g -O1'
testflags=$flags
if [ "${SANITIZE:-0}" = 1 ]; then
    # Instrument the included Global LB parser, not unrelated HAProxy globals
    # whose sanitizer registration would prevent support-code section GC.
    testflags="$testflags -fsanitize=address,undefined -fno-omit-frame-pointer"
fi
${CC:-cc} $flags -c src/tools.c -o "$test_dir/tools.o"
${CC:-cc} $flags -c src/cfgparse.c -o "$test_dir/cfgparse.o"
${CC:-cc} $testflags tests/unit/global-lb-config.c "$test_dir/tools.o" "$test_dir/cfgparse.o" -Wl,--gc-sections -o "$test_dir/test"
"$test_dir/test"
