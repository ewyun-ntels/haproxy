#!/bin/sh
# UD-007 r4-resp2-codec-20260904. Run from the source root; no network access.
set -eu
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/global-lb-resp.XXXXXX")
trap 'rm -f "$test_dir/test" "$test_dir/off.o"; rmdir "$test_dir"' EXIT HUP INT TERM
flags='-Iinclude -std=c99 -Wall -Wextra -Werror -g -O2'
if [ "${SANITIZE:-0}" = 1 ]; then
    flags="$flags -fsanitize=address,undefined -fno-omit-frame-pointer"
fi
${CC:-cc} $flags -DUSE_GLOBAL_LB src/global_lb_resp.c tests/unit/global-lb-resp.c \
    -Wl,--wrap=malloc -Wl,--wrap=realloc -o "$test_dir/test"
"$test_dir/test"
${CC:-cc} -Iinclude -c src/global_lb_resp.c -o "$test_dir/off.o"
if nm "$test_dir/off.o" | grep -q global_lb_resp; then
    echo 'FAIL: RESP2 symbols present with feature OFF'
    exit 1
fi
echo 'PASS: RESP2 feature-OFF object has no codec symbols'
