#!/bin/sh
# UD-008 r2-global-cache-20260908. Run from the source root; no network.
set -eu
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/global-lb-collect.XXXXXX")
trap 'rm -f "$test_dir/test" "$test_dir/off.o"; rmdir "$test_dir"' EXIT HUP INT TERM
flags='-Iinclude -std=gnu99 -Wall -Wextra -Werror -Wno-unused-parameter -g -O2 -DUSE_GLOBAL_LB -DUSE_GLOBAL_LEASTCONN'
if [ "${SANITIZE:-0}" = 1 ]; then
    flags="$flags -fsanitize=address,undefined -fno-omit-frame-pointer"
fi
${CC:-cc} $flags src/global_lb_resp.c src/global_lb_store.c src/global_lb_collect.c \
    tests/unit/global-lb-collect.c -o "$test_dir/test"
"$test_dir/test"
${CC:-cc} -Iinclude -c src/global_lb_collect.c -o "$test_dir/off.o"
if nm "$test_dir/off.o" | grep -q global_lb_collect; then
    echo 'FAIL: collector symbols present with feature OFF'
    exit 1
fi
echo 'PASS: USE_GLOBAL_LEASTCONN-OFF object has no collector/cache symbols'
