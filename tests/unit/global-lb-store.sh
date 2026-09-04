#!/bin/sh
# UD-007 r5-store-protocol-20260904 / UD-011 r3-sequenced-store-20260904.
# Run from source root. Unit tests have no network access.
# STORE_TEST_IMAGE=valkey/valkey:9.1.1-alpine enables an isolated Docker test.
# STORE_TEST_IMAGE=redis:7.2-alpine runs the same tests against Redis.
set -eu
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/global-lb-store.XXXXXX")
trap 'rm -f "$test_dir/test" "$test_dir/off.o"; rmdir "$test_dir"' EXIT HUP INT TERM
flags='-Iinclude -std=c99 -Wall -Wextra -Werror -g -O2'
if [ "${SANITIZE:-0}" = 1 ]; then
    flags="$flags -fsanitize=address,undefined -fno-omit-frame-pointer"
fi
${CC:-cc} $flags -DUSE_GLOBAL_LB src/global_lb_store.c src/global_lb_resp.c \
    tests/unit/global-lb-store.c -Wl,--wrap=malloc -Wl,--wrap=calloc -o "$test_dir/test"
"$test_dir/test"
${CC:-cc} -Iinclude -c src/global_lb_store.c -o "$test_dir/off.o"
if nm "$test_dir/off.o" | grep -q global_lb_store; then
    echo 'FAIL: store symbols present with feature OFF'
    exit 1
fi
echo 'PASS: store feature-OFF object has no protocol symbols'
if [ -n "${STORE_TEST_IMAGE:-}" ]; then
    python3 tests/unit/global-lb-store.py "$test_dir/test" "$STORE_TEST_IMAGE"
fi
