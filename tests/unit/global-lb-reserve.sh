#!/bin/sh
# UD-007/009/011 v2-r1-20261003. Uses only disposable Docker test stores.
set -eu
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/global-lb-reserve.XXXXXX")
trap 'rm -f "$test_dir/test" "$test_dir/off.o"; rmdir "$test_dir"' EXIT HUP INT TERM
python3 dev/global-lb/embed-reserve.py --check
flags='-Iinclude -std=c99 -Wall -Wextra -Werror -g -O2'
if [ "${SANITIZE:-0}" = 1 ]; then
    flags="$flags -fsanitize=address,undefined -fno-omit-frame-pointer"
fi
${CC:-cc} $flags -DUSE_GLOBAL_LB src/global_lb_reserve.c src/global_lb_store.c \
    src/global_lb_resp.c tests/unit/global-lb-reserve.c \
    -Wl,--wrap=malloc -Wl,--wrap=calloc -o "$test_dir/test"
"$test_dir/test"
${CC:-cc} -Iinclude -c src/global_lb_reserve.c -o "$test_dir/off.o"
if nm "$test_dir/off.o" | grep -q global_lb_reserve; then
    echo 'FAIL: v2 symbols present with feature OFF'; exit 1
fi
echo 'PASS: v2 feature-OFF object has no reservation symbols'
if [ -n "${STORE_TEST_IMAGE:-}" ]; then
    python3 tests/unit/global-lb-reserve.py "$test_dir/test" "$STORE_TEST_IMAGE"
fi
