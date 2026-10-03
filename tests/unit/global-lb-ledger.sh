#!/bin/sh
# UD-005/006/007/010/011/016 v2-r2-20261003.
set -eu
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/global-lb-ledger.XXXXXX")
trap 'rm -f "$test_dir/test" "$test_dir/off.o"; rmdir "$test_dir"' EXIT HUP INT TERM
flags='-Iinclude -std=c99 -Wall -Wextra -Werror -g -O2'
if [ "${SANITIZE:-0}" = 1 ]; then
    flags="$flags -fsanitize=address,undefined -fno-omit-frame-pointer"
fi
${CC:-cc} $flags -DUSE_GLOBAL_LB src/global_lb_ledger.c src/global_lb_store.c \
    src/global_lb_resp.c tests/unit/global-lb-ledger.c \
    -Wl,--wrap=malloc -Wl,--wrap=calloc -o "$test_dir/test"
"$test_dir/test"
${CC:-cc} -Iinclude -c src/global_lb_ledger.c -o "$test_dir/off.o"
if nm "$test_dir/off.o" | grep -q glb_ledger; then
    echo 'FAIL: ledger symbols present with feature OFF'; exit 1
fi
echo 'PASS: ledger feature-OFF object has no symbols'
