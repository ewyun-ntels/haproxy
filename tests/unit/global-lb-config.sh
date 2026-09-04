#!/bin/sh
# UD-007 r3-config-parser-20260904; USE_GLOBAL_LB configuration regression.
# Usage: sh tests/unit/global-lb-config.sh /absolute/path/to/haproxy on|off
set -eu
haproxy=$1
mode=${2:-on}
case "$mode" in on|off) ;; *) exit 2 ;; esac
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/global-lb-config.XXXXXX")
trap 'rm -f "$test_dir/test.cfg" "$test_dir/output"; rmdir "$test_dir"' EXIT HUP INT TERM
count=0

check() {
    expected=$1
    pattern=$2
    global_lines=$3
    printf 'global\n%s\ndefaults\n mode tcp\n timeout connect 1s\n timeout client 1s\n timeout server 1s\nfrontend fe\n bind 127.0.0.1:18080\n default_backend be\nbackend be\n balance roundrobin\n server s1 127.0.0.1:18081\n' "$global_lines" > "$test_dir/test.cfg"
    if "$haproxy" -c -f "$test_dir/test.cfg" > "$test_dir/output" 2>&1; then
        actual=pass
    else
        actual=fail
    fi
    if [ "$expected" != "$actual" ] || { [ -n "$pattern" ] && ! grep -Fq "$pattern" "$test_dir/output"; }; then
        printf 'FAIL case %s: expected %s (%s), got %s\n' "$count" "$expected" "$pattern" "$actual"
        cat "$test_dir/test.cfg" "$test_dir/output"
        exit 1
    fi
    count=$((count + 1))
}

base=' global-lb state-store 127.0.0.1:6379
 global-lb instance-id cluster-a/haproxy-0'
check pass '' ''
if grep -Fq 'global-lb:' "$test_dir/output"; then
    echo 'FAIL: legacy configuration must not emit Global LB diagnostics'
    exit 1
fi
if [ "$mode" = off ]; then
    check fail "unknown keyword 'global-lb'" "$base"
    printf 'PASS: %s Global LB feature-OFF checks\n' "$count"
    exit 0
fi
check pass 'configuration only' "$base"
check pass 'configuration only' "$base
 global-lb key-prefix test:pool
 global-lb sync-interval 300ms
 global-lb timeout connect 200ms
 global-lb timeout command 100ms
 global-lb reconnect 100ms 5s
 global-lb reconnect-jitter 20
 global-lb snapshot-ttl 3s
 global-lb stale-after 3s
 global-lb recovery-successes 3"

# Default sync is 300ms (not 100ms): the 200ms TTL must be rejected.
check fail 'must exceed' "$base
 global-lb snapshot-ttl 200ms"
check pass 'configuration only' "$base
 global-lb sync-interval 100ms
 global-lb snapshot-ttl 200ms
 global-lb stale-after 200ms"
check fail 'both' ' global-lb state-store 127.0.0.1:6379'
check fail 'both' ' global-lb instance-id cluster-a/haproxy-0'
check fail 'both' ' global-lb sync-interval 300ms'
check fail 'expects' ' global-lb'
check fail 'expects' ' global-lb timeout'
check fail 'expects' "$base
 global-lb timeout connect"
check fail 'expects' "$base
 global-lb reconnect 100ms"
check fail 'expects' "$base
 global-lb auth secret"
check fail 'expects' "$base
 global-lb tls on"

for setting in 'sync-interval' 'timeout connect' 'timeout command' 'snapshot-ttl' 'stale-after'; do
    for value in 0 -1 1.5s 2147483648ms 2147483647001us 18446744073709551617ms 999999999999999999999999s abc 10xs 10msjunk; do
        check fail 'duration' "$base
 global-lb $setting $value"
    done
    check fail 'already specified' "$base
 global-lb $setting 500ms
 global-lb $setting 600ms"
    check fail 'cannot handle unexpected argument' "$base
 global-lb $setting 500ms extra"
done
check pass 'configuration only' "$base
 global-lb sync-interval 1us"
check pass 'configuration only' "$base
 global-lb timeout command 2147483647ms"
check pass 'configuration only' "$base
 global-lb timeout command 2147483647000us"
for value in 0 -1 1x 1.5 2147483648 9999999999999999999999; do
    check fail 'expects an integer' "$base
 global-lb recovery-successes $value"
done
for value in -1 101 20% 1x 999999999999999999999; do
    check fail 'expects an integer' "$base
 global-lb reconnect-jitter $value"
done
for value in 0 100; do
    check pass 'configuration only' "$base
 global-lb reconnect-jitter $value"
done
check fail 'initial delay' "$base
 global-lb reconnect 5s 100ms"
check fail 'duration' "$base
 global-lb reconnect 0 5s"
check fail 'duration' "$base
 global-lb reconnect 100ms 0"
check fail 'must exceed' "$base
 global-lb sync-interval 3s"
check fail 'must exceed' "$base
 global-lb stale-after 300ms"

for endpoint in '127.0.0.1:1' '127.0.0.1:65535' '[::1]:6379' '[2001:db8::1]:6379' 'store.example.invalid:6379' 'store.example.invalid.:6379'; do
    check pass 'configuration only' " global-lb state-store $endpoint
 global-lb instance-id test"
done
for endpoint in '127.0.0.1' '127.0.0.1:0' '127.0.0.1:65536' '127.0.0.1:4294973675' '127.0.0.1:+6379' '127.0.0.1:1-2' ':6379' '*:6379' '::1:6379' '[::1]' '[::1]:6379x' '[bad]:6379' '[::1]junk:6379' '999.0.0.1:6379' 'redis://localhost:6379' '/tmp/store.sock' 'fd@1' 'bad..host:6379' '-bad.host:6379'; do
    check fail 'expects host:port' " global-lb state-store $endpoint
 global-lb instance-id test"
done
for setting in 'state-store 127.0.0.1:6380' 'instance-id test'; do
    check fail 'already specified' "$base
 global-lb $setting"
done
check fail 'already specified' "$base
global
 global-lb instance-id test"
check fail 'already specified' "$base
 global-lb key-prefix a
 global-lb key-prefix b"
check fail 'already specified' "$base
 global-lb reconnect 100ms 5s
 global-lb reconnect 100ms 5s"
for setting in key-prefix instance-id; do
    check fail 'empty' " global-lb state-store 127.0.0.1:6379
 global-lb $setting \"\""
    check fail 'printable ASCII' " global-lb state-store 127.0.0.1:6379
 global-lb $setting \"two words\""
done
HAPROXY_INSTANCE_ID=cluster-a/haproxy-7
export HAPROXY_INSTANCE_ID
check pass 'configuration only' ' global-lb state-store 127.0.0.1:6379
 global-lb instance-id "$HAPROXY_INSTANCE_ID"'
unset HAPROXY_INSTANCE_ID
check fail 'empty' ' global-lb state-store 127.0.0.1:6379
 global-lb instance-id "$HAPROXY_INSTANCE_ID"'
check fail 'global-lb' "$base
backend wrong_section
 global-lb sync-interval 300ms"
if "$haproxy" -vv | grep -Fq '+GLOBAL_LEASTCONN'; then
    check pass 'native local leastconn' "$base
backend opted_in
 mode tcp
 balance global-leastconn
 global-lb fallback leastconn"
    check fail 'expects no arguments' "$base
backend bad
 balance global-leastconn extra"
    check fail 'requires global state-store' 'backend missing
 balance global-leastconn'
    check fail 'requires mode tcp' "$base
backend bad
 mode http
 balance global-leastconn"
    check fail 'equal server weights' "$base
backend bad
 balance global-leastconn
 server a 127.0.0.1:1234 weight 1
 server b 127.0.0.1:1235 weight 2"
    check fail 'fallback leastconn' "$base
backend bad
 balance global-leastconn
 global-lb fallback roundrobin"
else
    check fail 'balance only supports' "$base
backend not_enabled
 balance global-leastconn"
fi
printf 'PASS: %s Global LB feature-ON checks\n' "$count"
