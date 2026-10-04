#!/bin/sh
# UD-007/010/011 v2-r1-20261003. V2 timers and rejected v1 directives.
set -eu
haproxy=$1
mode=${2:-on}
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/global-lb-config-v2.XXXXXX")
trap 'rm -f "$test_dir/test.cfg" "$test_dir/output"; rmdir "$test_dir"' EXIT HUP INT TERM
count=0
base=' global-lb state-store 127.0.0.1:6379
 global-lb instance-id test-v2/ha-0'
check() {
    expected=$1; pattern=$2; settings=$3
    printf 'global\n%s\ndefaults\n mode tcp\n timeout connect 1s\n timeout client 1s\n timeout server 1s\nfrontend fe\n bind 127.0.0.1:18080\n default_backend be\nbackend be\n balance roundrobin\n server s1 127.0.0.1:18081\n' "$settings" > "$test_dir/test.cfg"
    if "$haproxy" -c -f "$test_dir/test.cfg" > "$test_dir/output" 2>&1; then actual=pass; else actual=fail; fi
    if [ "$expected" != "$actual" ] || { [ -n "$pattern" ] && ! grep -Fq "$pattern" "$test_dir/output"; }; then
        cat "$test_dir/test.cfg" "$test_dir/output"; exit 1
    fi
    count=$((count+1))
}
if [ "$mode" = off ]; then
    check fail "unknown keyword 'global-lb'" "$base
 global-lb timeout reserve 100ms"
else
    for setting in max-instances max-requests; do
        check pass '' "$base
 global-lb $setting 16"
        for value in 0 -1 1.5 2147483648 18446744073709551617 10junk; do
            check fail 'integer' "$base
 global-lb $setting $value"
        done
        check fail 'already specified' "$base
 global-lb $setting 16
 global-lb $setting 32"
        check fail 'unexpected argument' "$base
 global-lb $setting 16 extra"
        check fail 'was removed with v1' "$base
 global-lb $setting 16
 global-lb sync-interval 300ms"
    done
    check fail 'integer' "$base
 global-lb max-instances 524288"
    check pass '' "$base
 global-lb timeout reserve 100ms
 global-lb heartbeat-interval 300ms
 global-lb instance-timeout 3s"
    for setting in 'timeout reserve' heartbeat-interval instance-timeout; do
        check pass '' "$base
 global-lb $setting 1s"
        # heartbeat=1s remains below default instance timeout; instance=1s
        # remains above default heartbeat. Reserve is an independent deadline.
        for value in 0 -1 1.5s 2147483648ms 18446744073709551617ms 10msjunk; do
            check fail 'duration' "$base
 global-lb $setting $value"
        done
        check fail 'already specified' "$base
 global-lb $setting 1s
 global-lb $setting 2s"
        check fail 'unexpected argument' "$base
 global-lb $setting 1s extra"
    done
    for legacy in 'sync-interval 300ms' 'snapshot-ttl 3s' 'stale-after 3s' 'recovery-successes 3'; do
        check fail 'was removed with v1' "$base
 global-lb timeout reserve 100ms
 global-lb $legacy"
        check fail 'was removed with v1' "$base
 global-lb $legacy
 global-lb heartbeat-interval 300ms"
    done
    for value in 1ms 300ms; do
        check fail 'must exceed' "$base
 global-lb instance-timeout $value"
    done
    check fail 'both' ' global-lb heartbeat-interval 300ms'
fi
printf 'PASS: %s v2 configuration checks (%s)\n' "$count" "$mode"
