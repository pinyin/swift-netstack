#!/bin/sh
# Test: NAT TCP large multi-segment transfer (stress).
#
# Runs the standard nc-based echo test 30 times in a loop with 10 KB
# data to surface intermittent race conditions.  Equivalent to running
# `iperf -l 10K -t 30` but using only in-VM busybox tools.
#
# Requires: nat_target and nat_tcp_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT TCP Large Multi-Segment Transfer ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_TCP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_tcp_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_TCP_PORT" ]; then
    echo "  SKIP: nat_target or nat_tcp_port not in cmdline"
    return 0
fi

echo "  Target: $NAT_TARGET:$NAT_TCP_PORT"

# Generate 10240 bytes once (12 + 10218 + 10) with start/end markers.
{
    printf "MARKER-START"
    dd if=/dev/zero bs=10218 count=1 2>/dev/null | tr '\0' 'A'
    printf "MARKER-END"
} > /tmp/large-in-10k.bin

IN_SIZE=$(wc -c < /tmp/large-in-10k.bin)

# Stress loop: 30 iterations.  Equivalent to `iperf -l 10K -P 1 -t 30`
# adapted for a busybox-only environment.
PASS=0
FAIL=0
echo "  Stress: $IN_SIZE bytes × 30 iterations..."
for i in $(seq 1 30); do
    nc -w 5 "$NAT_TARGET" "$NAT_TCP_PORT" < /tmp/large-in-10k.bin > /tmp/large-out-10k.bin 2>/dev/null
    OUT_SIZE=$(wc -c < /tmp/large-out-10k.bin 2>/dev/null || echo 0)

    if [ "$IN_SIZE" -ne "$OUT_SIZE" ]; then
        echo "  [#$i] size mismatch: sent=$IN_SIZE received=$OUT_SIZE"
        FAIL=$((FAIL + 1))
    elif ! cmp -s /tmp/large-in-10k.bin /tmp/large-out-10k.bin; then
        DIFF_BYTE=$(cmp -l /tmp/large-in-10k.bin /tmp/large-out-10k.bin 2>/dev/null | head -1)
        echo "  [#$i] data mismatch at: $DIFF_BYTE"
        FAIL=$((FAIL + 1))
    else
        PASS=$((PASS + 1))
    fi
done

echo "  Results: $PASS/$((PASS + FAIL)) passed"
if [ "$FAIL" -eq 0 ]; then
    test_pass "nat-tcp-large-multi-seg"
else
    test_fail "nat-tcp-large-multi-seg"
fi
