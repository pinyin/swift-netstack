#!/bin/sh
# Test: NAT TCP 50 concurrent connections.
#
# Exercises connection tracking under load. Each connection sends a unique
# payload and expects an exact echo.  Verifies the NAT doesn't drop, corrupt,
# or misroute data under moderate concurrency.
#
# Requires: nat_target and nat_tcp_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT TCP 50 Concurrent Connections ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_TCP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_tcp_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_TCP_PORT" ]; then
    echo "  SKIP: nat_target or nat_tcp_port not in cmdline"
    return 0
fi

echo "  Target: $NAT_TARGET:$NAT_TCP_PORT"
echo "  Starting 50 concurrent connections..."

CONCURRENT=50
PIDS=""
FAILS=0
TIMEOUT=15

# Start all connections in background, each with a unique payload
i=1
while [ $i -le $CONCURRENT ]; do
    PAYLOAD="conn-$i-$(printf '%04d' $i)"
    echo "$PAYLOAD" | nc -w $TIMEOUT "$NAT_TARGET" "$NAT_TCP_PORT" > "/tmp/concurrent-50-$i.out" 2>/dev/null &
    PIDS="$PIDS $!"
    i=$((i + 1))
done

# Wait for all background nc processes
for pid in $PIDS; do
    wait $pid 2>/dev/null || true
done

# Verify every response matches its payload
i=1
while [ $i -le $CONCURRENT ]; do
    EXPECTED="conn-$i-$(printf '%04d' $i)"
    if [ -f "/tmp/concurrent-50-$i.out" ]; then
        RESULT=$(cat "/tmp/concurrent-50-$i.out" 2>/dev/null)
        if [ "$RESULT" = "$EXPECTED" ]; then
            :  # OK
        else
            echo "  Mismatch conn $i: expected='$EXPECTED' got='$RESULT'"
            FAILS=$((FAILS + 1))
        fi
    else
        echo "  Missing output for conn $i"
        FAILS=$((FAILS + 1))
    fi
    i=$((i + 1))
done

echo "  Verified: $((CONCURRENT - FAILS))/$CONCURRENT correct"

if [ $FAILS -eq 0 ]; then
    test_pass "nat-tcp-concurrent-50"
else
    test_fail "nat-tcp-concurrent-50"
fi
