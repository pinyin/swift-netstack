#!/bin/sh
# Test: Concurrent TCP connections through NAT.
# Launches 3 simultaneous echo connections, verifies each gets its own data back.
# Requires: nat_target and nat_tcp_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT TCP Concurrent Connections ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_TCP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_tcp_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_TCP_PORT" ]; then
    echo "  SKIP: nat_target or nat_tcp_port not in cmdline"
    return 0
fi

echo "  Target: $NAT_TARGET:$NAT_TCP_PORT"

# Allow previous test's connection cleanup to settle
sleep 1

echo "  Starting 3 concurrent connections..."

echo "concurrent-1-marker-data" | nc -w 5 "$NAT_TARGET" "$NAT_TCP_PORT" > /tmp/tcp-conc-out1 &
PID1=$!
echo "concurrent-2-marker-data" | nc -w 5 "$NAT_TARGET" "$NAT_TCP_PORT" > /tmp/tcp-conc-out2 &
PID2=$!
echo "concurrent-3-marker-data" | nc -w 5 "$NAT_TARGET" "$NAT_TCP_PORT" > /tmp/tcp-conc-out3 &
PID3=$!

wait $PID1 $PID2 $PID3

FAILS=0
for i in 1 2 3; do
    if grep -q "concurrent-${i}-marker-data" "/tmp/tcp-conc-out${i}"; then
        echo "  Connection $i: OK"
    else
        echo "  Connection $i: FAIL (got: $(cat /tmp/tcp-conc-out${i}))"
        FAILS=$((FAILS + 1))
    fi
done

if [ "$FAILS" -eq 0 ]; then
    test_pass "nat-tcp-concurrent"
else
    echo "  $FAILS connection(s) failed"
    test_fail "nat-tcp-concurrent"
fi
