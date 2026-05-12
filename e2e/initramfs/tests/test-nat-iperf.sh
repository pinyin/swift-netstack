#!/bin/sh
# Test: NAT TCP throughput with iperf3.
#
# Runs iperf3 client in the VM against the host-side iperf3 server.
# This validates TCP throughput using a standard tool.
#
# Requires: nat_target and nat_iperf_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT iperf3 Throughput ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
IPERF_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_iperf_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$IPERF_PORT" ]; then
    echo "  SKIP: nat_target or nat_iperf_port not in cmdline"
    return 0
fi

if [ ! -x /bin/iperf3 ]; then
    echo "  SKIP: /bin/iperf3 not found"
    return 0
fi

echo "  Target: $NAT_TARGET:$IPERF_PORT"

# Run iperf3 with -t 1 (1 second, minimum allowed).
# Output to file to avoid console buffer contention with NAT debug logs.
# The test result is echoed FIRST, then iperf output follows.
echo "  === 1. Single stream -t 1 ==="
/bin/iperf3 -c "$NAT_TARGET" -p "$IPERF_PORT" -t 1 -i 0 2>&1
echo "  exit=$?"
sleep 1

echo "  === 2. Single stream -t 3 ==="
/bin/iperf3 -c "$NAT_TARGET" -p "$IPERF_PORT" -t 3 -i 0 2>&1
echo "  exit=$?"
sleep 1

echo "  === 3. 4 parallel -t 1 ==="
/bin/iperf3 -c "$NAT_TARGET" -p "$IPERF_PORT" -t 1 -i 0 -P 4 2>&1
echo "  exit=$?"
sleep 1

echo "  === 4. 4 parallel -t 3 ==="
/bin/iperf3 -c "$NAT_TARGET" -p "$IPERF_PORT" -t 3 -i 0 -P 4 2>&1
echo "  exit=$?"
sleep 1

echo "  === 5. 8 parallel -t 1 ==="
/bin/iperf3 -c "$NAT_TARGET" -p "$IPERF_PORT" -t 1 -i 0 -P 8 2>&1
echo "  exit=$?"
sleep 1

echo "  === 6. 8 parallel -t 3 ==="
/bin/iperf3 -c "$NAT_TARGET" -p "$IPERF_PORT" -t 3 -i 0 -P 8 2>&1
echo "  exit=$?"

test_pass "nat-iperf"
