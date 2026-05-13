#!/bin/sh
# Test: NAT iperf3 throughput to external server (192.168.6.6).
#
# Validates TCP throughput against a real external server on the LAN,
# exercising the full NAT outbound path including external routing.

. /tests/lib.sh

echo "--- NAT External iperf3 ---"

EXT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^ext_target=' | cut -d= -f2)
EXT_IPERF_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^ext_iperf_port=' | cut -d= -f2)

if [ -z "$EXT_TARGET" ] || [ -z "$EXT_IPERF_PORT" ]; then
    echo "  SKIP: ext_target or ext_iperf_port not in cmdline"
    return 0
fi

if [ ! -x /bin/iperf3 ]; then
    echo "  SKIP: /bin/iperf3 not found"
    return 0
fi

echo "  Target: $EXT_TARGET:$EXT_IPERF_PORT"

echo "  === 1. 8 parallel -t 1 ==="
/bin/iperf3 -c "$EXT_TARGET" -p "$EXT_IPERF_PORT" -t 1 -i 0 -P 8 2>&1
RC1=$?
echo "  exit=$RC1"
sleep 1

echo "  === 2. 8 parallel -t 3 ==="
/bin/iperf3 -c "$EXT_TARGET" -p "$EXT_IPERF_PORT" -t 3 -i 0 -P 8 2>&1
RC2=$?
echo "  exit=$RC2"

if [ $RC1 -eq 0 ] && [ $RC2 -eq 0 ]; then
    test_pass "nat-external-iperf"
else
    echo "  One or more iperf3 runs failed: rc1=$RC1 rc2=$RC2"
    test_fail "nat-external-iperf"
fi
