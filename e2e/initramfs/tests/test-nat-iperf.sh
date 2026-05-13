#!/bin/sh
# Test: NAT TCP throughput with iperf3.
#
# Runs iperf3 client in the VM against the host-side iperf3 server.
# Uses --json output for data integrity verification:
# a non-zero bits_per_second confirms data actually traversed the NAT.
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

FAIL=0

run_iperf() {
    local label="$1" duration="$2"
    echo "  === ${label}: 8 parallel x ${duration}s ==="
    local json
    json=$(/bin/iperf3 -c "$NAT_TARGET" -p "$IPERF_PORT" -t "$duration" -P 8 --json 2>&1)
    local rc=$?

    if [ $rc -ne 0 ]; then
        echo "  iperf3 exit=$rc (connection/execution failure)"
        FAIL=1
        return
    fi

    # Integrity check: verify actual data traversed the NAT.
    # grep for bits_per_second matching [1-9] confirms non-zero throughput.
    if echo "$json" | grep -q '"bits_per_second":[1-9]'; then
        local bps
        bps=$(echo "$json" | grep -o '"bits_per_second":[0-9.]*' | tail -1 | cut -d: -f2)
        local gbps
        gbps=$(awk "BEGIN { printf \"%.2f\", $bps / 1000000000 }" 2>/dev/null || echo "N/A")
        echo "  Throughput: ${gbps} Gbits/sec  exit=$rc"
    else
        echo "  INTEGRITY FAIL: zero throughput (no data transferred through NAT)"
        FAIL=1
    fi
}

run_iperf "1" 1
sleep 1
run_iperf "2" 3

if [ $FAIL -eq 0 ]; then
    test_pass "nat-iperf"
else
    test_fail "nat-iperf"
fi
