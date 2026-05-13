#!/bin/sh
# Test: NAT iperf3 throughput to external server (192.168.6.6).
#
# Validates TCP throughput against a real external server on the LAN,
# exercising the full NAT outbound path including external routing.
# Uses --json output for data integrity verification.
#
# Requires: ext_target and ext_iperf_port in kernel cmdline.

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

FAIL=0

run_ext_iperf() {
    local label="$1" duration="$2"
    echo "  === ${label}: 8 parallel x ${duration}s ==="
    local json
    json=$(/bin/iperf3 -c "$EXT_TARGET" -p "$EXT_IPERF_PORT" -t "$duration" -P 8 --json 2>/dev/null)
    local rc=$?

    if [ $rc -ne 0 ]; then
        echo "  iperf3 exit=$rc (connection/execution failure)"
        FAIL=1
        return
    fi

    # Integrity check: verify actual data traversed the NAT.
    if echo "$json" | grep -q '"bits_per_second":[[:space:]]*[1-9]'; then
        local bps
        bps=$(echo "$json" | grep -o '"bits_per_second":[[:space:]]*[0-9.e+]*' | tail -1 | sed 's/.*: *//')
        local gbps
        gbps=$(awk "BEGIN { printf \"%.2f\", $bps / 1000000000 }" 2>/dev/null || echo "N/A")
        echo "  Throughput: ${gbps} Gbits/sec  exit=$rc"
    else
        echo "  INTEGRITY FAIL: zero throughput (no data transferred through NAT)"
        FAIL=1
    fi
}

run_ext_iperf "1" 1
sleep 1
run_ext_iperf "2" 3

if [ $FAIL -eq 0 ]; then
    test_pass "nat-external-iperf"
else
    test_fail "nat-external-iperf"
fi
