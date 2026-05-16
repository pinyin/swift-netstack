#!/bin/sh
# Test: NAT TCP throughput with iperf3 (bidirectional).
#
# Upload: VM client → host server (northbound, guest-as-client scenario).
# Download: VM client ← host server with -R (southbound, guest-as-server
# or download-heavy scenario). Host runs a single iperf3 server (-s).
#
# Requires: nat_target and nat_iperf_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT iperf3 Throughput (bidirectional) ---"

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
    local label="$1" duration="$2" reverse="$3"
    local extra=""
    [ "$reverse" = "receive" ] && extra="-R"
    echo "  === ${label}: 8p x ${duration}s ==="

    local json
    json=$(/bin/iperf3 -c "$NAT_TARGET" -p "$IPERF_PORT" -t "$duration" -P 8 $extra --json 2>/dev/null)
    local rc=$?

    if [ $rc -ne 0 ]; then
        echo "  iperf3 exit=$rc"
        FAIL=1
        return
    fi

    # Extract bits_per_second from the side that actually sent data.
    # Without -R: sender is the VM (sum_sent). With -R: sender is the host
    # (sum_received by VM). Try sent first, then received.
    local bps
    bps=$(echo "$json" | grep -o '"bits_per_second":[[:space:]]*[0-9.e+]*' | tail -1 | sed 's/.*:[[:space:]]*//')
    if [ -z "$bps" ] || [ "$bps" = "0" ] || [ "$bps" = "0.0" ]; then
        # Fallback: try sum_received path (json nested, grep picks last)
        bps=$(echo "$json" | grep -o '"bits_per_second":[[:space:]]*[0-9.e+]*' | head -1 | sed 's/.*:[[:space:]]*//')
    fi
    if [ -z "$bps" ] || [ "$bps" = "0" ] || [ "$bps" = "0.0" ]; then
        echo "  INTEGRITY FAIL: zero throughput (bps=$bps)"
        FAIL=1
        return
    fi

    local gbps
    gbps=$(awk "BEGIN { printf \"%.2f\", $bps / 1000000000 }" 2>/dev/null || echo "N/A")
    echo "  Throughput: ${gbps} Gbits/sec  exit=$rc"
}

# Upload (VM→host): VM sends, host receives. Northbound heavy.
run_iperf "upload"   1 "send"
sleep 1
run_iperf "upload"   3 "send"
sleep 1
# Download (host→VM): host sends, VM receives via -R. Southbound heavy.
run_iperf "download" 1 "receive"
sleep 1
run_iperf "download" 3 "receive"

if [ $FAIL -eq 0 ]; then
    test_pass "nat-iperf"
else
    test_fail "nat-iperf"
fi
