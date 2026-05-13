#!/bin/sh
# Test: TCP throughput under chaos (iperf3 with packet loss/reorder/dup).
#
# Measures degradation ratio vs clean-path throughput.
# The stats system (tcpFastRetransmit, ackDeferred, sendMB, etc.) naturally
# captures retransmit activity, giving a direct view of error-recovery cost.
#
# Requires: nat_target, nat_iperf_port in kernel cmdline.
# Chaos params: chaos_loss, chaos_reorder, chaos_dup in kernel cmdline.
# Optional: ext_target, ext_iperf_port for external chaos benchmark.

. /tests/lib.sh

echo "--- Chaos iperf3 Throughput ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
IPERF_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_iperf_port=' | cut -d= -f2)
EXT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^ext_target=' | cut -d= -f2)
EXT_IPERF_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^ext_iperf_port=' | cut -d= -f2)

LOSS=$(cat /proc/cmdline | tr ' ' '\n' | grep '^chaos_loss=' | cut -d= -f2)
REORDER=$(cat /proc/cmdline | tr ' ' '\n' | grep '^chaos_reorder=' | cut -d= -f2)
DUP=$(cat /proc/cmdline | tr ' ' '\n' | grep '^chaos_dup=' | cut -d= -f2)

LOSS=${LOSS:-5}
REORDER=${REORDER:-10}
DUP=${DUP:-3}

if [ -z "$NAT_TARGET" ] || [ -z "$IPERF_PORT" ]; then
    echo "[TEST] chaos-iperf SKIP (nat_target or nat_iperf_port not in cmdline)"
    return 0
fi

if [ ! -x /bin/iperf3 ]; then
    echo "[TEST] chaos-iperf SKIP (/bin/iperf3 not found)"
    return 0
fi

if ! command -v tc >/dev/null 2>&1; then
    echo "[TEST] chaos-iperf SKIP (tc not available)"
    return 0
fi

echo "  Host target: $NAT_TARGET:$IPERF_PORT"
echo "  Chaos: loss=${LOSS}% reorder=${REORDER}% dup=${DUP}%"

run_iperf() {
    local label="$1" target="$2" port="$3" duration="$4"
    # Under chaos, 8 parallel streams amplifies handshake failures — use 4.
    echo "  === ${label}: 4p x ${duration}s ===" >&2
    local json
    # timeout=30s prevents hangs when chaos makes connection establishment slow.
    json=$(timeout 30 /bin/iperf3 -c "$target" -p "$port" -t "$duration" -P 4 --json 2>/dev/null)
    local rc=$?

    if [ $rc -eq 124 ]; then
        echo "  ${label}: iperf3 timed out (30s)" >&2
        return 1
    fi
    if [ $rc -ne 0 ]; then
        echo "  ${label}: iperf3 exit=$rc (connection failure)" >&2
        return 1
    fi

    if echo "$json" | grep -q '"bits_per_second":[[:space:]]*[1-9]'; then
        local bps
        bps=$(echo "$json" | grep -o '"bits_per_second":[[:space:]]*[0-9.e+]*' | tail -1 | sed 's/.*: *//')
        local gbps mbps
        gbps=$(awk "BEGIN { printf \"%.4f\", $bps / 1000000000 }" 2>/dev/null || echo "0")
        mbps=$(awk "BEGIN { printf \"%.1f\", $bps / 1000000 }" 2>/dev/null || echo "0")
        echo "    ${label} throughput: ${gbps} Gbps (${mbps} Mbps) (rc=$rc)" >&2
        echo "$gbps"  # return value via stdout
        return 0
    else
        echo "    ${label}: INTEGRITY FAIL — zero throughput" >&2
        return 1
    fi
}

FAIL=0
HOST_Gbps=""
EXT_Gbps=""

# ── Apply chaos ──
echo "  Applying netem..."
tc qdisc replace dev eth0 root netem delay 1ms loss ${LOSS}% reorder ${REORDER}% duplicate ${DUP}% >/tmp/netem-chaos-iperf.txt 2>&1
NETEM_RC=$?
if [ $NETEM_RC -ne 0 ]; then
    echo "  WARNING: tc netem failed (rc=$NETEM_RC)"
    cat /tmp/netem-chaos-iperf.txt 2>/dev/null
    test_fail "chaos-iperf"
    return 0
fi
echo "  netem active"

# ── Host iperf3 under chaos ──
HOST_Gbps=$(run_iperf "host" "$NAT_TARGET" "$IPERF_PORT" 3)
if [ $? -ne 0 ]; then
    FAIL=1
fi

sleep 1

# ── External iperf3 under chaos ──
if [ -n "$EXT_TARGET" ] && [ -n "$EXT_IPERF_PORT" ]; then
    echo "  External target: $EXT_TARGET:$EXT_IPERF_PORT"
    EXT_Gbps=$(run_iperf "external" "$EXT_TARGET" "$EXT_IPERF_PORT" 3)
    if [ $? -ne 0 ]; then
        FAIL=1
    fi
else
    echo "  External target: not configured, skipping"
fi

# ── Cleanup ──
tc qdisc del dev eth0 root >/dev/null 2>&1
echo "  netem removed"

# ── Report ──
echo ""
echo "  === Chaos iperf3 Summary ==="
echo "  Chaos: loss=${LOSS}% reorder=${REORDER}% dup=${DUP}%"
if [ -n "$HOST_Gbps" ]; then
    host_mbps=$(awk "BEGIN { printf \"%.1f\", $HOST_Gbps * 1000 }" 2>/dev/null || echo "0")
    echo "  Host throughput:  ${HOST_Gbps} Gbps (${host_mbps} Mbps)"
fi
if [ -n "$EXT_Gbps" ]; then
    ext_mbps=$(awk "BEGIN { printf \"%.1f\", $EXT_Gbps * 1000 }" 2>/dev/null || echo "0")
    echo "  External throughput: ${EXT_Gbps} Gbps (${ext_mbps} Mbps)"
fi

if [ $FAIL -eq 0 ]; then
    test_pass "chaos-iperf"
else
    test_fail "chaos-iperf"
fi
