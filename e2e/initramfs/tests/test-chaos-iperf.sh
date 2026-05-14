#!/bin/sh
# Test: TCP throughput under chaos from external server.
#
# Chaos (tc netem) is applied on the external server (192.168.6.6), NOT on
# the guest. This tests netstack's lossless link mode on the southbound path
# (external→netstack→guest) where netstack's own TCP state machine manages
# retransmission and cwnd.
#
# Uses iperf3 reverse mode (-R) so the external server sends data to the
# guest — exercising the southbound path where lossless link mode matters.
# Also tests regular mode for northbound baseline.
#
# Requires: ext_target, ext_iperf_port in kernel cmdline.

. /tests/lib.sh

echo "--- Chaos iperf3 Throughput (external) ---"

EXT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^ext_target=' | cut -d= -f2)
EXT_IPERF_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^ext_iperf_port=' | cut -d= -f2)

LOSS=$(cat /proc/cmdline | tr ' ' '\n' | grep '^chaos_loss=' | cut -d= -f2)
REORDER=$(cat /proc/cmdline | tr ' ' '\n' | grep '^chaos_reorder=' | cut -d= -f2)
DUP=$(cat /proc/cmdline | tr ' ' '\n' | grep '^chaos_dup=' | cut -d= -f2)

LOSS=${LOSS:-5}
REORDER=${REORDER:-10}
DUP=${DUP:-3}

if [ -z "$EXT_TARGET" ] || [ -z "$EXT_IPERF_PORT" ]; then
    echo "[TEST] chaos-iperf SKIP (ext_target or ext_iperf_port not in cmdline)"
    return 0
fi

if [ ! -x /bin/iperf3 ]; then
    echo "[TEST] chaos-iperf SKIP (/bin/iperf3 not found)"
    return 0
fi

echo "  External target: $EXT_TARGET:$EXT_IPERF_PORT"
echo "  Chaos (applied on external server): loss=${LOSS}% reorder=${REORDER}% dup=${DUP}%"

run_iperf() {
    local label="$1" target="$2" port="$3" duration="$4" reverse="$5"
    local rflag=""
    if [ "$reverse" = "reverse" ]; then
        rflag="-R"
        echo "  === ${label} (reverse, 4p x ${duration}s) ===" >&2
    else
        echo "  === ${label} (regular, 4p x ${duration}s) ===" >&2
    fi
    local json
    json=$(timeout 30 /bin/iperf3 -c "$target" -p "$port" -t "$duration" -P 4 $rflag --json 2>/dev/null)
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
REG_Gbps=""
REV_Gbps=""

sleep 1

# ── Regular mode (guest→external, northbound) ──
REG_Gbps=$(run_iperf "northbound" "$EXT_TARGET" "$EXT_IPERF_PORT" 3 "regular")
if [ $? -ne 0 ]; then
    FAIL=1
fi

sleep 1

# ── Reverse mode (external→guest, southbound, netstack TCP) ──
REV_Gbps=$(run_iperf "southbound" "$EXT_TARGET" "$EXT_IPERF_PORT" 3 "reverse")
if [ $? -ne 0 ]; then
    FAIL=1
fi

# ── Report ──
echo ""
echo "  === Chaos iperf3 Summary ==="
echo "  Chaos (on $EXT_TARGET): loss=${LOSS}% reorder=${REORDER}% dup=${DUP}%"
if [ -n "$REG_Gbps" ]; then
    reg_mbps=$(awk "BEGIN { printf \"%.1f\", $REG_Gbps * 1000 }" 2>/dev/null || echo "0")
    echo "  Northbound (guest→external): ${REG_Gbps} Gbps (${reg_mbps} Mbps)"
fi
if [ -n "$REV_Gbps" ]; then
    rev_mbps=$(awk "BEGIN { printf \"%.1f\", $REV_Gbps * 1000 }" 2>/dev/null || echo "0")
    echo "  Southbound (external→guest): ${REV_Gbps} Gbps (${rev_mbps} Mbps)"
fi

if [ $FAIL -eq 0 ]; then
    test_pass "chaos-iperf"
else
    test_fail "chaos-iperf"
fi
