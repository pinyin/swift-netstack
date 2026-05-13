#!/bin/sh
# Test: TCP correctness under chaos (packet loss + reordering + duplication).
#
# Uses netem-set (minimal netlink tool) to inject controlled network chaos,
# then runs TCP echo, large transfer, and concurrent connection tests to
# verify data integrity.
#
# Requires: nat_target, nat_tcp_port in kernel cmdline.
# Chaos params: chaos_loss, chaos_reorder, chaos_dup in kernel cmdline.

. /tests/lib.sh

echo "--- Chaos TCP ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_TCP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_tcp_port=' | cut -d= -f2)

LOSS=$(cat /proc/cmdline | tr ' ' '\n' | grep '^chaos_loss=' | cut -d= -f2)
REORDER=$(cat /proc/cmdline | tr ' ' '\n' | grep '^chaos_reorder=' | cut -d= -f2)
DUP=$(cat /proc/cmdline | tr ' ' '\n' | grep '^chaos_dup=' | cut -d= -f2)

LOSS=${LOSS:-5}
REORDER=${REORDER:-10}
DUP=${DUP:-3}

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_TCP_PORT" ]; then
    echo "  SKIP: nat_target or nat_tcp_port not in cmdline"
    return 0
fi

if ! command -v netem-set >/dev/null 2>&1; then
    echo "  SKIP: netem-set not available"
    return 0
fi

echo "  Target: $NAT_TARGET:$NAT_TCP_PORT"
echo "  Chaos: loss=${LOSS}% reorder=${REORDER}% dup=${DUP}%"

# Apply chaos qdisc
echo "  Applying netem..."
netem-set eth0 "$LOSS" "$REORDER" "$DUP" >/tmp/netem-out.txt 2>&1
NETEM_RC=$?
if [ $NETEM_RC -eq 0 ]; then
    echo "  netem applied on eth0"
else
    echo "  WARNING: netem-set failed (rc=$NETEM_RC)"
    cat /tmp/netem-out.txt 2>/dev/null
    test_fail "chaos-tcp-netem"
    return 0
fi

CHAOS_PASSED=0
CHAOS_FAILED=0

# ── Test 1: Basic TCP echo under chaos ──
echo "  === 1. TCP echo under chaos ==="
PAYLOAD="chaos-test-$(head -c 8 /dev/urandom | base64 2>/dev/null || echo 'xyz')"
RESULT=$(echo "$PAYLOAD" | nc -w 10 "$NAT_TARGET" "$NAT_TCP_PORT" 2>&1)
case "$RESULT" in
    *"$PAYLOAD"*)
        echo "    echo OK: data matched"
        CHAOS_PASSED=$((CHAOS_PASSED + 1))
        ;;
    *)
        echo "    echo FAIL: expected '$PAYLOAD', got '$RESULT'"
        CHAOS_FAILED=$((CHAOS_FAILED + 1))
        ;;
esac

# ── Test 2: Large (64KB) binary transfer under chaos ──
# Uses TCP echo port (reads until EOF, echoes everything back).
echo "  === 2. Large (64KB) binary transfer under chaos ==="
dd if=/dev/urandom of=/tmp/chaos-large.bin bs=1024 count=64 2>/dev/null
CHECKSUM_SRC=$(md5sum /tmp/chaos-large.bin 2>/dev/null | cut -d' ' -f1)
SRC_SIZE=$(wc -c < /tmp/chaos-large.bin 2>/dev/null)

nc -w 30 "$NAT_TARGET" "$NAT_TCP_PORT" < /tmp/chaos-large.bin > /tmp/chaos-recv.bin 2>&1
RC=$?
CHECKSUM_RECV=$(md5sum /tmp/chaos-recv.bin 2>/dev/null | cut -d' ' -f1)
RECV_SIZE=$(wc -c < /tmp/chaos-recv.bin 2>/dev/null)

if [ "$CHECKSUM_SRC" = "$CHECKSUM_RECV" ] && [ "$SRC_SIZE" = "$RECV_SIZE" ]; then
    echo "    large OK: ${SRC_SIZE}B, md5=$CHECKSUM_SRC"
    CHAOS_PASSED=$((CHAOS_PASSED + 1))
else
    echo "    large FAIL: src=${SRC_SIZE}B md5=$CHECKSUM_SRC, recv=${RECV_SIZE}B md5=$CHECKSUM_RECV (nc_rc=$RC)"
    CHAOS_FAILED=$((CHAOS_FAILED + 1))
fi

# ── Test 3: Full-buffer (4096B) echo under chaos ──
# Use sha256sum comparison instead of diff (more reliable with busybox nc)
echo "  === 3. Full-buffer (4096B) echo under chaos ==="
dd if=/dev/urandom of=/tmp/chaos-buf4k.bin bs=4096 count=1 2>/dev/null
SRC_HASH=$(sha256sum /tmp/chaos-buf4k.bin 2>/dev/null | cut -d' ' -f1)
SRC_SIZE=$(wc -c < /tmp/chaos-buf4k.bin 2>/dev/null)
nc -w 15 "$NAT_TARGET" "$NAT_TCP_PORT" < /tmp/chaos-buf4k.bin > /tmp/chaos-buf4k-recv.bin 2>&1
RECV_HASH=$(sha256sum /tmp/chaos-buf4k-recv.bin 2>/dev/null | cut -d' ' -f1)
RECV_SIZE=$(wc -c < /tmp/chaos-buf4k-recv.bin 2>/dev/null)
if [ "$SRC_SIZE" = "$RECV_SIZE" ] && [ "$SRC_HASH" = "$RECV_HASH" ]; then
    echo "    buffer OK: ${SRC_SIZE}B sha256=$SRC_HASH"
    CHAOS_PASSED=$((CHAOS_PASSED + 1))
else
    echo "    buffer FAIL: src=${SRC_SIZE}B sha256=$SRC_HASH, recv=${RECV_SIZE}B sha256=$RECV_HASH"
    CHAOS_FAILED=$((CHAOS_FAILED + 1))
fi

# ── Test 4: Multiple sequential connections under chaos ──
echo "  === 4. Sequential connections under chaos ==="
SEQ_FAILED=0
for i in $(seq 1 10); do
    RESULT=$(echo "seq-$i" | nc -w 5 "$NAT_TARGET" "$NAT_TCP_PORT" 2>&1)
    case "$RESULT" in
        *"seq-$i"*) ;;
        *) SEQ_FAILED=$((SEQ_FAILED + 1)) ;;
    esac
done
if [ $SEQ_FAILED -eq 0 ]; then
    echo "    sequential OK: 10/10 connections"
    CHAOS_PASSED=$((CHAOS_PASSED + 1))
else
    echo "    sequential FAIL: $SEQ_FAILED/10 connections"
    CHAOS_FAILED=$((CHAOS_FAILED + 1))
fi

# ── Cleanup ──
netem-set eth0 del >/dev/null 2>&1
echo "  netem removed"

# ── Report ──
TOTAL=$((CHAOS_PASSED + CHAOS_FAILED))
if [ $CHAOS_FAILED -eq 0 ] && [ $TOTAL -gt 0 ]; then
    test_pass "chaos-tcp"
else
    test_fail "chaos-tcp"
fi
