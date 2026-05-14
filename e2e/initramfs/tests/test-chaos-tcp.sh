#!/bin/sh
# Test: TCP correctness under chaos from external server.
#
# Chaos (tc netem) is applied on the external server (192.168.6.6), NOT on
# the guest. Runs TCP echo, large transfer, and sequential connection tests
# against the external echo server to verify data integrity under packet
# loss + reordering + duplication.
#
# Requires: ext_target, ext_tcp_echo_port in kernel cmdline.

. /tests/lib.sh

echo "--- Chaos TCP (external) ---"

EXT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^ext_target=' | cut -d= -f2)
EXT_TCP_ECHO_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^ext_tcp_echo_port=' | cut -d= -f2)

LOSS=$(cat /proc/cmdline | tr ' ' '\n' | grep '^chaos_loss=' | cut -d= -f2)
REORDER=$(cat /proc/cmdline | tr ' ' '\n' | grep '^chaos_reorder=' | cut -d= -f2)
DUP=$(cat /proc/cmdline | tr ' ' '\n' | grep '^chaos_dup=' | cut -d= -f2)

LOSS=${LOSS:-5}
REORDER=${REORDER:-10}
DUP=${DUP:-3}

if [ -z "$EXT_TARGET" ] || [ -z "$EXT_TCP_ECHO_PORT" ]; then
    echo "[TEST] chaos-tcp SKIP (ext_target or ext_tcp_echo_port not in cmdline)"
    return 0
fi

echo "  Target: $EXT_TARGET:$EXT_TCP_ECHO_PORT"
echo "  Chaos (on external server): loss=${LOSS}% reorder=${REORDER}% dup=${DUP}%"

CHAOS_PASSED=0
CHAOS_FAILED=0

# ── Test 1: Basic TCP echo under chaos ──
echo "  === 1. TCP echo under chaos ==="
PAYLOAD="chaos-test-$(head -c 8 /dev/urandom | base64 2>/dev/null || echo 'xyz')"
RESULT=$(echo "$PAYLOAD" | nc -w 15 "$EXT_TARGET" "$EXT_TCP_ECHO_PORT" 2>&1)
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
echo "  === 2. Large (64KB) binary transfer under chaos ==="
dd if=/dev/urandom of=/tmp/chaos-large.bin bs=1024 count=64 2>/dev/null
CHECKSUM_SRC=$(md5sum /tmp/chaos-large.bin 2>/dev/null | cut -d' ' -f1)
SRC_SIZE=$(wc -c < /tmp/chaos-large.bin 2>/dev/null)

nc -w 45 "$EXT_TARGET" "$EXT_TCP_ECHO_PORT" < /tmp/chaos-large.bin > /tmp/chaos-recv.bin 2>&1
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
echo "  === 3. Full-buffer (4096B) echo under chaos ==="
dd if=/dev/urandom of=/tmp/chaos-buf4k.bin bs=4096 count=1 2>/dev/null
SRC_HASH=$(sha256sum /tmp/chaos-buf4k.bin 2>/dev/null | cut -d' ' -f1)
SRC_SIZE=$(wc -c < /tmp/chaos-buf4k.bin 2>/dev/null)
nc -w 25 "$EXT_TARGET" "$EXT_TCP_ECHO_PORT" < /tmp/chaos-buf4k.bin > /tmp/chaos-buf4k-recv.bin 2>&1
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
    RESULT=$(echo "seq-$i" | nc -w 10 "$EXT_TARGET" "$EXT_TCP_ECHO_PORT" 2>&1)
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

# ── Report ──
TOTAL=$((CHAOS_PASSED + CHAOS_FAILED))
if [ $CHAOS_FAILED -eq 0 ] && [ $TOTAL -gt 0 ]; then
    test_pass "chaos-tcp"
else
    test_fail "chaos-tcp"
fi
