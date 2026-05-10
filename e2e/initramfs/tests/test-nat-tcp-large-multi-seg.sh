#!/bin/sh
# Test: NAT TCP large multi-segment transfer.
#
# Sends 10 KB through the echo server. At 1400-byte MSS this spans ~8
# TCP segments, exercising sendBuf/sendQueue draining across multiple
# flushTCPOutgoing rounds and verifying correct sequence-number tracking
# and reassembly.
#
# Requires: nat_target and nat_tcp_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT TCP Large Multi-Segment Transfer ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_TCP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_tcp_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_TCP_PORT" ]; then
    echo "  SKIP: nat_target or nat_tcp_port not in cmdline"
    return 0
fi

echo "  Target: $NAT_TARGET:$NAT_TCP_PORT"

# Generate exactly 10240 bytes (12 + 10218 + 10) with start/end markers.
# Build as a single pipeline to avoid dd conv=notrunc compatibility issues.
{
    printf "MARKER-START"
    dd if=/dev/zero bs=10218 count=1 2>/dev/null | tr '\0' 'A'
    printf "MARKER-END"
} > /tmp/large-in-10k.bin

IN_SIZE=$(wc -c < /tmp/large-in-10k.bin)
echo "  Sending $IN_SIZE bytes..."

nc -w 30 "$NAT_TARGET" "$NAT_TCP_PORT" < /tmp/large-in-10k.bin > /tmp/large-out-10k.bin 2>/dev/null
OUT_SIZE=$(wc -c < /tmp/large-out-10k.bin)

echo "  Received $OUT_SIZE bytes"

if [ "$IN_SIZE" -ne "$OUT_SIZE" ]; then
    echo "  FAIL: size mismatch: sent=$IN_SIZE received=$OUT_SIZE"
    test_fail "nat-tcp-large-multi-seg"
    return 0
fi

# Verify data integrity via cmp
if cmp -s /tmp/large-in-10k.bin /tmp/large-out-10k.bin; then
    echo "  Data integrity: OK"
    test_pass "nat-tcp-large-multi-seg"
else
    # Show first difference
    DIFF_BYTE=$(cmp -l /tmp/large-in-10k.bin /tmp/large-out-10k.bin 2>/dev/null | head -1)
    echo "  FAIL: data mismatch at: $DIFF_BYTE"
    test_fail "nat-tcp-large-multi-seg"
fi
