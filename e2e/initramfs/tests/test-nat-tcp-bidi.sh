#!/bin/sh
# Test: NAT TCP bidirectional data flow.
#
# Connects to a bidi server that sends bulk data (2048 'S' bytes) AFTER
# receiving only a trigger line — while the client is still sending its
# payload.  Verifies the NAT correctly handles overlapping data flows in
# both directions (sendQueue + externalSendQueue) on a single connection.
#
# Protocol:
#   1. Client sends TRIGGER\n + 512 bytes of payload
#   2. Server reads trigger, sends 2048 'S' (while client still sending)
#   3. Server reads remaining client data, echoes back with ECHO: prefix
#   4. Client reads everything and verifies structure
#
# Requires: nat_target and nat_tcp_bidi_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT TCP Bidirectional ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_BIDI_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_tcp_bidi_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_BIDI_PORT" ]; then
    echo "  SKIP: nat_target or nat_tcp_bidi_port not in cmdline"
    return 0
fi

echo "  Target: $NAT_TARGET:$NAT_BIDI_PORT"

# Build request: trigger line + 512 bytes of 'C'
printf "TRIGGER\n" > /tmp/bidi-req.bin
dd if=/dev/zero bs=512 count=1 2>/dev/null | tr '\0' 'C' >> /tmp/bidi-req.bin

echo "  Sending trigger + 512 bytes, reading bidi response..."

nc -w 10 "$NAT_TARGET" "$NAT_BIDI_PORT" < /tmp/bidi-req.bin > /tmp/bidi-resp.bin 2>/dev/null
BIDI_SIZE=$(wc -c < /tmp/bidi-resp.bin)

# Expected: 2048 'S' + 5 ("ECHO:") + 512 'C' = 2565 bytes minimum
# Check for 'S' block and ECHO prefix separately
S_COUNT=$(head -c 2048 /tmp/bidi-resp.bin | tr -dc 'S' | wc -c)
HAS_ECHO=$(grep -c "ECHO:" /tmp/bidi-resp.bin 2>/dev/null || echo 0)

echo "  Response size: $BIDI_SIZE bytes"
echo "  S-block count: $S_COUNT (expected 2048)"
echo "  ECHO prefix:   $([ "$HAS_ECHO" -gt 0 ] && echo yes || echo no)"

if [ "$BIDI_SIZE" -ge 2560 ] && [ "$S_COUNT" -ge 2000 ] && [ "$HAS_ECHO" -gt 0 ]; then
    test_pass "nat-tcp-bidi"
else
    echo "  FAIL: bidi data flow incomplete or corrupted"
    test_fail "nat-tcp-bidi"
fi
