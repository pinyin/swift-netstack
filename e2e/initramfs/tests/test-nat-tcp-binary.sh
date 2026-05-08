#!/bin/sh
# Test: Data integrity through TCP NAT using known text patterns.
# Requires: nat_target and nat_tcp_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT TCP Data Integrity ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_TCP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_tcp_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_TCP_PORT" ]; then
    echo "  SKIP: nat_target or nat_tcp_port not in cmdline"
    return 0
fi

echo "  Target: $NAT_TARGET:$NAT_TCP_PORT"

# Allow previous test's connection cleanup to settle
sleep 1

# Build a known text payload with a unique marker
MARKER="BINARY_INTEGRITY_$(date +%s 2>/dev/null || echo 'STATIC')"
# Build ~1KB payload
PAYLOAD="${MARKER}_START_"
i=0; while [ $i -lt 80 ]; do PAYLOAD="${PAYLOAD}0123456789ABCDEF"; i=$((i+1)); done
PAYLOAD="${PAYLOAD}_${MARKER}_END"

sleep 1

RESULT=$(echo "$PAYLOAD" | nc -w 10 "$NAT_TARGET" "$NAT_TCP_PORT" 2>&1)

if [ "$PAYLOAD" = "$RESULT" ]; then
    test_pass "nat-tcp-binary"
else
    SENT_LEN=$(printf '%s' "$PAYLOAD" | wc -c)
    RECV_LEN=$(printf '%s' "$RESULT" | wc -c)
    echo "  Sent: $SENT_LEN B, Recv: $RECV_LEN B"
    if echo "$RESULT" | grep -qF "$MARKER"; then
        echo "  Marker found but data mismatch (newline/whitespace issue?)"
    fi
    test_fail "nat-tcp-binary"
fi
