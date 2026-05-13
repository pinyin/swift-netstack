#!/bin/sh
# Test: NAT TCP with server closing first (external EOF → VM FIN).
#
# The server sends a greeting then immediately closes the connection.
# The NAT must propagate the external EOF to the VM via handleStreamHangup
# and handleTCPExternalFIN.  The VM sees data followed by EOF.
#
# Requires: nat_target and nat_tcp_close_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT TCP Server-Close-First ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_TCP_CLOSE_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_tcp_close_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_TCP_CLOSE_PORT" ]; then
    echo "  SKIP: nat_target or nat_tcp_close_port not in cmdline"
    return 0
fi

echo "  Target: $NAT_TARGET:$NAT_TCP_CLOSE_PORT"
echo "  Connecting to close-first server..."

RESULT=$(timeout 6 nc -w 5 "$NAT_TARGET" "$NAT_TCP_CLOSE_PORT" 2>&1)

if echo "$RESULT" | grep -q "HELLO-FROM-SERVER"; then
    echo "  Received greeting: OK"
    test_pass "nat-tcp-server-close"
else
    echo "  Expected: HELLO-FROM-SERVER"
    echo "  Got:      $RESULT"
    test_fail "nat-tcp-server-close"
fi
