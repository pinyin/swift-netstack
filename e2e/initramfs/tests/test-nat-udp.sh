#!/bin/sh
# Test: Outbound UDP through NAT.
# Sends a UDP datagram to the host echo server via NAT, verifies echo reply.
# Requires: nat_target and nat_udp_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT UDP (outbound) ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_UDP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_udp_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_UDP_PORT" ]; then
    echo "  SKIP: nat_target or nat_udp_port not in cmdline"
    return 0
fi

echo "  Target: $NAT_TARGET:$NAT_UDP_PORT"
echo "  Sending UDP echo probe..."

RESULT=$(echo "hello-nat-udp" | nc -u -w 5 "$NAT_TARGET" "$NAT_UDP_PORT" 2>&1)
case "$RESULT" in
    *"hello-nat-udp"*)
        test_pass "nat-udp"
        ;;
    *)
        echo "  Expected: hello-nat-udp"
        echo "  Got:      $RESULT"
        test_fail "nat-udp"
        ;;
esac
