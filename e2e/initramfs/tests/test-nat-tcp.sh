#!/bin/sh
# Test: Outbound TCP through NAT.
# Connects to the host echo server via NAT, sends data, verifies echo reply.
# Requires: nat_target and nat_tcp_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT TCP (outbound) ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_TCP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_tcp_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_TCP_PORT" ]; then
    echo "  SKIP: nat_target or nat_tcp_port not in cmdline"
    return 0
fi

echo "  Target: $NAT_TARGET:$NAT_TCP_PORT"
echo "  Sending TCP echo probe..."

RESULT=$(echo "hello-nat-tcp" | nc -w 5 "$NAT_TARGET" "$NAT_TCP_PORT" 2>&1)
case "$RESULT" in
    *"hello-nat-tcp"*)
        test_pass "nat-tcp"
        ;;
    *)
        echo "  Expected: hello-nat-tcp"
        echo "  Got:      $RESULT"
        test_fail "nat-tcp"
        ;;
esac
