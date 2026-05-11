#!/bin/sh
# Test: NAT TCP 100 concurrent connections with binary payload.
#
# Uses tcpstress (Go static binary) for fast concurrent connection setup.
# Each connection sends 256 bytes of identifiable data and expects exact echo.
#
# Requires: nat_target and nat_tcp_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT TCP 100 Concurrent Connections ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_TCP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_tcp_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_TCP_PORT" ]; then
    echo "  SKIP: nat_target or nat_tcp_port not in cmdline"
    return 0
fi

echo "  Target: $NAT_TARGET:$NAT_TCP_PORT"
echo "  Starting 100 concurrent connections..."

/bin/tcpstress "$NAT_TARGET:$NAT_TCP_PORT" 100 256 15

if [ $? -eq 0 ]; then
    test_pass "nat-tcp-stress-100"
else
    test_fail "nat-tcp-stress-100"
fi
