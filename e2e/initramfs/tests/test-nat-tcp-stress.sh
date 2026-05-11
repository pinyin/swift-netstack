#!/bin/sh
# Test: NAT TCP stress — multiple concurrency levels.
#
# Uses tcpstress (Go static binary) for fast concurrent connection setup.
# Each connection sends 256 bytes of identifiable data and expects exact echo.
# Runs multiple concurrency levels, each reported as a separate test result.
#
# Requires: nat_target and nat_tcp_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT TCP Stress (multi-concurrency) ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_TCP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_tcp_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_TCP_PORT" ]; then
    echo "  SKIP: nat_target or nat_tcp_port not in cmdline"
    return 0
fi

echo "  Target: $NAT_TARGET:$NAT_TCP_PORT"

# Concurrency levels: (connections, timeout_sec)
STRESS_LEVELS="100:15 200:20"

for level in $STRESS_LEVELS; do
    CONN="${level%%:*}"
    TO="${level##*:}"
    echo "  Starting ${CONN} concurrent connections (timeout ${TO}s)..."
    if /bin/tcpstress "$NAT_TARGET:$NAT_TCP_PORT" "$CONN" 256 "$TO"; then
        test_pass "nat-tcp-stress-${CONN}"
    else
        test_fail "nat-tcp-stress-${CONN}"
    fi
done
