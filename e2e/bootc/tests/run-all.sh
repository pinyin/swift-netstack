#!/bin/bash
# SwiftNetStack E2E test suite entry point (Fedora/bootc edition).
# Runs after systemd-networkd has configured eth0 via DHCP.
#
# Outputs [TEST] <name> PASS/FAIL markers consumed by e2e/run.sh.

set -e

# Wait for systemd-networkd to acquire a DHCP lease on eth0
echo "Waiting for eth0 DHCP lease..."
for i in $(seq 1 30); do
    if ip addr show eth0 2>/dev/null | grep -q 'inet '; then
        echo "eth0 has IP: $(ip -4 addr show eth0 | grep inet | awk '{print $2}')"
        break
    fi
    sleep 1
done

echo "Routes:"
ip route show
echo "DNS:"
cat /etc/resolv.conf 2>/dev/null || true

echo ""
echo "=== SwiftNetStack E2E Test Suite ==="
echo ""

# Shared state
TESTS_PASSED=""
TESTS_FAILED=""
TEST_COUNT=0
. /tests/lib.sh

# Run tests in dependency order.
# dhcp must run first (validates IP/gateway); remainder depend on it.
TESTS="dhcp icmp arp dns routing nat-udp nat-tcp nat-tcp-large nat-tcp-mss nat-tcp-rst nat-tcp-bidi nat-tcp-concurrent nat-tcp-stress-200 nat-tcp-close-first nat-udp-stress nat-iperf nat-internet nat-external-iperf nat-external-http chaos-tcp"

for t in $TESTS; do
    TEST_SCRIPT="/tests/test-${t}.sh"
    if [ -f "$TEST_SCRIPT" ]; then
        set +e; . "$TEST_SCRIPT"; set -e
    else
        echo "[TEST] $t SKIP (not found)"
    fi
    echo ""
done

# Summary
. /tests/lib.sh
test_summary

echo ""
echo "=== Test suite complete, powering off ==="
systemctl poweroff
