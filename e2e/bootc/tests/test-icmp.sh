#!/bin/sh
# Test: ICMP Echo to gateway.
# Prerequisite: valid DHCP lease and default route.
# Verifies L2 (ARP) + L3 (IP forwarding) + L4 (ICMP reply).

. /tests/lib.sh

echo "--- ICMP Echo (ping gateway) ---"

GATEWAY=$(get_gateway)
if [ -z "$GATEWAY" ]; then
    test_fail "icmp"
    exit 0
fi

PING_OUT=$(ping -c 3 -W 2 "$GATEWAY" 2>&1) || true
echo "$PING_OUT"

if echo "$PING_OUT" | grep -qE '[1-3] packets transmitted, [1-3].*received'; then
    test_pass "icmp"
else
    test_fail "icmp"
fi
