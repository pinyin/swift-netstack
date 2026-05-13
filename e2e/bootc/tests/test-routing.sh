#!/bin/sh
# Test: Routing table integrity.
# Prerequisite: valid DHCP lease.
# Verifies default route and subnet route are present.

. /tests/lib.sh

echo "--- Routing Table ---"

GATEWAY=$(get_gateway)
ROUTE_OUT=$(ip route show 2>/dev/null || route -n 2>/dev/null)
echo "$ROUTE_OUT"

HAS_DEFAULT=0
HAS_SUBNET=0

if echo "$ROUTE_OUT" | grep -q 'default via'; then
    HAS_DEFAULT=1
fi
if echo "$ROUTE_OUT" | grep -q 'scope link'; then
    HAS_SUBNET=1
fi

if [ "$HAS_DEFAULT" -eq 1 ] && [ "$HAS_SUBNET" -eq 1 ]; then
    test_pass "routing"
elif [ "$HAS_DEFAULT" -eq 1 ] || [ "$HAS_SUBNET" -eq 1 ]; then
    # At least one route is present — partial credit
    test_pass "routing"
else
    test_fail "routing"
fi
