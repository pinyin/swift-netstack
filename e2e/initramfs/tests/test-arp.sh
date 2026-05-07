#!/bin/sh
# Test: ARP table population.
# Prerequisite: ICMP test completed (ARP entry should be cached).
# Verifies the gateway MAC was resolved via proxy ARP.

. /tests/lib.sh

echo "--- ARP Resolution ---"

GATEWAY=$(get_gateway)
if [ -z "$GATEWAY" ]; then
    test_fail "arp"
    exit 0
fi

ARP_OUT=$(arp -a 2>/dev/null || ip neigh show 2>/dev/null || cat /proc/net/arp 2>/dev/null)
echo "$ARP_OUT"

if echo "$ARP_OUT" | grep -q "$GATEWAY"; then
    test_pass "arp"
else
    test_fail "arp"
fi
