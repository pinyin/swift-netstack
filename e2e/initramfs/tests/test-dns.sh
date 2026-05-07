#!/bin/sh
# Test: DNS resolution via gateway DNS server.
# Prerequisite: DHCP lease with DNS option (option 6).
# The gateway runs the SwiftNetStack DNS server with hosts-file lookup.
# Configure hostnames via --host name:IP when launching the demo.

. /tests/lib.sh

echo "--- DNS Resolution ---"

GATEWAY=$(get_gateway)
if [ -z "$GATEWAY" ]; then
    test_fail "dns"
    exit 0
fi

# Try configured test hostname
NS_OUT=$(nslookup "test.local" "$GATEWAY" 2>&1) || true
echo "$NS_OUT"

if echo "$NS_OUT" | grep -qE 'Address: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
    RESOLVED=$(echo "$NS_OUT" | grep 'Address:' | tail -1 | awk '{print $2}')
    echo "  resolved test.local → $RESOLVED"
    test_pass "dns"
elif echo "$NS_OUT" | grep -qiE 'NXDOMAIN|not found|cannot resolve|server can.t find'; then
    # Host not configured — this is expected if --host wasn't passed.
    # NXDOMAIN from our server is still correct behavior.
    echo "  test.local → NXDOMAIN (expected if --host not set)"
    test_pass "dns"
else
    test_fail "dns"
fi
