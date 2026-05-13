#!/bin/bash
# Test: DHCP lease acquisition (Fedora / systemd-networkd edition).
#
# systemd-networkd has already attempted DHCP on eth0 before this runs.
# We verify that an IP address and default gateway were obtained.
#
# Replaces the busybox-specific udhcpc invocation in the original test.

. /tests/lib.sh

echo "--- DHCP Lease Acquisition ---"

MY_IP=$(get_my_ip)
GATEWAY=$(get_gateway)

if [ -n "$MY_IP" ] && [ -n "$GATEWAY" ]; then
    echo "  IP: $MY_IP  Gateway: $GATEWAY"
    test_pass "dhcp"
else
    echo "  IP: ${MY_IP:-none}  Gateway: ${GATEWAY:-none}"
    test_fail "dhcp"
fi
