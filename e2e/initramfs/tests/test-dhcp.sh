#!/bin/sh
# Test: DHCP lease acquisition.
# Prerequisite: eth0 is up.
# Verifies that udhcpc can obtain a lease from the BDP pipeline.

. /tests/lib.sh

echo "--- DHCP Lease Acquisition ---"

udhcpc -i eth0 -n -t 8 -T 2 2>&1
if [ $? -eq 0 ]; then
    test_pass "dhcp"
else
    test_fail "dhcp"
fi
