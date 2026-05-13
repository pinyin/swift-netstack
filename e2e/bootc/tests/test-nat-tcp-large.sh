#!/bin/sh
# Test: TCP data transfer through NAT.
# Uses the same echo|nc pattern as the working basic test.
# Requires: nat_target and nat_tcp_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT TCP Data Transfer ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_TCP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_tcp_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_TCP_PORT" ]; then
    echo "  SKIP: nat_target or nat_tcp_port not in cmdline"
    return 0
fi

echo "  Target: $NAT_TARGET:$NAT_TCP_PORT"

# Allow previous test's connection cleanup to settle
sleep 1

ALL_PASS=1

# Test 1: Simple second connection (exact same pattern as basic test)
echo "  Test 1: simple second connection..."
RESULT=$(echo "second-connection-test" | nc -w 5 "$NAT_TARGET" "$NAT_TCP_PORT" 2>&1)
if echo "$RESULT" | grep -qF "second-connection-test"; then
    echo "    OK"
else
    echo "    FAIL (expected 'second-connection-test', got '${RESULT}')"
    ALL_PASS=0
fi

# Short sleep between connections
sleep 1

# Test 2: Simple third connection
echo "  Test 2: simple third connection..."
RESULT=$(echo "third-connection-test" | nc -w 5 "$NAT_TARGET" "$NAT_TCP_PORT" 2>&1)
if echo "$RESULT" | grep -qF "third-connection-test"; then
    echo "    OK"
else
    echo "    FAIL (expected 'third-connection-test', got '${RESULT}')"
    ALL_PASS=0
fi

sleep 1

# Test 3: Larger payload (~1KB)
echo "  Test 3: 1KB transfer..."
P1K="KILOBYTE_TEST_"
i=0; while [ $i -lt 100 ]; do P1K="${P1K}ABCDEFGHIJ"; i=$((i+1)); done
RESULT=$(echo "$P1K" | nc -w 10 "$NAT_TARGET" "$NAT_TCP_PORT" 2>&1)
if echo "$RESULT" | grep -qF "KILOBYTE_TEST_"; then
    echo "    OK"
else
    echo "    FAIL (recv empty or corrupt)"
    ALL_PASS=0
fi

if [ "$ALL_PASS" -eq 1 ]; then
    test_pass "nat-tcp-large"
else
    test_fail "nat-tcp-large"
fi
