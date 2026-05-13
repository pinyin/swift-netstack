#!/bin/sh
# Test: NAT TCP connection refused.
#
# Connects to a port where nothing is listening.  The NAT's connect()
# fails with ECONNREFUSED and must clean up without crashing, leaking fds,
# or leaving stale entries.  A follow-up echo test verifies the NAT is
# still functional.
#
# Requires: nat_target and nat_tcp_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT TCP Connection Refused ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_TCP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_tcp_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_TCP_PORT" ]; then
    echo "  SKIP: nat_target or nat_tcp_port not in cmdline"
    return 0
fi

# Pick a port that definitely has no listener (19999)
DEAD_PORT=19999

echo "  Connecting to $NAT_TARGET:$DEAD_PORT (expecting refusal)..."
echo "test" | timeout 5 nc -w 3 "$NAT_TARGET" "$DEAD_PORT" > /tmp/refused-out.txt 2>&1
RC=$?

# The VM should see connection failure (timeout or refused).
# nc exit codes: 0=success, 1=error/timeout
echo "  nc exit code: $RC (expected non-zero)"

# ── Sanity check: NAT still works after refused connection ──
echo "  Verifying NAT still functional..."
echo "sanity-after-refused" | nc -w 5 "$NAT_TARGET" "$NAT_TCP_PORT" > /tmp/refused-sanity.txt 2>/dev/null
SANITY=$(cat /tmp/refused-sanity.txt 2>/dev/null)

if [ "$SANITY" = "sanity-after-refused" ]; then
    echo "  Sanity echo: OK"
    test_pass "nat-tcp-conn-refused"
else
    echo "  FAIL: NAT not functional after refused connection (got '$SANITY')"
    test_fail "nat-tcp-conn-refused"
fi
