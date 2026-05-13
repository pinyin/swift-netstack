#!/bin/sh
# Test: NAT TCP RST handling (VM sends RST mid-connection).
#
# Starts a connection, then kills the client process.  The VM kernel sends
# RST for the abandoned connection.  The NAT must clean up the entry (fd,
# tcpFdToKey, tcpEntries) and remain functional for subsequent connections.
#
# Requires: nat_target and nat_tcp_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT TCP RST Handling ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_TCP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_tcp_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_TCP_PORT" ]; then
    echo "  SKIP: nat_target or nat_tcp_port not in cmdline"
    return 0
fi

echo "  Target: $NAT_TARGET:$NAT_TCP_PORT"

# ── Start a connection and kill it mid-flight ──
echo "  Starting connection and killing mid-flight..."

# Write enough data so it doesn't finish instantly
dd if=/dev/zero bs=512 count=4 2>/dev/null | tr '\0' 'R' > /tmp/rst-in.bin

# Start nc in background with exec to get the PID
nc "$NAT_TARGET" "$NAT_TCP_PORT" < /tmp/rst-in.bin > /tmp/rst-out1.bin 2>/dev/null &
RSTPID=$!

# Give it a moment to establish and start sending
sleep 0.5

# Kill the nc process — VM kernel sends RST for the abandoned socket
if kill -0 "$RSTPID" 2>/dev/null; then
    kill -9 "$RSTPID" 2>/dev/null
    wait "$RSTPID" 2>/dev/null || true
    echo "  Killed nc (pid=$RSTPID) — VM should send RST"
else
    echo "  nc already exited"
fi

# Brief sleep for RST to propagate through the NAT
sleep 0.5

# ── Verify NAT still works ──
echo "  Verifying NAT still functional after RST..."

for i in 1 2 3; do
    echo "rst-sanity-$i" | nc -w 5 "$NAT_TARGET" "$NAT_TCP_PORT" > "/tmp/rst-sanity-$i.txt" 2>/dev/null
    RESULT=$(cat "/tmp/rst-sanity-$i.txt" 2>/dev/null)
    if [ "$RESULT" = "rst-sanity-$i" ]; then
        echo "  Sanity $i: OK"
    else
        echo "  Sanity $i: FAIL (got '$RESULT')"
        test_fail "nat-tcp-rst"
        return 0
    fi
done

# ── Verify no connection leak ──
# We can't directly query NAT state, but if entries leaked, the 50-conn
# concurrent test would fail when run after this.  Multiple sanity
# connections succeeding is a good proxy.

echo "  RST cleanup: OK"
test_pass "nat-tcp-rst"
