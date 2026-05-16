#!/bin/sh
# KNOWN BUG: server-close-first download loses exactly 1 byte.
# This test uses nc < /dev/null → VM sends FIN before data arrives.
# The 50ms server timeout allows this, triggering the simultaneous-close
# path where swift-netstack loses the last byte. gvproxy does NOT lose it.
. /tests/lib.sh
echo "--- DL Close-First 64KB (known 1-byte-loss bug) ---"
NT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
DP=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_dl_integrity_port=' | cut -d= -f2)
[ -z "$NT" ] || [ -z "$DP" ] && { echo "  SKIP"; return 0; }
EXP=64240
echo "  Receiving $EXP bytes from $NT:$DP..."
if timeout 30 nc -w 25 "$NT" "$DP" < /dev/null > /tmp/dl-cf.bin 2>/dev/null; then
    RECV=$(wc -c < /tmp/dl-cf.bin)
    if [ "$RECV" -eq "$EXP" ]; then
        echo "  PASS: $RECV bytes (perfect)"
        test_pass "nat-tcp-dl-close-first"
    else
        echo "  FAIL: received $RECV, expected $EXP (lost $((EXP - RECV)) byte(s))"
        test_fail "nat-tcp-dl-close-first"
    fi
else
    echo "  FAIL: nc connection failed"
    test_fail "nat-tcp-dl-close-first"
fi
