#!/bin/sh
# Download integrity: send 1-byte trigger, receive 64KB pattern, verify.
. /tests/lib.sh
echo "--- NAT TCP Download Integrity (64 KB) ---"
NT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
DP=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_dl_integrity_port=' | cut -d= -f2)
[ -z "$NT" ] || [ -z "$DP" ] && { echo "  SKIP"; return 0; }
EXP=64240
echo "  Receiving $EXP bytes from $NT:$DP..."
# printf sends 1-byte trigger; nc -q 0 closes after EOF from server
if printf '\x00' | timeout 30 nc -w 25 "$NT" "$DP" > /tmp/dl-out.bin 2>/dev/null; then
    RECV=$(wc -c < /tmp/dl-out.bin)
    if [ "$RECV" -ne "$EXP" ]; then
        echo "  FAIL: received $RECV bytes, expected $EXP"
        test_fail "nat-tcp-dl-integrity"; return 1
    fi
    if cmp -s /tmp/dl-out.bin /tests/dl-pattern-64k.bin; then
        echo "  PASS: $RECV bytes byte-perfect"
        test_pass "nat-tcp-dl-integrity"
    else
        BAD=$(cmp -l /tmp/dl-out.bin /tests/dl-pattern-64k.bin 2>/dev/null | head -3)
        echo "  FAIL: mismatch at: $BAD"
        test_fail "nat-tcp-dl-integrity"
    fi
else
    echo "  FAIL: nc connection failed"
    test_fail "nat-tcp-dl-integrity"
fi
