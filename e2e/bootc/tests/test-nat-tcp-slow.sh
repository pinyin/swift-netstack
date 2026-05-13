#!/bin/sh
# Test: NAT TCP with slow HTTP response (server takes 3 seconds).
#
# Regression test for the FIN timing fix: the NAT must not forward FIN
# before the server responds, even when the server takes several seconds.
# A 0-byte response indicates premature FIN (Cloudflare bug pattern).
#
# Requires: nat_target and nat_http_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT TCP Slow HTTP Response ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_HTTP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_http_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_HTTP_PORT" ]; then
    echo "  SKIP: nat_target or nat_http_port not in cmdline"
    return 0
fi

echo "  Target: $NAT_TARGET:$NAT_HTTP_PORT/slow"
echo "  Sending HTTP request (expecting ~3s delay)..."

# Write HTTP request to a temp file to avoid pipe/busybox nc buffering issues.
cat > /tmp/slow-req.txt <<ENDOFREQUEST
GET /slow HTTP/1.0
Host: test
Connection: close

ENDOFREQUEST

# nc with 15s timeout — well above the 3s server delay.
nc -w 15 "$NAT_TARGET" "$NAT_HTTP_PORT" < /tmp/slow-req.txt > /tmp/slow-resp.txt 2>/dev/null

SLOW_SIZE=$(wc -c < /tmp/slow-resp.txt)

if [ "$SLOW_SIZE" -gt 0 ] && grep -q "slow-ok" /tmp/slow-resp.txt; then
    echo "  Response: $SLOW_SIZE bytes (slow-ok)"
    test_pass "nat-tcp-slow"
else
    echo "  Response: $SLOW_SIZE bytes"
    echo "  Content: $(head -c 200 /tmp/slow-resp.txt)"
    test_fail "nat-tcp-slow"
fi
