#!/bin/sh
# Test: NAT HTTP fetch to external server (192.168.6.6).
#
# Validates TCP+NAT outbound path: VM → NAT → external HTTP server → response.
# Exercises TCP connection establishment, data transfer, and teardown
# against a real external endpoint.

. /tests/lib.sh

echo "--- NAT External HTTP ---"

EXT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^ext_target=' | cut -d= -f2)
EXT_HTTP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^ext_http_port=' | cut -d= -f2)

if [ -z "$EXT_TARGET" ] || [ -z "$EXT_HTTP_PORT" ]; then
    echo "  SKIP: ext_target or ext_http_port not in cmdline"
    return 0
fi

echo "  Fetching http://$EXT_TARGET:$EXT_HTTP_PORT/"

HTTP_OUT=$(wget -q -O /tmp/ext-http-resp.txt "http://$EXT_TARGET:$EXT_HTTP_PORT/" 2>&1)
HTTP_RC=$?

if [ $HTTP_RC -eq 0 ]; then
    RESP=$(cat /tmp/ext-http-resp.txt)
    RESP_LEN=$(wc -c < /tmp/ext-http-resp.txt)
    echo "  response ($RESP_LEN bytes): $RESP"
    if echo "$RESP" | grep -q "ext-http-ok"; then
        test_pass "nat-external-http"
    else
        echo "  unexpected response content"
        test_fail "nat-external-http"
    fi
else
    echo "  wget failed (rc=$HTTP_RC): $HTTP_OUT"
    test_fail "nat-external-http"
fi
