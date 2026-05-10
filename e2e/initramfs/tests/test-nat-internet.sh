#!/bin/sh
# Test: Internet access through NAT.
#
# Part 1 (guest→host HTTP): Uses the host-side HTTP test server.
# Part 2 (guest→internet): DNS + HTTP fetch.

. /tests/lib.sh

echo "--- NAT Internet Access ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_HTTP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_http_port=' | cut -d= -f2)

# ── Part 1: Guest → Host HTTP ──

if [ -n "$NAT_TARGET" ] && [ -n "$NAT_HTTP_PORT" ]; then
    echo "  Guest→Host HTTP: http://$NAT_TARGET:$NAT_HTTP_PORT/"

    if wget -q -O /tmp/http-host-resp.txt "http://$NAT_TARGET:$NAT_HTTP_PORT/" 2>/dev/null; then
        if grep -q "endpoint-ok" /tmp/http-host-resp.txt; then
            test_pass "nat-http-host"
        else
            echo "  Response: $(head -n 1 /tmp/http-host-resp.txt)"
            test_fail "nat-http-host"
        fi
    else
        echo "  wget to host HTTP server failed"
        test_fail "nat-http-host"
    fi
else
    echo "  SKIP nat-http-host: nat_target or nat_http_port not in cmdline"
fi

# ── Part 2: Guest → Internet ──

echo "  Guest→Internet: DNS + HTTP fetch..."

# Verify upstream DNS forwarding
HTTPBIN_IP=$(nslookup example.com 2>/dev/null | awk '/^Address:/ && !/[#:][0-9]+$/ {print $2; exit}')
if [ -z "$HTTPBIN_IP" ]; then
    echo "  DNS cannot resolve internet hostnames"
    test_fail "nat-http-internet"
    return 0
fi
echo "  DNS OK: example.com -> $HTTPBIN_IP"

# Use printf+nc for raw HTTP request with proper Host header.
# This avoids issues with busybox wget DNS resolution and --header support.
echo "  HTTP fetch http://$HTTPBIN_IP/ ..."
printf 'GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n' \
    | nc -w 10 "$HTTPBIN_IP" 80 > /tmp/inet-http-resp.txt 2>/tmp/inet-http-err.txt
TCP_RESP=$(wc -c < /tmp/inet-http-resp.txt)
echo "  response: $TCP_RESP bytes"
if [ "$TCP_RESP" -gt 0 ]; then
    test_pass "nat-http-internet"
    return 0
fi

echo "  HTTP fetch failed"
echo "  stderr: $(cat /tmp/inet-http-err.txt)"
test_fail "nat-http-internet"
