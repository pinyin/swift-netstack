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

# wget does its own DNS resolution through libc getaddrinfo().
# This exercises both A and AAAA query forwarding through the NAT DNS server.
WGET_ERR=$(timeout 10 wget -q -O /tmp/inet-http-resp.txt "http://example.com/" 2>&1)
WGET_RC=$?
if [ $WGET_RC -eq 0 ]; then
    TCP_RESP=$(wc -c < /tmp/inet-http-resp.txt)
    echo "  response: $TCP_RESP bytes"
    if [ "$TCP_RESP" -gt 0 ]; then
        test_pass "nat-http-internet"
    else
        echo "  empty response"
        test_fail "nat-http-internet"
    fi
else
    echo "  wget to example.com failed (rc=$WGET_RC): $WGET_ERR"
    test_fail "nat-http-internet"
fi
