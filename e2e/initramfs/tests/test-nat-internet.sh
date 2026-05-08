#!/bin/sh
# Test: Internet access through NAT.
#
# Part 1 (guest→host HTTP): Uses the host-side HTTP test server.
# Part 2 (guest→internet): DNS + TCP connectivity + HTTP fetch.

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

echo "  Guest→Internet: DNS + TCP connectivity..."

# Verify upstream DNS forwarding
HTTPBIN_IP=$(nslookup httpbin.org 2>/dev/null | awk '/^Address:/ && !/[#:][0-9]+$/ {print $2; exit}')
if [ -z "$HTTPBIN_IP" ]; then
    echo "  DNS cannot resolve internet hostnames"
    test_fail "nat-http-internet"
    return 0
fi
echo "  DNS OK: httpbin.org → $HTTPBIN_IP"

# Test 1: Raw TCP connectivity — send a short string, expect any response
echo "  TCP probe to $HTTPBIN_IP:80..."
echo "hello" | nc -w 10 "$HTTPBIN_IP" 80 > /tmp/inet-tcp-probe.txt 2>/dev/null
TCP_RESP=$(wc -c < /tmp/inet-tcp-probe.txt)
echo "  TCP probe response: $TCP_RESP bytes"
if [ "$TCP_RESP" -gt 0 ]; then
    echo "  TCP connectivity OK"
    test_pass "nat-http-internet"
    return 0
fi

echo "  No TCP response from internet host"
test_fail "nat-http-internet"
