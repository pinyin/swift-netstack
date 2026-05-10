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

# Verify upstream DNS forwarding is working (nslookup uses busybox's own
# DNS client which sends a plain A query — works reliably through the NAT).
HTTPBIN_IP=$(nslookup example.com 2>/dev/null | awk '/^Address:/ && !/[#:][0-9]+$/ {print $2; exit}')
if [ -z "$HTTPBIN_IP" ]; then
    echo "  DNS cannot resolve internet hostnames"
    test_fail "nat-http-internet"
    return 0
fi
echo "  DNS OK: example.com -> $HTTPBIN_IP"

# Use printf|nc with explicit Host header for the HTTP request.
# We pre-resolve the IP with nslookup (above) because wget in this
# environment uses libc getaddrinfo() which sends AAAA queries that the
# NAT DNS server does not forward upstream, causing resolution to fail.
#
# Unlike the old approach, we include the correct Host header so
# Cloudflare (and other virtual-hosting servers) return a valid response
# instead of HTTP 403.
echo "  HTTP fetch http://$HTTPBIN_IP/ (Host: example.com) ..."
# The subshell (printf; sleep) keeps stdin open for 1.5s after sending
# the request.  This gives Cloudflare time to respond before the NAT
# forwards the VM-side FIN — avoiding the race where Cloudflare aborts
# if it receives FIN before it starts sending the response.
HTTP_RESP=$( (printf "GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n"; sleep 1.5) | nc -w 5 "$HTTPBIN_IP" 80 2>/dev/null)
HTTP_RC=$?
if [ $HTTP_RC -eq 0 ] && [ -n "$HTTP_RESP" ]; then
    if echo "$HTTP_RESP" | grep -q "HTTP/1.[01] [23]"; then
        echo "  HTTP response: $(echo "$HTTP_RESP" | head -n 1)"
        test_pass "nat-http-internet"
    else
        echo "  unexpected HTTP response: $(echo "$HTTP_RESP" | head -n 1)"
        test_fail "nat-http-internet"
    fi
else
    echo "  HTTP fetch to $HTTPBIN_IP failed (rc=$HTTP_RC)"
    test_fail "nat-http-internet"
fi
