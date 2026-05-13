#!/bin/bash
# Test: Outbound UDP through NAT.
# Sends a UDP datagram to the host echo server via NAT, verifies echo reply.
# Uses bash /dev/udp to avoid nmap-ncat UDP behavioral differences.
# Requires: nat_target and nat_udp_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT UDP (outbound) ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_UDP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_udp_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_UDP_PORT" ]; then
    echo "  SKIP: nat_target or nat_udp_port not in cmdline"
    return 0
fi

echo "  Target: $NAT_TARGET:$NAT_UDP_PORT"
echo "  Sending UDP echo probe..."

# bash /dev/udp: write sends a datagram, dd reads full datagram in one syscall
RESULT=$(bash -c '
    exec 3<>/dev/udp/$1/$2 2>/dev/null || { printf "__BASH_UDP_FAILED__"; exit 0; }
    printf "hello-nat-udp" >&3
    dd bs=1024 count=1 <&3 2>/dev/null
    exec 3>&-
' -- "$NAT_TARGET" "$NAT_UDP_PORT" 2>/dev/null)

if [ "$RESULT" = "__BASH_UDP_FAILED__" ]; then
    # Fallback to nc -u (nmap-ncat)
    RESULT=$(printf "hello-nat-udp" | nc -u -w 5 "$NAT_TARGET" "$NAT_UDP_PORT" 2>&1)
fi

case "$RESULT" in
    *"hello-nat-udp"*)
        test_pass "nat-udp"
        ;;
    *)
        echo "  Expected: hello-nat-udp"
        echo "  Got:      $RESULT"
        test_fail "nat-udp"
        ;;
esac
