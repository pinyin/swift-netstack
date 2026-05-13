#!/bin/bash
# Test: Large UDP datagram through NAT.
# Sends a text-based UDP datagram through NAT echo, verifies byte count.
# Uses bash /dev/udp to avoid nmap-ncat UDP behavioral differences.
# Requires: nat_target and nat_udp_port in kernel cmdline.

. /tests/lib.sh

echo "--- NAT UDP Large Datagram ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
NAT_UDP_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_udp_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$NAT_UDP_PORT" ]; then
    echo "  SKIP: nat_target or nat_udp_port not in cmdline"
    return 0
fi

echo "  Target: $NAT_TARGET:$NAT_UDP_PORT"

# Generate a large text payload for UDP
PAYLOAD="UDP_LARGE_TEST_"
i=0
while [ $i -lt 40 ]; do
    PAYLOAD="${PAYLOAD}PADDING_DATA_$(printf '%02d' $i)_"
    i=$((i + 1))
done
echo "$PAYLOAD" > /tmp/udp-large-in.bin
SENT=$(wc -c < /tmp/udp-large-in.bin)
echo "  Sending $SENT bytes via UDP..."

# bash /dev/udp: write sends datagram, dd reads response
FAILED=0
bash -c '
    exec 3<>/dev/udp/$1/$2 2>/dev/null || exit 1
    cat /tmp/udp-large-in.bin >&3
    dd bs=4096 count=1 <&3 of=/tmp/udp-large-out.bin 2>/dev/null
    exec 3>&-
' -- "$NAT_TARGET" "$NAT_UDP_PORT" 2>/dev/null || FAILED=1

if [ "$FAILED" -eq 1 ]; then
    # Fallback to nc -u
    cat /tmp/udp-large-in.bin | nc -u -w 5 "$NAT_TARGET" "$NAT_UDP_PORT" > /tmp/udp-large-out.bin
fi

RECV=$(wc -c < /tmp/udp-large-out.bin)

if [ "$SENT" -eq "$RECV" ]; then
    test_pass "nat-udp-large"
else
    echo "  Sent: $SENT bytes, Received: $RECV bytes"
    test_fail "nat-udp-large"
fi
