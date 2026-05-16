#!/bin/sh
. /tests/lib.sh

echo "--- NAT iperf3 Throughput ---"

NAT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_target=' | cut -d= -f2)
IPERF_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^nat_iperf_port=' | cut -d= -f2)

if [ -z "$NAT_TARGET" ] || [ -z "$IPERF_PORT" ]; then
    echo "  SKIP: nat_target or nat_iperf_port not in cmdline"; return 0
fi
if [ ! -x /bin/iperf3 ]; then
    echo "  SKIP: /bin/iperf3 not found"; return 0
fi
echo "  Target: $NAT_TARGET:$IPERF_PORT"

FAIL=0

check_iperf() {
    _label="$1"; _json="$2"; _rc="$3"
    if [ $_rc -ne 0 ]; then echo "  $_label: exit=$_rc"; FAIL=1; return; fi
    _bps=$(echo "$_json" | grep 'bits_per_second' | tail -1 | sed 's/.*bits_per_second": *//' | sed 's/[^0-9.e+]//g')
    if [ -z "$_bps" ] || [ "$_bps" = "0" ]; then echo "  $_label: ZERO"; FAIL=1; return; fi
    _gbps=$(awk "BEGIN { printf \"%.2f\", $_bps / 1000000000 }" 2>/dev/null)
    echo "  $_label: ${_gbps} Gbits/sec"
}

# Upload (northbound): 8 streams
json=$(/bin/iperf3 -c "$NAT_TARGET" -p "$IPERF_PORT" -t 3 -P 8 --json 2>/dev/null); rc=$?
check_iperf "Upload" "$json" $rc
sleep 1

# Download (southbound via -R): 1 stream
json=$(/bin/iperf3 -c "$NAT_TARGET" -p "$IPERF_PORT" -t 3 -P 1 -R --json 2>/dev/null); rc=$?
check_iperf "Download" "$json" $rc

if [ $FAIL -eq 0 ]; then test_pass "nat-iperf"; else test_fail "nat-iperf"; fi
