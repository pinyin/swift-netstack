#!/bin/sh
# Test: NAT TCP throughput — remote server, single-stream + parallel.
. /tests/lib.sh

echo '--- NAT External iperf3 (remote) ---'

EXT_TARGET=$(cat /proc/cmdline | tr ' ' '\n' | grep '^ext_target=' | cut -d= -f2)
EXT_IPERF_PORT=$(cat /proc/cmdline | tr ' ' '\n' | grep '^ext_iperf_port=' | cut -d= -f2)

if [ -z "$EXT_TARGET" ] || [ -z "$EXT_IPERF_PORT" ]; then
    echo '  SKIP: ext_target or ext_iperf_port not in cmdline'; return 0
fi
if [ ! -x /bin/iperf3 ]; then
    echo '  SKIP: /bin/iperf3 not found'; return 0
fi

echo "  Target: $EXT_TARGET:$EXT_IPERF_PORT"
FAIL=0

check_iperf() {
    _label="$1"; _json="$2"; _rc="$3"
    if [ $_rc -ne 0 ]; then echo "  $_label: exit=$_rc"; FAIL=1; return; fi
    _bps=$(echo "$_json" | grep 'bits_per_second' | tail -1 | sed 's/.*bits_per_second": *//' | sed 's/[^0-9.e+]//g')
    if [ -z "$_bps" ] || [ "$_bps" = "0" ]; then echo "  $_label: ZERO"; FAIL=1; return; fi
    _gbps=$(awk "BEGIN { printf \"%.2f\", $_bps / 1000000000 }" 2>/dev/null)
    _mbps=$(awk "BEGIN { printf \"%.0f\", $_bps / 1000000 }" 2>/dev/null)
    echo "  $_label: ${_gbps} Gbits/sec (${_mbps} Mbps)"
}

# Upload: VM→remote
for P in 1 8 128; do
    dur=10
    [ $P -eq 128 ] && dur=5
    json=$(/bin/iperf3 -c "$EXT_TARGET" -p "$EXT_IPERF_PORT" -t $dur -P $P --json 2>/dev/null); rc=$?
    check_iperf "Upload-${P}p" "$json" $rc
    sleep 1
done

# Download: remote→VM via -R
for P in 1 8 128; do
    dur=10
    [ $P -eq 128 ] && dur=5
    json=$(/bin/iperf3 -c "$EXT_TARGET" -p "$EXT_IPERF_PORT" -t $dur -P $P -R --json 2>/dev/null); rc=$?
    check_iperf "Download-${P}p" "$json" $rc
    sleep 1
done

if [ $FAIL -eq 0 ]; then test_pass 'nat-external-iperf'; else test_fail 'nat-external-iperf'; fi
