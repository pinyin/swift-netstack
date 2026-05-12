#!/usr/bin/env bash
# gvisor-tap-vsock comparison benchmark.
# Uses the same VM (kernel, initramfs, tests) as the SwiftNetStack e2e,
# but replaces the BDP networking stack with gvproxy.
#
# Usage:
#   ./run-gvproxy.sh              # all tests (default)
#   ./run-gvproxy.sh --timeout 30 # custom timeout

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

TIMEOUT=180
TCP_PORT=7777
UDP_PORT=7778
HTTP_PORT=7779
TCP_CLOSE_PORT=7780
BIDI_PORT=7781
IPERF_PORT=7782
CHAOS_CMD=""

while [ $# -gt 0 ]; do
    case "$1" in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --chaos)
            CHAOS_LOSS=5; CHAOS_REORDER=10; CHAOS_DUP=3
            if [ -n "${2:-}" ] && [ "${2#-}" = "$2" ]; then
                IFS=',' read -r a b c <<< "$2"
                CHAOS_LOSS="${a:-5}"; CHAOS_REORDER="${b:-10}"; CHAOS_DUP="${c:-3}"
                shift
            fi
            CHAOS_CMD="chaos_loss=$CHAOS_LOSS chaos_reorder=$CHAOS_REORDER chaos_dup=$CHAOS_DUP"
            shift
            ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

KERNEL="$SCRIPT_DIR/kernel/Image"
INITRD="$SCRIPT_DIR/initramfs/initramfs.cpio.gz"
DEMO_BIN="$PROJECT_DIR/.build/release/SwiftNetStackDemo"
GVPROXY="/Users/pinyin/developer/gvisor-tap-vsock/bin/gvproxy"
GVPROXY_SOCK="/tmp/gvproxy-e2e.sock"
VFKIT_SOCK="/tmp/gvproxy-e2e-vfkit.sock"

# ── Validate prerequisites ──

if [ ! -f "$KERNEL" ]; then
    echo "ERROR: kernel not found at $KERNEL"
    exit 1
fi

if [ ! -f "$INITRD" ]; then
    echo "Building initramfs..."
    "$SCRIPT_DIR/initramfs/build.sh"
fi

if [ ! -x "$DEMO_BIN" ]; then
    echo "Building SwiftNetStackDemo (release)..."
    (cd "$PROJECT_DIR" && swift build -c release --product SwiftNetStackDemo) || {
        echo "ERROR: Build failed"
        exit 1
    }
fi

if [ ! -x "$GVPROXY" ]; then
    echo "ERROR: gvproxy not found at $GVPROXY"
    exit 1
fi

# ── Cleanup leftover sockets ──
rm -f "$GVPROXY_SOCK" "$VFKIT_SOCK" "/tmp/gvproxy-demo-"*.sock 2>/dev/null || true

# ── Start iperf3 server ──
killall iperf3 2>/dev/null || true
if command -v iperf3 &>/dev/null; then
    iperf3 -s -p "$IPERF_PORT" --daemon 2>/dev/null && echo "iperf3 server started on port $IPERF_PORT"
fi

# ── Start echo servers (bind to 0.0.0.0 for gvproxy NAT 192.168.127.254→127.0.0.1) ──
python3 "$SCRIPT_DIR/echo_servers.py" "$TCP_PORT" "$UDP_PORT" "$HTTP_PORT" "$TCP_CLOSE_PORT" "$BIDI_PORT" &
ECHO_PID=$!
sleep 0.5

TMPLOG="$(mktemp /tmp/gvproxy-cmp.XXXXXX.log)"
trap 'kill $DEMOPID 2>/dev/null || true; kill $GVPROXY_PID 2>/dev/null || true; kill $ECHO_PID 2>/dev/null || true; killall iperf3 2>/dev/null || true; rm -f "$TMPLOG" "$GVPROXY_SOCK" "$VFKIT_SOCK" "/tmp/gvproxy-demo-"*.sock 2>/dev/null' EXIT

# ── Start gvproxy ──
echo "Starting gvproxy..."
"$GVPROXY" \
    --listen-vfkit "unixgram://$VFKIT_SOCK" \
    --listen "unix://$GVPROXY_SOCK" \
    >/tmp/gvproxy-e2e-gvproxy.log 2>&1 &
GVPROXY_PID=$!

# Wait for vfkit socket
for i in $(seq 1 30); do
    if [ -S "$VFKIT_SOCK" ]; then
        echo "gvproxy ready (pid $GVPROXY_PID)"
        break
    fi
    if ! kill -0 "$GVPROXY_PID" 2>/dev/null; then
        echo "ERROR: gvproxy exited early"
        exit 1
    fi
    sleep 0.5
done

if [ ! -S "$VFKIT_SOCK" ]; then
    echo "ERROR: gvproxy vfkit socket not created"
    exit 1
fi

# ── gvproxy subnet: 192.168.127.0/24 ──
# Gateway: 192.168.127.1, Device (VM): 192.168.127.2, Host: 192.168.127.254
# hostIP (192.168.127.254) is NAT'd to 127.0.0.1, so VM tests connect to 192.168.127.254
NAT_CMD="nat_target=192.168.127.254 nat_tcp_port=$TCP_PORT nat_udp_port=$UDP_PORT nat_http_port=$HTTP_PORT nat_tcp_close_port=$TCP_CLOSE_PORT nat_tcp_bidi_port=$BIDI_PORT nat_iperf_port=$IPERF_PORT"
EXT_CMD="ext_target=192.168.6.6 ext_iperf_port=7782 ext_http_port=7783"

echo "Starting demo with external networking (gvproxy)..."
"$DEMO_BIN" \
    --kernel "$KERNEL" \
    --initrd "$INITRD" \
    --cmdline "console=hvc0 init=/init loglevel=4 panic=10 $NAT_CMD $EXT_CMD $CHAOS_CMD" \
    --cpus 1 --memory 512 \
    --external-net "$VFKIT_SOCK" \
    >"$TMPLOG" 2>&1 &
DEMOPID=$!

# Wait for test completion or timeout
DEADLINE=$(($(date +%s) + TIMEOUT))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if grep -q '=== Test suite complete' "$TMPLOG" 2>/dev/null; then
        sleep 2
        break
    fi
    if ! kill -0 "$DEMOPID" 2>/dev/null; then
        echo "Demo exited early"
        break
    fi
    sleep 1
done

# ── Report results ──

echo ""
echo "=== VM output ==="
cat "$TMPLOG"
echo "=== End VM output ==="
echo ""

# Parse test markers
PASSED=()
FAILED=()
while IFS= read -r line; do
    if echo "$line" | grep -q '\[TEST\] .* PASS'; then
        name=$(echo "$line" | sed 's/.*\[TEST\] //;s/ PASS.*//')
        PASSED+=("$name")
    elif echo "$line" | grep -q '\[TEST\] .* FAIL'; then
        name=$(echo "$line" | sed 's/.*\[TEST\] //;s/ FAIL.*//')
        FAILED+=("$name")
    fi
done < "$TMPLOG"

TOTAL=$((${#PASSED[@]} + ${#FAILED[@]}))

echo ""
echo "========================================="
echo "gvisor-tap-vsock E2E Results"
echo "========================================="
for t in "${PASSED[@]}"; do
    echo "  PASS  $t"
done
for t in "${FAILED[@]}"; do
    echo "  FAIL  $t"
done
echo "-----------------------------------------"
echo "  Total: ${#PASSED[@]} passed, ${#FAILED[@]} failed, $TOTAL tests"
echo "========================================="

# Cleanup
kill "$DEMOPID" 2>/dev/null || true
wait "$DEMOPID" 2>/dev/null || true
kill "$GVPROXY_PID" 2>/dev/null || true
wait "$GVPROXY_PID" 2>/dev/null || true
kill "$ECHO_PID" 2>/dev/null || true
killall iperf3 2>/dev/null || true

if [ ${#FAILED[@]} -gt 0 ]; then
    exit 1
elif [ "$TOTAL" -eq 0 ]; then
    echo "WARNING: No test markers found (VM may have failed to boot)"
    exit 1
else
    exit 0
fi
