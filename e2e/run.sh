#!/usr/bin/env bash
# SwiftNetStack E2E test runner.
#
# Launches a Linux VM with the BDP pipeline and runs comprehensive
# networking tests (DHCP, ICMP, ARP, DNS, routing).
#
# Usage:
#   ./run.sh                              # all tests (default)
#   ./run.sh --host test.local:1.2.3.4   # with DNS hostname
#   ./run.sh --timeout 30                 # custom timeout
#
# Prerequisites:
#   - Swift toolchain (swift build)
#   - com.apple.security.virtualization entitlement
#   - e2e/kernel/Image (aarch64 Linux kernel)
#   - e2e/initramfs/bin/busybox (aarch64 static busybox)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMEOUT=120
TCP_PORT=7777
UDP_PORT=7778
HTTP_PORT=7779
TCP_CLOSE_PORT=7780
BIDI_PORT=7781
IPERF_PORT=7782
INIT="/init"
HOST_ARGS=()
PCAP_PATH=""
MTU=""

while [ $# -gt 0 ]; do
    case "$1" in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --host)
            HOST_ARGS+=("--host" "$2")
            shift 2
            ;;
        --pcap) PCAP_PATH="$2"; shift 2 ;;
        --mtu) MTU="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

KERNEL="$SCRIPT_DIR/kernel/Image"
INITRD="$SCRIPT_DIR/initramfs/initramfs.cpio.gz"
DEMO_BIN="$PROJECT_DIR/.build/release/SwiftNetStackDemo"

# ── Validate prerequisites ──

if [ ! -f "$KERNEL" ]; then
    echo "ERROR: kernel not found at $KERNEL"
    exit 1
fi

# Build initramfs if needed
INIT_SRC="$SCRIPT_DIR/initramfs/init"
if [ ! -f "$INITRD" ] || [ "$INIT_SRC" -nt "$INITRD" ] || [ "$SCRIPT_DIR/initramfs/build.sh" -nt "$INITRD" ]; then
    echo "Building initramfs..."
    "$SCRIPT_DIR/initramfs/build.sh"
fi

# Build demo if needed
if [ ! -x "$DEMO_BIN" ]; then
    echo "Building SwiftNetStackDemo (release)..."
    (cd "$PROJECT_DIR" && swift build -c release --product SwiftNetStackDemo) || {
        echo "ERROR: Build failed"
        exit 1
    }
fi

# Ensure demo is signed
if ! codesign -d "$DEMO_BIN" 2>/dev/null | grep -q 'authority'; then
    codesign -s - --entitlements /tmp/vm-demo.entitlements -f "$DEMO_BIN" 2>/dev/null || true
fi

# ── NAT echo servers ──

HOST_IP=$(ifconfig en0 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1)
if [ -z "$HOST_IP" ]; then
    HOST_IP=$(ifconfig en1 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1)
fi

ECHO_PID=""
IPERF_PID=""
NAT_CMD=""

if [ -n "$HOST_IP" ] && command -v python3 &>/dev/null; then
    python3 "$SCRIPT_DIR/echo_servers.py" "$TCP_PORT" "$UDP_PORT" "$HTTP_PORT" "$TCP_CLOSE_PORT" "$BIDI_PORT" &
    ECHO_PID=$!
    sleep 0.5
    if kill -0 "$ECHO_PID" 2>/dev/null; then
        NAT_CMD="nat_target=$HOST_IP nat_tcp_port=$TCP_PORT nat_udp_port=$UDP_PORT nat_http_port=$HTTP_PORT nat_tcp_close_port=$TCP_CLOSE_PORT nat_tcp_bidi_port=$BIDI_PORT nat_iperf_port=$IPERF_PORT"
        echo "Echo servers: TCP:$TCP_PORT UDP:$UDP_PORT HTTP:$HTTP_PORT CLOSE:$TCP_CLOSE_PORT BIDI:$BIDI_PORT (target=$HOST_IP)"
    else
        ECHO_PID=""
        echo "WARNING: Echo servers failed to start, NAT tests will skip"
    fi
else
    echo "WARNING: python3 or host IP not available, NAT tests will skip"
fi

# Start iperf3 server (independent of echo_servers.py)
if [ -n "$HOST_IP" ] && command -v iperf3 &>/dev/null; then
    iperf3 -s -p "$IPERF_PORT" --daemon 2>/dev/null && IPERF_PID=$!
    if [ -n "$IPERF_PID" ]; then
        echo "iperf3 server: port $IPERF_PORT (pid $IPERF_PID)"
    fi
fi

# ── Run test ──

TMPLOG="$(mktemp /tmp/swiftnetstack-e2e.XXXXXX.log)"
trap '[ -n "$ECHO_PID" ] && kill "$ECHO_PID" 2>/dev/null; [ -n "$IPERF_PID" ] && kill "$IPERF_PID" 2>/dev/null; rm -f "$TMPLOG"' EXIT

echo "========================================="
echo "SwiftNetStack E2E Test Suite"
echo "========================================="
echo "Kernel:  $KERNEL"
echo "Initrd:  $INITRD"
echo "Init:    $INIT"
echo "Timeout: ${TIMEOUT}s"
if [ ${#HOST_ARGS[@]} -gt 0 ]; then
    echo "Hosts:   ${HOST_ARGS[*]}"
fi
echo ""

echo "Starting demo..."
"$DEMO_BIN" \
    --kernel "$KERNEL" \
    --initrd "$INITRD" \
    --cmdline "console=hvc0 init=$INIT loglevel=4 panic=10 ${MTU:+MTU=$MTU }$NAT_CMD" \
    --cpus 1 --memory 512 \
    ${HOST_ARGS[@]+"${HOST_ARGS[@]}"} \
    ${PCAP_PATH:+--pcap "$PCAP_PATH"} \
    ${MTU:+--mtu "$MTU"} \
    >"$TMPLOG" 2>&1 &
DEMOPID=$!

# Wait for test completion or timeout
DEADLINE=$(($(date +%s) + TIMEOUT))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if grep -q '=== Test suite complete' "$TMPLOG" 2>/dev/null; then
        sleep 2  # let final tests finish
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
echo "=== Test output ==="
cat "$TMPLOG"
echo "=== End output ==="
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
echo "E2E Test Results"
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
[ -n "$ECHO_PID" ] && kill "$ECHO_PID" 2>/dev/null || true
[ -n "$IPERF_PID" ] && kill "$IPERF_PID" 2>/dev/null || true

if [ ${#FAILED[@]} -gt 0 ]; then
    exit 1
elif [ "$TOTAL" -eq 0 ]; then
    echo "WARNING: No test markers found (VM may have failed to boot)"
    exit 1
else
    exit 0
fi
