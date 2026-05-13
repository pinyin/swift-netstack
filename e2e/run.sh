#!/usr/bin/env bash
# SwiftNetStack E2E test runner.
#
# Launches a Linux VM with the BDP pipeline and runs comprehensive
# networking tests (DHCP, ICMP, ARP, DNS, routing).
#
# Usage:
#   ./run.sh                              # all tests (busybox initramfs, default)
#   ./run.sh --bootc                      # all tests (Fedora bootc initramfs)
#   ./run.sh --host test.local:1.2.3.4   # with DNS hostname
#   ./run.sh --timeout 30                 # custom timeout
#   ./run.sh --ext-target 192.168.6.6     # external server for NAT tests
#
# Prerequisites:
#   - Swift toolchain (swift build)
#   - com.apple.security.virtualization entitlement
#   - e2e/kernel/Image (aarch64 Linux kernel)
#   - busybox path: e2e/initramfs/bin/busybox + e2e/initramfs/initramfs.cpio.gz
#   - bootc path:   e2e/bootc/output/initramfs.cpio.gz (build on server first)

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
BOOTC_MODE=false
HOST_ARGS=()
PCAP_PATH=""
MTU=""
EXT_TARGET=""
EXT_IPERF_PORT=7782
EXT_HTTP_PORT=7783
CHAOS_CMD=""

while [ $# -gt 0 ]; do
    case "$1" in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --host)
            HOST_ARGS+=("--host" "$2")
            shift 2
            ;;
        --pcap) PCAP_PATH="$2"; shift 2 ;;
        --mtu) MTU="$2"; shift 2 ;;
        --ext-target) EXT_TARGET="$2"; shift 2 ;;
        --ext-iperf-port) EXT_IPERF_PORT="$2"; shift 2 ;;
        --ext-http-port) EXT_HTTP_PORT="$2"; shift 2 ;;
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
        --bootc) BOOTC_MODE=true; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

KERNEL="$SCRIPT_DIR/kernel/Image"
if $BOOTC_MODE; then
    INITRD="$SCRIPT_DIR/bootc/output/initramfs.cpio.gz"
else
    INITRD="$SCRIPT_DIR/initramfs/initramfs.cpio.gz"
fi
DEMO_BIN="$PROJECT_DIR/.build/release/SwiftNetStackDemo"

# ── Validate prerequisites ──

if [ ! -f "$KERNEL" ]; then
    echo "ERROR: kernel not found at $KERNEL"
    exit 1
fi

# Build initramfs if needed
if $BOOTC_MODE; then
    if [ ! -f "$INITRD" ]; then
        echo "ERROR: bootc initramfs not found at $INITRD"
        echo "Build it first: cd e2e/bootc && bash build.sh  (on the local server)"
        exit 1
    fi
else
    INIT_SRC="$SCRIPT_DIR/initramfs/init"
    if [ ! -f "$INITRD" ] || [ "$INIT_SRC" -nt "$INITRD" ] || [ "$SCRIPT_DIR/initramfs/build.sh" -nt "$INITRD" ]; then
        echo "Building initramfs..."
        "$SCRIPT_DIR/initramfs/build.sh"
    fi
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

# ── External server services (for nat-external-* tests) ──

EXT_IPERF_SSH_PID=""
EXT_HTTP_SSH_PID=""
EXT_CMD=""

if [ -n "$EXT_TARGET" ]; then
    echo "External target: $EXT_TARGET"
    EXT_CMD="ext_target=$EXT_TARGET ext_iperf_port=$EXT_IPERF_PORT ext_http_port=$EXT_HTTP_PORT"

    # Start iperf3 on external server if not already running
    if ssh -o ConnectTimeout=3 -o BatchMode=yes "pinyin@$EXT_TARGET" "iperf3 -c 127.0.0.1 -p $EXT_IPERF_PORT -t 1 2>&1" >/dev/null 2>&1; then
        echo "iperf3 already running on $EXT_TARGET:$EXT_IPERF_PORT"
    else
        ssh -o ConnectTimeout=3 -o BatchMode=yes "pinyin@$EXT_TARGET" "killall iperf3 2>/dev/null; nohup iperf3 -s -p $EXT_IPERF_PORT --daemon" 2>/dev/null &
        EXT_IPERF_SSH_PID=$!
        sleep 0.5
        echo "Started iperf3 on $EXT_TARGET:$EXT_IPERF_PORT"
    fi

    # Start HTTP server on external server if not already running
    if ssh -o ConnectTimeout=3 -o BatchMode=yes "pinyin@$EXT_TARGET" "curl -s http://127.0.0.1:$EXT_HTTP_PORT/ 2>&1" >/dev/null 2>&1; then
        echo "HTTP already running on $EXT_TARGET:$EXT_HTTP_PORT"
    else
        ssh -o ConnectTimeout=3 -o BatchMode=yes "pinyin@$EXT_TARGET" "killall python3 2>/dev/null; mkdir -p /tmp/http-test; echo 'ext-http-ok' > /tmp/http-test/index.html; cd /tmp/http-test && nohup python3 -m http.server $EXT_HTTP_PORT --bind 0.0.0.0 > /tmp/http-server.log 2>&1 &" 2>/dev/null &
        EXT_HTTP_SSH_PID=$!
        sleep 1
        echo "Started HTTP on $EXT_TARGET:$EXT_HTTP_PORT"
    fi
fi

# ── Run test ──

TMPLOG="$(mktemp /tmp/swiftnetstack-e2e.XXXXXX.log)"
trap '[ -n "$ECHO_PID" ] && kill "$ECHO_PID" 2>/dev/null; [ -n "$IPERF_PID" ] && kill "$IPERF_PID" 2>/dev/null; [ -n "$EXT_IPERF_SSH_PID" ] && kill "$EXT_IPERF_SSH_PID" 2>/dev/null; [ -n "$EXT_HTTP_SSH_PID" ] && kill "$EXT_HTTP_SSH_PID" 2>/dev/null; rm -f "$TMPLOG"' EXIT

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
MEMORY=512
if $BOOTC_MODE; then
    MEMORY=1024
    CMDLINE="console=hvc0 loglevel=4 panic=10 ${MTU:+MTU=$MTU }$NAT_CMD $EXT_CMD $CHAOS_CMD"
else
    CMDLINE="console=hvc0 init=$INIT loglevel=4 panic=10 ${MTU:+MTU=$MTU }$NAT_CMD $EXT_CMD $CHAOS_CMD"
fi
"$DEMO_BIN" \
    --kernel "$KERNEL" \
    --initrd "$INITRD" \
    --cmdline "$CMDLINE" \
    --cpus 1 --memory $MEMORY \
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
