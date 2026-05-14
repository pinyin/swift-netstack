#!/usr/bin/env bash
# SwiftNetStack E2E — gvproxy comparison test.
#
# Same tests, same VM (SwiftNetStackDemo), same kernel+initramfs as run.sh,
# but replaces the BDP network pipeline with an external gvproxy process.
# This enables same-metric comparison of NAT throughput and behavior.
#
# Usage:
#   ./run_gvproxy.sh                              # all tests
#   ./run_gvproxy.sh --ext-target 192.168.6.6     # with external tests
#   ./run_gvproxy.sh --chaos [loss,reorder,dup]   # chaos testing
#   ./run_gvproxy.sh --timeout 30                 # custom timeout
#
# Prerequisites:
#   - SwiftNetStackDemo built (same as run.sh)
#   - gvproxy binary (built from gvisor-tap-vsock, placed at e2e/gvproxy/bin/gvproxy)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Source shared library ─────────────────────────────────────────────

. "$SCRIPT_DIR/lib.sh"

# ── Parse args ────────────────────────────────────────────────────────

HOST_ARGS=()
EXT_TARGET=""
CHAOS_CMD=""
GVPROXY_SOCK="/tmp/gvproxy-comparison.sock"

while [ $# -gt 0 ]; do
    case "$1" in
        --timeout)       TIMEOUT="$2"; shift 2 ;;
        --host)          HOST_ARGS+=("--host" "$2"); shift 2 ;;
        --ext-target)    EXT_TARGET="$2"; shift 2 ;;
        --ext-iperf-port) EXT_IPERF_PORT="$2"; shift 2 ;;
        --ext-http-port)  EXT_HTTP_PORT="$2"; shift 2 ;;
        --chaos)         parse_chaos_arg "$1" "${2:-}"; shift $([ -n "${2:-}" ] && [ "${2#-}" = "$2" ] && echo 2 || echo 1) ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ── Prerequisites ─────────────────────────────────────────────────────

KERNEL="$SCRIPT_DIR/kernel/Image"
INITRD="$SCRIPT_DIR/initramfs/output/initramfs.cpio.gz"
DEMO_BIN="$PROJECT_DIR/.build/release/SwiftNetStackDemo"

check_prereqs "$KERNEL" "$INITRD"
build_demo "$SCRIPT_DIR" "$PROJECT_DIR"

# ── Locate gvproxy ────────────────────────────────────────────────────

GVPROXY_BIN=""
for candidate in "$SCRIPT_DIR/gvproxy/bin/gvproxy" /tmp/gvisor-tap-vsock/bin/gvproxy; do
    [ -x "$candidate" ] && { GVPROXY_BIN="$candidate"; break; }
done
if [ -z "$GVPROXY_BIN" ]; then
    echo "ERROR: gvproxy not found. Build it first:"
    echo "  git clone https://github.com/containers/gvisor-tap-vsock /tmp/gvisor-tap-vsock"
    echo "  cd /tmp/gvisor-tap-vsock && go build -o bin/gvproxy ./cmd/gvproxy"
    exit 1
fi

# ── Host IP & local services ──────────────────────────────────────────

HOST_IP=$(find_host_ip)
start_local_services "$SCRIPT_DIR" "$HOST_IP"

# ── External server services ──────────────────────────────────────────

start_external_services "$EXT_TARGET"

# ── Chaos (tc netem on external server) ───────────────────────────────

apply_chaos "$EXT_TARGET" "$CHAOS_CMD"

# ── Start gvproxy ─────────────────────────────────────────────────────

rm -f "$GVPROXY_SOCK"
"$GVPROXY_BIN" -listen-vfkit "unixgram://$GVPROXY_SOCK" -mtu 1500 &>/tmp/gvproxy-comparison.log &
GVPROXY_PID=$!
echo "gvproxy: pid $GVPROXY_PID (socket: $GVPROXY_SOCK)"
sleep 1

# ── Run test ──────────────────────────────────────────────────────────

TMPLOG="$(mktemp /tmp/swiftnetstack-gvproxy.XXXXXX.log)"
trap 'stop_local_services; stop_external_services; remove_chaos "$EXT_TARGET"; [ -n "$GVPROXY_PID" ] && kill "$GVPROXY_PID" 2>/dev/null; rm -f "$TMPLOG" "$GVPROXY_SOCK"' EXIT

echo "========================================="
echo "gvproxy Comparison Test Suite"
echo "========================================="
echo "Kernel:  $KERNEL"
echo "Initrd:  $INITRD"
echo "Timeout: ${TIMEOUT}s"
echo "Backend: gvproxy via SwiftNetStackDemo --external-net"
[ ${#HOST_ARGS[@]} -gt 0 ] && echo "Hosts:   ${HOST_ARGS[*]}"
echo ""

echo "Starting demo with external gvproxy networking..."
CMDLINE="console=hvc0 loglevel=4 panic=10 $NAT_CMD $EXT_CMD $CHAOS_CMD"
"$DEMO_BIN" \
    --kernel "$KERNEL" \
    --initrd "$INITRD" \
    --cmdline "$CMDLINE" \
    --cpus 1 --memory 1024 \
    --external-net "$GVPROXY_SOCK" \
    ${HOST_ARGS[@]+"${HOST_ARGS[@]}"} \
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

# ── Report results ────────────────────────────────────────────────────

echo ""
echo "=== Test output ==="
cat "$TMPLOG"
echo "=== End output ==="
echo ""

parse_test_results "$TMPLOG"
print_results "gvproxy Comparison Results"

# Cleanup
kill "$DEMOPID" 2>/dev/null || true
wait "$DEMOPID" 2>/dev/null || true
[ -n "$GVPROXY_PID" ] && kill "$GVPROXY_PID" 2>/dev/null || true
stop_local_services
exit_from_results
