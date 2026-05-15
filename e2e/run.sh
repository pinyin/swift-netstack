#!/usr/bin/env bash
# SwiftNetStack E2E test runner.
#
# Launches a Linux VM with the BDP pipeline and runs comprehensive
# networking tests (DHCP, ICMP, ARP, DNS, routing, NAT, chaos).
#
# Usage:
#   ./run.sh                              # all tests (Fedora bootc initramfs)
#   ./run.sh --host test.local:1.2.3.4   # with DNS hostname
#   ./run.sh --timeout 30                 # custom timeout
#   ./run.sh --ext-target 192.168.6.6     # external server for NAT tests
#   ./run.sh --chaos [loss,reorder,dup]  # chaos testing (default 5,10,3)
#
# Prerequisites:
#   - Swift toolchain (swift build)
#   - com.apple.security.virtualization entitlement
#   - e2e/kernel/Image (aarch64 Linux kernel)
#   - e2e/initramfs/output/initramfs.cpio.gz (build on server)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Source shared library ─────────────────────────────────────────────

. "$SCRIPT_DIR/lib.sh"

# ── Parse args ────────────────────────────────────────────────────────

HOST_ARGS=()
PCAP_PATH=""
MTU=""
EXT_TARGET=""
CHAOS_CMD=""

while [ $# -gt 0 ]; do
    case "$1" in
        --timeout)       TIMEOUT="$2"; shift 2 ;;
        --host)          HOST_ARGS+=("--host" "$2"); shift 2 ;;
        --pcap)          PCAP_PATH="$2"; shift 2 ;;
        --mtu)           MTU="$2"; shift 2 ;;
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

# ── Cleanup stale state from previous runs ────────────────────────────

cleanup_stale_state "$EXT_TARGET"

# ── Host IP & local services ──────────────────────────────────────────

HOST_IP=$(find_host_ip)
start_local_services "$SCRIPT_DIR" "$HOST_IP"

# ── External server services ──────────────────────────────────────────

start_external_services "$EXT_TARGET"

# ── Chaos (tc netem on external server) ───────────────────────────────

apply_chaos "$EXT_TARGET" "$CHAOS_CMD"

# ── Run test ──────────────────────────────────────────────────────────

TMPLOG="$(mktemp /tmp/swiftnetstack-e2e.log.XXXXXX)"
trap 'stop_local_services; stop_external_services; remove_chaos "$EXT_TARGET"; rm -f "$TMPLOG"' EXIT

echo "========================================="
echo "SwiftNetStack E2E Test Suite"
echo "========================================="
echo "Kernel:  $KERNEL"
echo "Initrd:  $INITRD"
echo "Timeout: ${TIMEOUT}s"
[ ${#HOST_ARGS[@]} -gt 0 ] && echo "Hosts:   ${HOST_ARGS[*]}"
echo ""

echo "Starting demo..."
CMDLINE="console=hvc0 loglevel=4 panic=10 ${MTU:+MTU=$MTU }$NAT_CMD $EXT_CMD $CHAOS_CMD"
"$DEMO_BIN" \
    --kernel "$KERNEL" \
    --initrd "$INITRD" \
    --cmdline "$CMDLINE" \
    --cpus 1 --memory 1024 \
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

# ── Report results ────────────────────────────────────────────────────

echo ""
echo "=== Test output ==="
cat "$TMPLOG"
echo "=== End output ==="
echo ""

parse_test_results "$TMPLOG"
print_results "E2E Test Results"

# Cleanup
kill "$DEMOPID" 2>/dev/null || true
wait "$DEMOPID" 2>/dev/null || true
stop_local_services
exit_from_results
