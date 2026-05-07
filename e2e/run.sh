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
TIMEOUT=25
INIT="/init"
HOST_ARGS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --host)
            HOST_ARGS+=("--host" "$2")
            shift 2
            ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

KERNEL="$SCRIPT_DIR/kernel/Image"
INITRD="$SCRIPT_DIR/initramfs/initramfs.cpio.gz"
DEMO_BIN="$PROJECT_DIR/.build/debug/SwiftNetStackDemo"

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
    echo "Building SwiftNetStackDemo..."
    (cd "$PROJECT_DIR" && swift build --product SwiftNetStackDemo) || {
        echo "ERROR: Build failed"
        exit 1
    }
fi

# Ensure demo is signed
if ! codesign -d "$DEMO_BIN" 2>/dev/null | grep -q 'authority'; then
    codesign -s - --entitlements /tmp/vm-demo.entitlements -f "$DEMO_BIN" 2>/dev/null || true
fi

# ── Run test ──

TMPLOG="$(mktemp /tmp/swiftnetstack-e2e.XXXXXX.log)"
trap 'rm -f "$TMPLOG"' EXIT

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
    --cmdline "console=hvc0 init=$INIT loglevel=4 panic=10" \
    --cpus 1 --memory 512 \
    ${HOST_ARGS[@]+"${HOST_ARGS[@]}"} \
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

if [ ${#FAILED[@]} -gt 0 ]; then
    exit 1
elif [ "$TOTAL" -eq 0 ]; then
    echo "WARNING: No test markers found (VM may have failed to boot)"
    exit 1
else
    exit 0
fi
