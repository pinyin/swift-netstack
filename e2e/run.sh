#!/usr/bin/env bash
# SwiftNetStack DHCP E2E test runner.
#
# Builds initramfs if needed, launches the demo with the kernel and initrd,
# waits for DHCP lease, and reports pass/fail.
#
# Prerequisites:
#   - Swift toolchain (swift build)
#   - codesign with com.apple.security.virtualization entitlement
#   - e2e/kernel/Image (built separately or copied from minimal-vfkit-kernel)
#
# Usage: ./run.sh [--timeout SECONDS]

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMEOUT=25

while [ $# -gt 0 ]; do
    case "$1" in
        --timeout) TIMEOUT="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

KERNEL="$SCRIPT_DIR/kernel/Image"
INITRD="$SCRIPT_DIR/initramfs/initramfs.cpio.gz"
DEMO_BIN="$PROJECT_DIR/.build/debug/SwiftNetStackDemo"

# ── Validate prerequisites ──

if [ ! -f "$KERNEL" ]; then
    echo "ERROR: kernel not found at $KERNEL"
    echo "Copy the aarch64 kernel Image to e2e/kernel/Image"
    exit 1
fi

# Build initramfs if not present or if source is newer
if [ ! -f "$INITRD" ] || [ "$SCRIPT_DIR/initramfs/init" -nt "$INITRD" ] || [ "$SCRIPT_DIR/initramfs/udhcpc.script" -nt "$INITRD" ]; then
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
    echo "Signing demo with ad-hoc signature..."
    codesign -s - --entitlements /tmp/vm-demo.entitlements -f "$DEMO_BIN" 2>/dev/null || {
        echo "NOTE: codesign failed, VM may not start"
    }
fi

# ── Run test ──

TMPLOG="$(mktemp /tmp/swiftnetstack-e2e.XXXXXX.log)"
trap 'rm -f "$TMPLOG"' EXIT

echo "========================================="
echo "SwiftNetStack DHCP E2E Test"
echo "========================================="
echo "Kernel:  $KERNEL"
echo "Initrd:  $INITRD"
echo "Timeout: ${TIMEOUT}s"
echo "Log:     $TMPLOG"
echo ""

echo "Starting demo..."
"$DEMO_BIN" \
    --kernel "$KERNEL" \
    --initrd "$INITRD" \
    --cmdline "console=hvc0 init=/init loglevel=4 panic=10" \
    --cpus 1 --memory 512 \
    >"$TMPLOG" 2>&1 &
DEMOPID=$!

# Wait for DHCP lease or timeout
PASS=0
DEADLINE=$(($(date +%s) + TIMEOUT))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    if grep -q "lease of .* obtained" "$TMPLOG" 2>/dev/null; then
        PASS=1
        sleep 1  # let ping finish
        break
    fi
    if ! kill -0 "$DEMOPID" 2>/dev/null; then
        echo "Demo exited early (PID $DEMOPID)"
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

# Extract key info
LEASE=$(grep -o 'lease of [0-9.]* obtained' "$TMPLOG" 2>/dev/null || true)
PING=$(grep -o '[0-9]* packets transmitted, [0-9]* received' "$TMPLOG" 2>/dev/null || true)

if [ "$PASS" -eq 1 ]; then
    echo ""
    echo "========================================="
    echo "PASS: $LEASE"
    if [ -n "$PING" ]; then
        echo "      $PING"
    fi
    echo "========================================="
    EXIT=0
else
    echo ""
    echo "========================================="
    echo "FAIL: DHCP lease not obtained within ${TIMEOUT}s"
    echo "========================================="
    EXIT=1
fi

# Cleanup
kill "$DEMOPID" 2>/dev/null || true
wait "$DEMOPID" 2>/dev/null || true

exit $EXIT
