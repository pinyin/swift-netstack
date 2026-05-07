#!/bin/sh
# E2E test framework library.
# Provides assert/report functions and shared state.
# Variables TESTS_PASSED and TESTS_FAILED must be initialized by the caller
# (init script) before sourcing any test scripts.

# ── Assertions ──

test_pass() {
    TEST_COUNT=$((TEST_COUNT + 1))
    TESTS_PASSED="$TESTS_PASSED $1"
    echo "[TEST] $1 PASS"
}

test_fail() {
    TEST_COUNT=$((TEST_COUNT + 1))
    TESTS_FAILED="$TESTS_FAILED $1"
    echo "[TEST] $1 FAIL"
}

test_assert() {
    local name="$1" desc="$2" cmd="$3"
    shift 3
    if eval "$cmd" "$@" >/dev/null 2>&1; then
        test_pass "$name"
    else
        echo "  assert failed: $desc"
        test_fail "$name"
    fi
}

# ── Network state queries ──

get_gateway() {
    ip route show 2>/dev/null | grep default | awk '{print $3}' | head -1
}

get_my_ip() {
    ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1
}

# ── Summary ──

test_summary() {
    local passed_count=$(echo "$TESTS_PASSED" | wc -w | tr -d ' ')
    local failed_count=$(echo "$TESTS_FAILED" | wc -w | tr -d ' ')
    local total=$((passed_count + failed_count))
    echo ""
    echo "========================================="
    echo "E2E Test Suite Summary"
    echo "========================================="
    for t in $TESTS_PASSED; do
        echo "  PASS  $t"
    done
    for t in $TESTS_FAILED; do
        echo "  FAIL  $t"
    done
    echo "-----------------------------------------"
    echo "  $passed_count passed, $failed_count failed, $total total"
    echo "========================================="
}
