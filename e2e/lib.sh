#!/usr/bin/env bash
# Shared E2E test infrastructure for SwiftNetStack.
# Sourced by run.sh and run_gvproxy.sh.
#
# Provides:
#   - Default port assignments
#   - Host IP detection
#   - Local echo/iPerf3 server lifecycle
#   - External server (SSH) service lifecycle
#   - Chaos (tc netem) on external server
#   - Demo build & sign helpers
#   - Test result parsing & reporting

set -e

# ── Defaults ──────────────────────────────────────────────────────────

TCP_PORT="${TCP_PORT:-7777}"
UDP_PORT="${UDP_PORT:-7778}"
HTTP_PORT="${HTTP_PORT:-7779}"
TCP_CLOSE_PORT="${TCP_CLOSE_PORT:-7780}"
BIDI_PORT="${BIDI_PORT:-7781}"
IPERF_PORT="${IPERF_PORT:-7782}"
EXT_IPERF_PORT="${EXT_IPERF_PORT:-7782}"
EXT_HTTP_PORT="${EXT_HTTP_PORT:-7783}"
EXT_TCP_ECHO_PORT="${EXT_TCP_ECHO_PORT:-7784}"
TIMEOUT="${TIMEOUT:-120}"

# ── Pre-test cleanup ──────────────────────────────────────────────────

# cleanup_stale_state [ext_target]
# Kills stale processes, removes socket files, and clears tc netem from
# previous runs so ports are free for the current test.
cleanup_stale_state() {
    local ext_target="$1"

    # Kill stale processes from prior runs
    pkill -9 SwiftNetStackDemo 2>/dev/null || true
    pkill -9 gvproxy           2>/dev/null || true
    pkill -9 -f echo_servers.py 2>/dev/null || true

    # Remove stale socket files
    rm -f /tmp/gvproxy-comparison.sock 2>/dev/null || true

    # Remove tc netem from external server
    if [ -n "$ext_target" ]; then
        ssh -o ConnectTimeout=3 -o BatchMode=yes "pinyin@$ext_target" \
            "sudo tc qdisc del dev enp5s0 root 2>/dev/null; sudo tc qdisc del dev eno1 root 2>/dev/null; echo -n" 2>/dev/null || true
    fi

    # Give killed processes time to release their ports
    sleep 1
}

# ── Host IP detection ─────────────────────────────────────────────────

find_host_ip() {
    local ip
    ip=$(ifconfig en0 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1)
    if [ -z "$ip" ]; then
        ip=$(ifconfig en1 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1)
    fi
    echo "$ip"
}

# ── Demo build ────────────────────────────────────────────────────────

# build_demo SCRIPT_DIR PROJECT_DIR
# Builds SwiftNetStackDemo (release) if the binary is missing or stale.
build_demo() {
    local script_dir="$1" project_dir="$2"
    local bin="$project_dir/.build/release/SwiftNetStackDemo"
    if [ ! -x "$bin" ]; then
        echo "Building SwiftNetStackDemo (release)..."
        (cd "$project_dir" && swift build -c release --product SwiftNetStackDemo) || {
            echo "ERROR: Build failed"
            exit 1
        }
    fi
    # Ensure demo is signed
    if ! codesign -d "$bin" 2>/dev/null | grep -q 'authority'; then
        codesign -s - --entitlements /tmp/vm-demo.entitlements -f "$bin" 2>/dev/null || true
    fi
}

# ── Local services (echo servers + iperf3) ────────────────────────────

# start_local_services SCRIPT_DIR HOST_IP → sets ECHO_PID, IPERF_PID, NAT_CMD
# If HOST_IP is empty or python3 is missing, NAT_CMD stays empty.
start_local_services() {
    local script_dir="$1" host_ip="$2"
    ECHO_PID=""
    IPERF_PID=""
    NAT_CMD=""

    if [ -z "$host_ip" ] || ! command -v python3 &>/dev/null; then
        echo "WARNING: python3 or host IP not available, NAT tests will skip"
        return
    fi

    python3 "$script_dir/echo_servers.py" \
        "$TCP_PORT" "$UDP_PORT" "$HTTP_PORT" "$TCP_CLOSE_PORT" "$BIDI_PORT" &
    ECHO_PID=$!
    sleep 0.5

    if kill -0 "$ECHO_PID" 2>/dev/null; then
        NAT_CMD="nat_target=$host_ip nat_tcp_port=$TCP_PORT nat_udp_port=$UDP_PORT nat_http_port=$HTTP_PORT nat_tcp_close_port=$TCP_CLOSE_PORT nat_tcp_bidi_port=$BIDI_PORT nat_iperf_port=$IPERF_PORT"
        echo "Echo servers: TCP:$TCP_PORT UDP:$UDP_PORT HTTP:$HTTP_PORT CLOSE:$TCP_CLOSE_PORT BIDI:$BIDI_PORT (target=$host_ip)"
    else
        ECHO_PID=""
        echo "WARNING: Echo servers failed to start, NAT tests will skip"
    fi

    # iperf3 server (independent of echo_servers.py)
    if [ -n "$host_ip" ] && command -v iperf3 &>/dev/null; then
        iperf3 -s -p "$IPERF_PORT" --daemon 2>/dev/null && IPERF_PID=$!
        if [ -n "$IPERF_PID" ]; then
            echo "iperf3 server: port $IPERF_PORT (pid $IPERF_PID)"
        fi
    fi
}

# stop_local_services
stop_local_services() {
    [ -n "${ECHO_PID:-}" ] && kill "$ECHO_PID" 2>/dev/null || true
    [ -n "${IPERF_PID:-}" ] && kill "$IPERF_PID" 2>/dev/null || true
}

# ── External server services ──────────────────────────────────────────

# start_external_iperf EXT_TARGET → sets EXT_IPERF_SSH_PID
start_external_iperf() {
    local target="$1"
    EXT_IPERF_SSH_PID=""
    if ssh -o ConnectTimeout=3 -o BatchMode=yes "pinyin@$target" \
        "iperf3 -c 127.0.0.1 -p $EXT_IPERF_PORT -t 1 2>&1" >/dev/null 2>&1; then
        echo "iperf3 already running on $target:$EXT_IPERF_PORT"
    else
        ssh -o ConnectTimeout=3 -o BatchMode=yes "pinyin@$target" \
            "killall iperf3 2>/dev/null; nohup iperf3 -s -p $EXT_IPERF_PORT --daemon" 2>/dev/null &
        EXT_IPERF_SSH_PID=$!
        sleep 0.5
        echo "Started iperf3 on $target:$EXT_IPERF_PORT"
    fi
}

# start_external_http EXT_TARGET → sets EXT_HTTP_SSH_PID
start_external_http() {
    local target="$1"
    EXT_HTTP_SSH_PID=""
    if ssh -o ConnectTimeout=3 -o BatchMode=yes "pinyin@$target" \
        "curl -s http://127.0.0.1:$EXT_HTTP_PORT/ 2>&1" >/dev/null 2>&1; then
        echo "HTTP already running on $target:$EXT_HTTP_PORT"
    else
        ssh -o ConnectTimeout=3 -o BatchMode=yes "pinyin@$target" \
            "killall python3 2>/dev/null; mkdir -p /tmp/http-test; echo 'ext-http-ok' > /tmp/http-test/index.html; cd /tmp/http-test && nohup python3 -m http.server $EXT_HTTP_PORT --bind 0.0.0.0 > /tmp/http-server.log 2>&1 &" 2>/dev/null &
        EXT_HTTP_SSH_PID=$!
        sleep 1
        echo "Started HTTP on $target:$EXT_HTTP_PORT"
    fi
}

# start_external_tcp_echo EXT_TARGET → sets EXT_TCP_ECHO_SSH_PID
start_external_tcp_echo() {
    local target="$1"
    EXT_TCP_ECHO_SSH_PID=""
    local pidfile="/tmp/ext-echo-pid-$$"
    ssh -o ConnectTimeout=3 -o BatchMode=yes "pinyin@$target" \
        "kill \$(cat /tmp/tcp-echo-server.pid 2>/dev/null) 2>/dev/null; nohup python3 -u /tmp/tcp-echo-server.py > /tmp/tcp-echo.log 2>&1 & echo \$!" \
        > "$pidfile" 2>/dev/null
    if [ -s "$pidfile" ]; then
        EXT_TCP_ECHO_SSH_PID=$(cat "$pidfile")
        echo "Started TCP echo on $target:$EXT_TCP_ECHO_PORT"
    fi
    rm -f "$pidfile"
}

# start_external_services EXT_TARGET
# Starts iPerf3, HTTP, and TCP echo on the remote server.
# Sets EXT_IPERF_SSH_PID, EXT_HTTP_SSH_PID, EXT_TCP_ECHO_SSH_PID, EXT_CMD.
start_external_services() {
    local target="$1"
    EXT_CMD=""
    if [ -z "$target" ]; then return; fi

    echo "External target: $target"
    start_external_iperf "$target"
    start_external_http "$target"
    start_external_tcp_echo "$target"

    EXT_CMD="ext_target=$target ext_iperf_port=$EXT_IPERF_PORT ext_http_port=$EXT_HTTP_PORT ext_tcp_echo_port=$EXT_TCP_ECHO_PORT"
}

# stop_external_services
stop_external_services() {
    [ -n "${EXT_IPERF_SSH_PID:-}" ] && kill "$EXT_IPERF_SSH_PID" 2>/dev/null || true
    [ -n "${EXT_HTTP_SSH_PID:-}" ] && kill "$EXT_HTTP_SSH_PID" 2>/dev/null || true
    [ -n "${EXT_TCP_ECHO_SSH_PID:-}" ] && kill "$EXT_TCP_ECHO_SSH_PID" 2>/dev/null || true
}

# ── Chaos / tc netem ──────────────────────────────────────────────────

# apply_chaos EXT_TARGET CHAOS_CMD → sets EXT_NETEM_ACTIVE
apply_chaos() {
    local target="$1" chaos_cmd="$2"
    EXT_NETEM_ACTIVE=""
    if [ -z "$chaos_cmd" ] || [ -z "$target" ]; then return; fi

    local loss reorder dup
    loss=$(echo "$chaos_cmd" | grep -o 'chaos_loss=[0-9]*' | cut -d= -f2)
    reorder=$(echo "$chaos_cmd" | grep -o 'chaos_reorder=[0-9]*' | cut -d= -f2)
    dup=$(echo "$chaos_cmd" | grep -o 'chaos_dup=[0-9]*' | cut -d= -f2)
    loss=${loss:-5}; reorder=${reorder:-10}; dup=${dup:-3}

    echo "Applying tc netem on $target..."
    if ssh -o ConnectTimeout=3 -o BatchMode=yes "pinyin@$target" \
        "sudo tc qdisc replace dev enp5s0 root netem delay 1ms loss ${loss}% reorder ${reorder}% duplicate ${dup}%" 2>/dev/null; then
        EXT_NETEM_ACTIVE="yes"
        echo "tc netem applied on $target (loss=${loss}% reorder=${reorder}% dup=${dup}%)"
    else
        echo "WARNING: Failed to apply tc netem on $target"
    fi
}

# remove_chaos EXT_TARGET
remove_chaos() {
    local target="$1"
    if [ -n "${EXT_NETEM_ACTIVE:-}" ] && [ -n "$target" ]; then
        ssh -o ConnectTimeout=3 -o BatchMode=yes "pinyin@$target" \
            "sudo tc qdisc del dev enp5s0 root" 2>/dev/null || true
        echo "tc netem removed on $target"
    fi
}

# ── Test result parsing ───────────────────────────────────────────────

# parse_test_results LOGFILE → sets PASSED[], FAILED[], TOTAL
parse_test_results() {
    local log="$1"
    PASSED=()
    FAILED=()
    while IFS= read -r line; do
        if echo "$line" | grep -q '\[TEST\] .* PASS'; then
            local name
            name=$(echo "$line" | sed 's/.*\[TEST\] //;s/ PASS.*//')
            PASSED+=("$name")
        elif echo "$line" | grep -q '\[TEST\] .* FAIL'; then
            local name
            name=$(echo "$line" | sed 's/.*\[TEST\] //;s/ FAIL.*//')
            FAILED+=("$name")
        fi
    done < "$log"
    TOTAL=$((${#PASSED[@]} + ${#FAILED[@]}))
}

# print_results HEADING
print_results() {
    local heading="${1:-Test Results}"
    echo ""
    echo "========================================="
    echo "$heading"
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
}

# exit_from_results — exit 1 if any failures or zero tests, else 0
exit_from_results() {
    if [ ${#FAILED[@]} -gt 0 ]; then
        exit 1
    elif [ "$TOTAL" -eq 0 ]; then
        echo "WARNING: No test markers found (VM may have failed to boot)"
        exit 1
    else
        exit 0
    fi
}

# ── Prerequisites ─────────────────────────────────────────────────────

# check_prereqs KERNEL INITRD
check_prereqs() {
    local kernel="$1" initrd="$2"
    if [ ! -f "$kernel" ]; then
        echo "ERROR: kernel not found at $kernel"
        exit 1
    fi
    if [ ! -f "$initrd" ]; then
        echo "ERROR: initramfs not found at $initrd"
        echo "Build it first: cd e2e/initramfs && bash build.sh  (on the local server)"
        exit 1
    fi
}

# ── Chaos cmdline parsing ─────────────────────────────────────────────

# parse_chaos_arg "$1" "$2" → sets CHAOS_CMD
parse_chaos_arg() {
    local arg="$1" val="$2"
    local loss=5 reorder=10 dup=3
    if [ -n "$val" ] && [ "${val#-}" = "$val" ]; then
        IFS=',' read -r a b c <<< "$val"
        loss="${a:-5}"; reorder="${b:-10}"; dup="${c:-3}"
    fi
    CHAOS_CMD="chaos_loss=$loss chaos_reorder=$reorder chaos_dup=$dup"
}
