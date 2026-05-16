#!/usr/bin/env bash
# Rebuild initramfs on the server (NFS-shared ~/developer).
# Edit test scripts locally, then run this. No rsync needed.
#
# Usage: bash e2e/rebuild-initramfs.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER="pinyin@192.168.6.6"
SERVER_PATH="~/Developer/POC/swift-netstack-refactor/e2e/initramfs"

echo "=== Building initramfs on server ==="
ssh "$SERVER" "cd $SERVER_PATH && bash build.sh"

echo "=== Done ==="
echo "Run: cd $(cd "$SCRIPT_DIR/.." && pwd) && bash e2e/run.sh"
