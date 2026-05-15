# SwiftNetStack

User-space TCP/IP NAT gateway for macOS [Virtualization.framework](https://developer.apple.com/documentation/virtualization) VMs. Single-threaded BDP (poll → parse → process → write) pipeline with zero heap allocation in hot paths.

## Quick Start

```bash
swift build -c release --product SwiftNetStackDemo
codesign -s - --entitlements /tmp/vm-demo.entitlements -f .build/release/SwiftNetStackDemo
```

Entitlements file (`/tmp/vm-demo.entitlements`):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict><key>com.apple.security.virtualization</key><true/></dict>
</plist>
```

### Linux Boot

```bash
.build/release/SwiftNetStackDemo \
  --kernel /path/to/vmlinux --initrd /path/to/initrd \
  --cmdline "console=hvc0" \
  --subnet 100.64.1.0/24 --gateway 100.64.1.1
```

### EFI Boot

```bash
.build/release/SwiftNetStackDemo \
  --disk /path/to/disk.img --efi-store /path/to/efi-store \
  --subnet 100.64.1.0/24 --gateway 100.64.1.1
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--kernel` | — | Linux kernel Image (aarch64) |
| `--initrd` | — | Initial ramdisk |
| `--disk` | — | Disk image for EFI boot |
| `--efi-store` | — | EFI variable store |
| `--cmdline` | `console=hvc0` | Kernel command line |
| `--cpus` | 2 | VM CPU count |
| `--memory` | 1024 | VM memory in MB |
| `--mac` | `72:20:43:51:64:01` | VM MAC address |
| `--subnet` | `100.64.1.0/24` | NAT subnet |
| `--gateway` | `100.64.1.1` | Gateway IP |
| `--host name:IP` | — | DNS hosts-file entry (repeatable) |
| `--dns` | — | Upstream DNS server (auto-detected from /etc/resolv.conf) |
| `--mtu` | 1500 | MTU |
| `--pcap` | — | Write packets to .pcap for Wireshark |
| `--external-net` | — | gvproxy unixgram socket path (disables internal NAT) |

## Architecture

```
 ┌──────────┐     virtio-net     ┌──────────────────────────────┐
 │  VM (Linux)│ ◄──────────────► │  SwiftNetStack                │
 │  eth0     │     raw frames    │                               │
 └──────────┘                    │  poll() ─► parse ─► NAT/FSM  │
                                 │    ▲                        │  │
                                 │    └── writeBatch() ◄───────┘  │
                                 └────────────┬─────────────────┘
                                              │ POSIX sockets
                                              ▼
                                        ┌──────────┐
                                        │ Internet │
                                        └──────────┘
```

- **Phase 1**: `poll()` over VM endpoint + external FDs
- **Phase 2-6**: Parse Ethernet → IPv4 (with fragment reassembly) → TCP/UDP/ICMP
- **Phase 7-8**: ICMP echo reply, unreachable generation
- **Phase 9-10**: UDP NAT (DHCP on 67, DNS on 53, generic UDP)
- **Phase 11**: TCP NAT (state machine, delayed ACK, fast retransmit, RTO)
- **Phase 12-15**: NAT transport result, DNS upstream, DHCP server, ARP
- **Phase 16**: Batch write + timer cleanup

### Protocol Support

- **ARP**: Proxy ARP for gateway IP and NAT pool addresses
- **DHCP**: Server with lease pool (100.64.1.60-253), renewal, expiration
- **DNS**: Static hosts file + upstream forwarding with query tracking
- **ICMP**: Echo reply, TTL-exceeded, port/protocol unreachable (RFC 792)
- **TCP**: Full NAT proxy with RFC 793 state machine, RFC 5681 fast retransmit/recovery, RFC 6298 RTO, RFC 1323 window scaling, RFC 1122 delayed ACK
- **UDP**: Per-endpoint mapping with NAT cone semantics

## Tests

### Unit Tests

```bash
swift test --no-parallel
```

60 tests covering ARP aging, ICMP unreachable, IPv4 TTL/fragment, TCP checksum, TCP connection (OOO buffer, send queue, persist timer), and TCP state machine (all 8 states, wraparound, rewind prevention).

### E2E Tests

Full-stack tests: boot a Linux VM with SwiftNetStack as the NAT gateway, then run test scripts inside the VM against echo/iPerf3/HTTP servers on the host.

**Prerequisites:**
- macOS with `com.apple.security.virtualization` entitlement
- Linux kernel at `e2e/kernel/Image` (aarch64)
- initramfs at `e2e/initramfs/output/initramfs.cpio.gz` (build on server: `cd e2e/initramfs && bash build.sh`)
- `python3`, `iperf3` on macOS host
- For chaos/external tests: SSH access to a remote Linux server

```bash
# All tests (local only, skips chaos/external)
bash e2e/run.sh --timeout 300

# With external server for chaos & external NAT tests
bash e2e/run.sh --timeout 300 --ext-target 192.168.6.6

# Chaos testing (tc netem loss/reorder/dup on external server)
bash e2e/run.sh --timeout 300 --ext-target 192.168.6.6 --chaos 5,10,3

# With pcap capture
bash e2e/run.sh --timeout 300 --pcap /tmp/e2e.pcap
```

**Test suite** (23 tests):

| Category | Tests |
|---|---|
| Infrastructure | dhcp, icmp, arp, dns, routing |
| UDP NAT | nat-udp, nat-udp-large |
| TCP NAT | nat-tcp, nat-tcp-large, nat-tcp-slow, nat-tcp-rst, nat-tcp-bidi, nat-tcp-binary, nat-tcp-large-multi-seg, nat-tcp-server-close, nat-tcp-conn-refused |
| Concurrency | nat-tcp-concurrent, nat-tcp-concurrent-50, nat-tcp-stress (100/200 conn) |
| Throughput | nat-iperf (8p × 3s), nat-external-iperf (optional), chaos-iperf (optional) |
| HTTP | nat-http-host, nat-http-internet |
