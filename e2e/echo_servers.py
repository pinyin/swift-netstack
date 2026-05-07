#!/usr/bin/env python3
"""TCP and UDP echo servers for SwiftNetStack NAT e2e tests.

Usage: python3 echo_servers.py <tcp_port> <udp_port>
"""

import socket
import sys
import threading


def tcp_echo(port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(8)
    print(f"TCP echo listening on 0.0.0.0:{port}", flush=True)
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=_handle_tcp, args=(conn, addr), daemon=True)
        t.start()


def _handle_tcp(conn: socket.socket, addr: tuple) -> None:
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(data)
    except OSError:
        pass
    finally:
        conn.close()


def udp_echo(port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    print(f"UDP echo listening on 0.0.0.0:{port}", flush=True)
    while True:
        data, addr = s.recvfrom(4096)
        s.sendto(data, addr)


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <tcp_port> <udp_port>", file=sys.stderr)
        sys.exit(1)
    tcp_port = int(sys.argv[1])
    udp_port = int(sys.argv[2])

    threading.Thread(target=tcp_echo, args=(tcp_port,), daemon=True).start()
    threading.Thread(target=udp_echo, args=(udp_port,), daemon=True).start()

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
