#!/usr/bin/env python3
"""TCP, UDP echo and HTTP servers for SwiftNetStack NAT e2e tests.

Usage: python3 echo_servers.py <tcp_port> <udp_port> <http_port>
"""

import socket
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler


class EchoHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler that returns a fixed test page."""

    def do_GET(self) -> None:
        body = (
            b"<html><body>\n"
            b"<h1>SwiftNetStack E2E HTTP Test</h1>\n"
            b"<p>endpoint-ok</p>\n"
            b"</body></html>\n"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # suppress stderr logging


def http_server(port: int) -> None:
    srv = HTTPServer(("0.0.0.0", port), EchoHandler)
    print(f"HTTP server listening on 0.0.0.0:{port}", flush=True)
    srv.serve_forever()


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
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <tcp_port> <udp_port> <http_port>", file=sys.stderr)
        sys.exit(1)
    tcp_port = int(sys.argv[1])
    udp_port = int(sys.argv[2])
    http_port = int(sys.argv[3])

    threading.Thread(target=tcp_echo, args=(tcp_port,), daemon=True).start()
    threading.Thread(target=udp_echo, args=(udp_port,), daemon=True).start()
    threading.Thread(target=http_server, args=(http_port,), daemon=True).start()

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
