#!/usr/bin/env python3
"""TCP, UDP echo and HTTP servers for SwiftNetStack NAT e2e tests.

Usage: python3 echo_servers.py <tcp_port> <udp_port> <http_port> <tcp_close_port> <bidi_port>
"""

import socket
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler


class EchoHandler(BaseHTTPRequestHandler):
    """HTTP handler with test endpoints."""

    def do_GET(self) -> None:
        if self.path == "/slow":
            time.sleep(3)
            body = b"<html><body>\n<h1>Slow Response</h1>\n<p>slow-ok</p>\n</body></html>\n"
        elif self.path == "/large":
            body = b"X" * 102400
        else:
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
    s.listen(256)
    print(f"TCP echo listening on 0.0.0.0:{port}", flush=True)
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=_handle_tcp, args=(conn, addr), daemon=True)
        t.start()


def _handle_tcp(conn: socket.socket, addr: tuple) -> None:
    """TCP echo handler — reads until EOF (FIN), then echoes back.

    No socket timeouts: data arrival and FIN are both protocol-driven.
    The NAT forwards FIN via shutdown(SHUT_WR) once its VM→external send
    queue is drained, so recv() returns b'' naturally.
    """
    try:
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        if data:
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


def tcp_close_first(port: int) -> None:
    """Server that sends a greeting then closes its write side immediately.

    Uses shutdown(SHUT_WR) rather than close() to avoid macOS sending RST
    instead of FIN. The NAT sees this as external EOF and must deliver the
    greeting data before forwarding FIN to the VM.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(8)
    print(f"TCP close-first listening on 0.0.0.0:{port}", flush=True)
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=_handle_close_first, args=(conn, addr), daemon=True)
        t.start()


def _handle_close_first(conn: socket.socket, addr: tuple) -> None:
    """Send greeting, shutdown write, then read any client data."""
    try:
        conn.sendall(b"HELLO-FROM-SERVER\n")
        conn.shutdown(socket.SHUT_WR)
        # Read whatever the client sends (may be empty)
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
    except OSError:
        pass
    finally:
        conn.close()


def tcp_bidi(port: int) -> None:
    """Bidirectional server: receives trigger line, sends 2048 bytes BEFORE
    the client finishes writing, then echoes remaining client data.

    Tests the NAT's ability to handle overlapping bidirectional data flows
    on a single TCP connection — sendQueue and externalSendQueue draining
    simultaneously with correct sequence number tracking.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(8)
    print(f"TCP bidi listening on 0.0.0.0:{port}", flush=True)
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=_handle_bidi, args=(conn, addr), daemon=True)
        t.start()


def _handle_bidi(conn: socket.socket, addr: tuple) -> None:
    """Read trigger line, send bulk data immediately, then read+echo.

    The key design: conn.sendall(2048*'S') fires while client data may
    still be in-flight.  This creates genuine bidirectional TCP flows
    through the NAT with both sendQueue and externalSendQueue active.
    """
    try:
        # Read until newline (trigger)
        trigger = b""
        while not trigger.endswith(b"\n"):
            chunk = conn.recv(1)
            if not chunk:
                return
            trigger += chunk
        # Send bulk data NOW — before client finishes sending its payload
        conn.sendall(b"S" * 2048)
        # Read remaining client data
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        # Echo back with prefix
        if data:
            conn.sendall(b"ECHO:" + data)
    except OSError:
        pass
    finally:
        conn.close()


def main() -> None:
    if len(sys.argv) != 6:
        print(f"Usage: {sys.argv[0]} <tcp_port> <udp_port> <http_port> <tcp_close_port> <bidi_port>", file=sys.stderr)
        sys.exit(1)
    tcp_port = int(sys.argv[1])
    udp_port = int(sys.argv[2])
    http_port = int(sys.argv[3])
    tcp_close_port = int(sys.argv[4])
    bidi_port = int(sys.argv[5])

    threading.Thread(target=tcp_echo, args=(tcp_port,), daemon=True).start()
    threading.Thread(target=udp_echo, args=(udp_port,), daemon=True).start()
    threading.Thread(target=http_server, args=(http_port,), daemon=True).start()
    threading.Thread(target=tcp_close_first, args=(tcp_close_port,), daemon=True).start()
    threading.Thread(target=tcp_bidi, args=(bidi_port,), daemon=True).start()

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
