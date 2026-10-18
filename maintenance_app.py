"""Temporary schema-independent NBA Corner fence; standard library only."""

import os
from socketserver import TCPServer, ThreadingMixIn
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer

MESSAGE = b"NBA Corner is temporarily unavailable for maintenance.\n"
HEALTH = b"OK\n"


def application(environ, start_response):
    healthy = environ.get("PATH_INFO") == "/__maintenance_health" and environ.get(
        "REQUEST_METHOD"
    ) in {"GET", "HEAD"}
    body = HEALTH if healthy else MESSAGE
    headers = [
        ("Content-Type", "text/plain; charset=utf-8"),
        ("Server", ""),
        ("Content-Length", str(len(body))),
        ("Cache-Control", "no-store"),
    ]
    if not healthy:
        headers.append(("Retry-After", "300"))
    start_response("200 OK" if healthy else "503 Service Unavailable", headers)
    return [] if environ.get("REQUEST_METHOD") == "HEAD" else [body]


class MaintenanceServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True

    def server_bind(self):
        # Avoid HTTPServer's hostname/DNS lookup; no outbound startup dependency.
        TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = self.server_address[1]
        self.setup_environ()


class QuietHandler(WSGIRequestHandler):
    server_version = ""
    sys_version = ""

    def log_message(self, format, *args):
        # Do not log request URLs, query parameters, headers or bodies.
        pass


def main():
    port = int(os.environ["PORT"])
    if not 1 <= port <= 65535:
        raise ValueError("Invalid runtime port")
    with MaintenanceServer(("0.0.0.0", port), QuietHandler) as server:
        server.set_app(application)
        server.serve_forever()


if __name__ == "__main__":
    main()
