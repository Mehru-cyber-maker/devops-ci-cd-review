"""Loopback-only dashboard; no uploads are written or executed."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path

from .core import InputError, MAX_JSON_BYTES, evaluate, parse_json
from .demo import demo_bundle

WEB = Path(__file__).parent / "web"
ASSETS = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
          "/style.css": ("style.css", "text/css")}


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "EvidenceGate"

    def log_message(self, *args):
        # Keep document content and request paths out of logs.
        pass

    def _allowed(self):
        port = self.server.server_address[1]
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if self.headers.get("Host") not in hosts:
            self._json({"error": "Use the loopback dashboard address."}, 421)
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin not in {"http://" + host for host in hosts}:
            self._json({"error": "Cross-origin requests are not accepted."}, 403)
            return False
        return True

    def _send(self, body: bytes, content_type: str, status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, status=200):
        self._send(json.dumps(data).encode("utf-8"), "application/json", status)

    def do_GET(self):
        if not self._allowed():
            return
        if self.path == "/api/demo":
            self._json(demo_bundle())
        elif self.path in ASSETS:
            name, mime = ASSETS[self.path]
            self._send((WEB/name).read_bytes(), mime)
        else:
            self._json({"error": "Not found."}, 404)

    def do_POST(self):
        if not self._allowed():
            return
        if self.path != "/api/check":
            self._json({"error": "Not found."}, 404)
            return
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            self._json({"error": "Send application/json."}, 415)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= MAX_JSON_BYTES:
                raise InputError("Request must be between 1 byte and 8 MiB.")
            payload = parse_json(self.rfile.read(size))
            expected_keys = {"artifact_sha256", "provenance", "sbom", "scan", "policy"}
            if not isinstance(payload, dict) or set(payload) != expected_keys:
                raise InputError("Request must contain artifact_sha256, provenance, sbom, scan, and policy.")
            # Uploaded JSON is retained as text until strict duplicate-key parsing here.
            docs = [parse_json(payload[n].encode("utf-8")) if isinstance(payload[n], str) else payload[n]
                    for n in ["provenance", "sbom", "scan", "policy"]]
            self._json(evaluate(payload["artifact_sha256"], *docs))
        except (InputError, ValueError) as exc:
            self._json({"error": str(exc)}, 422)


def make_server(port=8765):
    return ThreadingHTTPServer(("127.0.0.1", port), DashboardHandler)


def serve(port=8765):
    with make_server(port) as server:
        print(f"EvidenceGate dashboard: http://127.0.0.1:{server.server_address[1]}", flush=True)
        print("Local processing only. Press Ctrl+C to stop.", flush=True)
        server.serve_forever()
