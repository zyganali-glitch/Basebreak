"""HTTP API server and request handler for Basebreak orchestrator.

P-21.02 & P-21.03: REST endpoints and SSE event streaming without external web frameworks.
"""

from __future__ import annotations

import http.server
import json
import re
import socketserver
import threading
from typing import Any
from urllib.parse import urlparse

from basebreak.api.auth import ApiAuthManager
from basebreak.api.models import RunCreateRequest
from basebreak.api.store import ApiRunStore, IdempotencyConflictError

_RUN_ID_ROUTE_PATTERN = re.compile(
    r"^/v1/runs/(?P<run_id>[A-Za-z0-9_.-]+)(?P<subpath>/evidence|/receipt|/events)?/?$"
)


MAX_REQUEST_BODY_BYTES: int = 1024 * 1024  # 1 MB


class BasebreakRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for Basebreak REST API and SSE event stream."""

    store: ApiRunStore
    auth: ApiAuthManager

    def _send_json(self, status_code: int, data: Any) -> None:
        """Send JSON response with secret redaction and headers."""
        body_text = self.auth.serialize_secret_safe(data)
        body_bytes = body_text.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body_bytes)

    def _send_error(self, status_code: int, message: str) -> None:
        """Send structured JSON error."""
        self._send_json(status_code, {"error": message, "status_code": status_code})

    def _check_auth(self, *, is_execution: bool = False) -> bool:
        """Verify authorization header with fail-closed enforcement for execution."""
        auth_hdr = self.headers.get("Authorization")
        if not self.auth.validate_auth_header(auth_hdr, is_execution=is_execution):
            self._send_error(401, "Unauthorized: missing or invalid Bearer token.")
            return False
        return True

    def do_POST(self) -> None:
        """Handle POST requests."""
        if not self._check_auth(is_execution=True):
            return

        parsed_url = urlparse(self.path)
        if parsed_url.path == "/v1/runs":
            content_len = int(self.headers.get("Content-Length", 0))
            if content_len <= 0:
                self._send_error(400, "Request body cannot be empty.")
                return
            if content_len > MAX_REQUEST_BODY_BYTES:
                self._send_error(
                    413,
                    f"Request payload too large: {content_len} bytes "
                    f"exceeds {MAX_REQUEST_BODY_BYTES} bytes limit.",
                )
                return

            try:
                body_bytes = self.rfile.read(content_len)
                body_json = json.loads(body_bytes.decode("utf-8"))
            except Exception as exc:
                self._send_error(400, f"Malformed JSON payload: {exc}")
                return

            # Extract Idempotency-Key from header or body
            idemp_header = self.headers.get("Idempotency-Key")
            if idemp_header and not body_json.get("idempotency_key"):
                body_json["idempotency_key"] = idemp_header.strip()

            try:
                req = RunCreateRequest.from_dict(body_json)
                run_meta, is_new = self.store.create_or_get_run(req)
                status_code = 201 if is_new else 200
                self._send_json(status_code, run_meta)
            except IdempotencyConflictError as exc:
                self._send_error(409, str(exc))
            except ValueError as exc:
                self._send_error(400, str(exc))
            except Exception as exc:
                self._send_error(500, f"Internal server error: {exc}")
        else:
            self._send_error(404, f"Endpoint not found: {self.path}")

    def do_GET(self) -> None:
        """Handle GET requests."""
        if not self._check_auth(is_execution=False):
            return

        parsed_url = urlparse(self.path)
        path = parsed_url.path

        match = _RUN_ID_ROUTE_PATTERN.match(path)
        if not match:
            self._send_error(404, f"Endpoint not found: {path}")
            return

        run_id = match.group("run_id")
        subpath = match.group("subpath") or ""

        run_meta = self.store.get_run(run_id)
        if run_meta is None:
            self._send_error(404, f"Run '{run_id}' not found.")
            return

        if not subpath:
            # GET /v1/runs/{run_id}
            self._send_json(200, run_meta)
        elif subpath == "/evidence":
            # GET /v1/runs/{run_id}/evidence
            evidence = self.store.get_evidence(run_id)
            self._send_json(200, {"run_id": run_id, "evidence": evidence})
        elif subpath == "/receipt":
            # GET /v1/runs/{run_id}/receipt
            receipt = self.store.get_receipt(run_id)
            if receipt is None:
                self._send_error(404, f"Public receipt for run '{run_id}' not found.")
                return

            # Mandatory receipt integrity verification before presentation
            from basebreak.causal.public_receipt import (
                PublicVerificationReceipt,
                verify_public_receipt_integrity,
            )

            try:
                verified_rc = PublicVerificationReceipt.from_dict(receipt)
                verify_public_receipt_integrity(verified_rc)
            except Exception as exc:
                self._send_error(400, f"Receipt integrity verification failed: {exc}")
                return

            self._send_json(200, receipt)
        elif subpath == "/events":
            # GET /v1/runs/{run_id}/events (Server-Sent Events)
            events = self.store.get_events(run_id)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()

            from basebreak.security.secret_policy import redact_text

            for ev in events:
                sse_chunk = ev.to_sse()
                safe_sse, _ = redact_text(sse_chunk)
                self.wfile.write(safe_sse.encode("utf-8"))
                self.wfile.flush()
        else:
            self._send_error(404, f"Unknown subpath: {subpath}")

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default console logging to avoid test clutter."""
        return


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded HTTP Server for concurrency."""

    daemon_threads = True
    allow_reuse_address = True


class BasebreakApiServer:
    """Orchestrator server lifecycle controller."""

    def __init__(
        self,
        store: ApiRunStore,
        auth: ApiAuthManager | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.store = store
        self.auth = auth or ApiAuthManager()
        self.host = host
        self.port = port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def server_address(self) -> tuple[str, int]:
        if not self._httpd:
            raise RuntimeError("Server is not running")
        addr = self._httpd.server_address
        return str(addr[0]), int(addr[1])

    @property
    def base_url(self) -> str:
        host, port = self.server_address
        return f"http://{host}:{port}"

    def start(self) -> None:
        """Start server in background thread."""
        handler_class = BasebreakRequestHandler
        handler_class.store = self.store
        handler_class.auth = self.auth

        self._httpd = ThreadingHTTPServer((self.host, self.port), handler_class)
        self.port = self._httpd.server_address[1]

        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Shut down server cleanly."""
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
