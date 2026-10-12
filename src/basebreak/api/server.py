"""HTTP API server and request handler for Basebreak orchestrator.

P-21.02 & P-21.03: REST endpoints and SSE event streaming without external web frameworks.
"""

from __future__ import annotations

import http.server
import json
import re
import socketserver
import threading
import time
from typing import Any
from urllib.parse import urlparse

from basebreak.api.auth import ApiAuthManager
from basebreak.api.models import RunCreateRequest
from basebreak.api.store import ApiRunStore, IdempotencyConflictError, UnpublishableRunError

_RUN_ID_ROUTE_PATTERN = re.compile(
    r"^/v1/runs/(?P<run_id>[A-Za-z0-9_.-]+)(?P<subpath>/evidence|/receipt|/events)?/?$"
)
_JUDGE_UI_ROUTE_PATTERN = re.compile(r"^/(?:judge|ui)(?:/(?P<run_id>[A-Za-z0-9_.-]+))?/?$")
_HEALTH_ROUTE_PATTERN = re.compile(r"^/(?:v1/)?health(?:z)?/?$")
_PUBLISH_ROUTE_PATTERN = re.compile(r"^/v1/runs/(?P<run_id>[A-Za-z0-9_.-]+)/publish/?$")


MAX_REQUEST_BODY_BYTES: int = 1024 * 1024  # 1 MB


class BasebreakRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for Basebreak REST API and SSE event stream."""

    store: ApiRunStore
    auth: ApiAuthManager
    server_start_time: float | None = None

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

    def _send_html(self, status_code: int, html_content: str) -> None:
        """Send HTML response with secret redaction and headers."""
        from basebreak.security.secret_policy import redact_text

        safe_html, _ = redact_text(html_content)
        body_bytes = safe_html.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body_bytes)

    def _check_auth(self, *, is_execution: bool = False) -> bool:
        """Verify authorization header with fail-closed enforcement for execution."""
        auth_hdr = self.headers.get("Authorization")
        if not self.auth.is_authenticated_operator(auth_hdr):
            self._send_error(401, "Unauthorized: missing or invalid Bearer token.")
            return False
        return True

    def do_POST(self) -> None:
        """Handle POST requests."""
        if not self._check_auth(is_execution=True):
            return

        parsed_url = urlparse(self.path)
        path = parsed_url.path

        pub_match = _PUBLISH_ROUTE_PATTERN.match(path)
        if pub_match:
            run_id = pub_match.group("run_id")
            if not self.store.get_run(run_id):
                self._send_error(404, f"Run '{run_id}' not found.")
                return
            try:
                self.store.publish_run(run_id)
                self._send_json(200, {"run_id": run_id, "is_published": True})
            except UnpublishableRunError as exc:
                self._send_error(422, str(exc))
            return

        if path == "/v1/runs":
            content_len = int(self.headers.get("Content-Length", 0))
            if content_len <= 0:
                self._send_error(400, "Request body cannot be empty.")
                return
            if content_len > MAX_REQUEST_BODY_BYTES:
                remaining = content_len
                drain_cap = 2 * 1024 * 1024
                while remaining > 0 and drain_cap > 0:
                    chunk_sz = min(remaining, 65536, drain_cap)
                    try:
                        discarded = self.rfile.read(chunk_sz)
                        if not discarded:
                            break
                        remaining -= len(discarded)
                        drain_cap -= len(discarded)
                    except Exception:
                        break
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
            except UnpublishableRunError as exc:
                self._send_error(422, str(exc))
            except ValueError as exc:
                self._send_error(400, str(exc))
            except Exception as exc:
                self._send_error(500, f"Internal server error: {exc}")
        else:
            self._send_error(404, f"Endpoint not found: {self.path}")

    def do_GET(self) -> None:
        """Handle GET requests."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        # Handle health probes (P-27.02 & P-27.04: unauthenticated health readiness)
        if _HEALTH_ROUTE_PATTERN.match(path):
            from basebreak.deployment.health import get_health_status

            published_cnt = len(self.store.list_published_runs())
            self._send_json(200, get_health_status(self.server_start_time, published_cnt))
            return

        is_operator = self.auth.is_authenticated_operator(self.headers.get("Authorization"))

        # Handle Judge & Operator UI routes (P-22 & P-27.05)
        ui_match = _JUDGE_UI_ROUTE_PATTERN.match(path)
        if ui_match or path == "/":
            import html as py_html

            from basebreak.causal.public_receipt import (
                PublicVerificationReceipt,
                verify_public_receipt_integrity,
            )
            from basebreak.ui.renderer import render_judge_ui_html

            ui_run_id = ui_match.group("run_id") if ui_match else None
            if not ui_run_id:
                published = self.store.list_published_runs()
                if published:
                    ui_run_id = published[-1]
                elif is_operator:
                    runs = self.store.list_runs()
                    if runs:
                        ui_run_id = runs[-1]

            if not ui_run_id:
                self._send_html(
                    200,
                    "<!DOCTYPE html><html><head><title>Basebreak Judge UI</title></head>"
                    "<body style='font-family: sans-serif; background: #0f172a; "
                    "color: #fff; padding: 2rem;'>"
                    "<h1>Basebreak Verification Runtime</h1>"
                    "<p style='color: #38bdf8;'>“If the patch matters, the base must break.”</p>"
                    "<p style='color: #94a3b8;'>Signed-out judge access is active. "
                    "No published verification runs recorded yet in store.</p>"
                    "</body></html>",
                )
                return

            # Check if specific run is published or caller is authenticated operator
            if not self.store.has_published_status(ui_run_id) and not is_operator:
                self._send_html(
                    401,
                    "<!DOCTYPE html><html><head><title>Private Run — Unauthorized</title></head>"
                    "<body style='font-family: sans-serif; background: #0f172a; "
                    "color: #fff; padding: 2rem;'>"
                    f"<h1>Run '{py_html.escape(ui_run_id)}' is Private</h1>"
                    "<p style='color: #ef4444;'>Signed-out judge access is permitted only "
                    "for explicitly published verification runs. "
                    "Bearer token required for private runs.</p>"
                    "</body></html>",
                )
                return

            run_meta = self.store.get_run(ui_run_id)
            receipt = self.store.get_receipt(ui_run_id)
            if not run_meta or not receipt:
                self._send_html(
                    404,
                    "<!DOCTYPE html><html><head><title>Run Not Found</title></head>"
                    "<body style='font-family: sans-serif; background: #0f172a; "
                    "color: #fff; padding: 2rem;'>"
                    f"<h1>Run '{py_html.escape(ui_run_id)}' Not Found</h1>"
                    "<p style='color: #ef4444;'>No verified public receipt recorded.</p>"
                    "</body></html>",
                )
                return

            # Mandatory receipt integrity verification before rendering judge UI
            try:
                verified_rc = PublicVerificationReceipt.from_dict(receipt)
                verify_public_receipt_integrity(verified_rc)
            except Exception as exc:
                self._send_html(
                    400,
                    "<!DOCTYPE html><html><head><title>Receipt Integrity Failure</title></head>"
                    "<body style='font-family: sans-serif; background: #0f172a; "
                    "color: #fff; padding: 2rem;'>"
                    "<h1>Receipt Integrity Verification Failed</h1>"
                    f"<p style='color: #ef4444;'>Receipt for '{py_html.escape(ui_run_id)}' "
                    f"failed integrity check: {py_html.escape(str(exc))}</p>"
                    "</body></html>",
                )
                return

            rendered = render_judge_ui_html(receipt, run_meta=run_meta)
            self._send_html(200, rendered)
            return

        match = _RUN_ID_ROUTE_PATTERN.match(path)
        if not match:
            self._send_error(404, f"Endpoint not found: {path}")
            return

        run_id = match.group("run_id")
        subpath = match.group("subpath") or ""

        # Public /receipt endpoint: available to signed-out judges for published runs, or operator
        if subpath == "/receipt":
            if not self.store.has_published_status(run_id) and not is_operator:
                self._send_error(
                    401, f"Unauthorized: Run '{run_id}' is private. Bearer token required."
                )
                return

            receipt = self.store.get_receipt(run_id)
            if receipt is None:
                self._send_error(404, f"Public receipt for run '{run_id}' not found.")
                return

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
            return

        # Raw run metadata, evidence records, and event streams strictly require operator identity
        if not is_operator:
            self._send_error(
                401,
                "Unauthorized: Operator Bearer token required to access raw run metadata, "
                "internal evidence, or event streams.",
            )
            return

        run_meta = self.store.get_run(run_id)
        if run_meta is None:
            self._send_error(404, f"Run '{run_id}' not found.")
            return

        if not subpath:
            # GET /v1/runs/{run_id} (Operator authenticated)
            self._send_json(200, run_meta)
        elif subpath == "/evidence":
            # GET /v1/runs/{run_id}/evidence (Operator authenticated)
            evidence = self.store.get_evidence(run_id)
            self._send_json(200, {"run_id": run_id, "evidence": evidence})
        elif subpath == "/events":
            # GET /v1/runs/{run_id}/events (Server-Sent Events, Operator authenticated)
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
        handler_class.server_start_time = time.time()

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
