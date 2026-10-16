"""Trusted Python bridge for deployed LIVE_NEBIUS execution readiness.

This bridge authenticates Cloudflare Worker dispatch requests, enforces exact
source/target binding, and returns a verifier-signed proof over the public
receipt so the Worker cannot self-certify a causal verdict.
"""

from __future__ import annotations

import hashlib
import hmac
import http.server
import json
import os
import socketserver
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from basebreak.causal.public_receipt import (
    PublicVerificationReceipt,
    verify_public_receipt_integrity,
)
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.verifier.trust_bridge import (
    PINNED_VERIFIER_EXPONENT,
    PINNED_VERIFIER_MODULUS,
    _PrivilegedVerifierSigner,
)

LIVE_BRIDGE_ROUTE: str = "/internal/live-verifications"
BRIDGE_REQUEST_SCHEMA_VERSION: str = "1.0.0"
BRIDGE_PROOF_SCHEMA_VERSION: str = "1.0.0"
DEFAULT_BRIDGE_AUDIENCE: str = "cloudflare-worker"
DEFAULT_BRIDGE_REQUEST_TTL_SECONDS: int = 300


class BridgeValidationError(Exception):
    """Raised when a bridge request or response payload is malformed."""


def _canonical_json(data: Mapping[str, Any] | dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _compute_sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_bridge_request_signature_payload(
    *,
    method: str,
    path: str,
    timestamp: str,
    audience: str,
    body: Mapping[str, Any],
) -> str:
    return "\n".join(
        [
            method.upper().strip(),
            path.strip(),
            timestamp.strip(),
            audience.strip(),
            _canonical_json(dict(body)),
        ]
    )


def sign_bridge_request(
    *,
    shared_secret: str,
    method: str,
    path: str,
    timestamp: str,
    audience: str,
    body: Mapping[str, Any],
) -> str:
    payload = build_bridge_request_signature_payload(
        method=method,
        path=path,
        timestamp=timestamp,
        audience=audience,
        body=body,
    )
    return hmac.new(
        shared_secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class BridgeRequest:
    """Trusted Worker request accepted by the Python bridge."""

    request_id: str
    issued_at_ms: int
    deadline_ms: int
    receipt_audience: str
    task_id: str
    change_class: str
    target: str
    source_commit_id: str
    frozen_contract_digest: str
    max_estimated_cost_usd: float
    schema_version: str = BRIDGE_REQUEST_SCHEMA_VERSION

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BridgeRequest:
        if not isinstance(data, Mapping):
            raise BridgeValidationError("Bridge request payload must be a JSON object.")

        request_id = str(data.get("request_id", "")).strip()
        target = str(data.get("target", "")).strip()
        source_commit_id = str(data.get("source_commit_id", "")).strip().lower()
        task_id = str(data.get("task_id", "")).strip()
        change_class = str(data.get("change_class", "")).strip()
        frozen_contract_digest = str(data.get("frozen_contract_digest", "")).strip().lower()
        audience = str(data.get("receipt_audience", "")).strip()
        schema_version = str(data.get("schema_version", "")).strip()

        if schema_version != BRIDGE_REQUEST_SCHEMA_VERSION:
            raise BridgeValidationError(
                f"Unsupported bridge request schema_version: {schema_version!r}"
            )
        if not request_id:
            raise BridgeValidationError("request_id is required.")
        if not target:
            raise BridgeValidationError("target is required.")
        if len(source_commit_id) != 40 or any(
            c not in "0123456789abcdef" for c in source_commit_id
        ):
            raise BridgeValidationError(
                "source_commit_id must be a 40-character lowercase hex SHA."
            )
        if not task_id:
            raise BridgeValidationError("task_id is required.")
        if not change_class:
            raise BridgeValidationError("change_class is required.")
        if len(frozen_contract_digest) != 64 or any(
            c not in "0123456789abcdef" for c in frozen_contract_digest
        ):
            raise BridgeValidationError(
                "frozen_contract_digest must be a 64-character lowercase hex digest."
            )
        if not audience:
            raise BridgeValidationError("receipt_audience is required.")

        issued_at_ms = data.get("issued_at_ms")
        deadline_ms = data.get("deadline_ms")
        max_cost = data.get("max_estimated_cost_usd")
        if not isinstance(issued_at_ms, int):
            raise BridgeValidationError("issued_at_ms must be an integer.")
        if not isinstance(deadline_ms, int):
            raise BridgeValidationError("deadline_ms must be an integer.")
        if not isinstance(max_cost, (int, float)) or float(max_cost) <= 0.0:
            raise BridgeValidationError("max_estimated_cost_usd must be a positive number.")

        return cls(
            request_id=request_id,
            issued_at_ms=issued_at_ms,
            deadline_ms=deadline_ms,
            receipt_audience=audience,
            task_id=task_id,
            change_class=change_class,
            target=target,
            source_commit_id=source_commit_id,
            frozen_contract_digest=frozen_contract_digest,
            max_estimated_cost_usd=float(max_cost),
            schema_version=schema_version,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "issued_at_ms": self.issued_at_ms,
            "deadline_ms": self.deadline_ms,
            "receipt_audience": self.receipt_audience,
            "task_id": self.task_id,
            "change_class": self.change_class,
            "target": self.target,
            "source_commit_id": self.source_commit_id,
            "frozen_contract_digest": self.frozen_contract_digest,
            "max_estimated_cost_usd": self.max_estimated_cost_usd,
        }


@dataclass(frozen=True, slots=True)
class BridgeExecutionResult:
    """Outcome produced by the trusted verifier bridge executor."""

    status: str
    receipt: PublicVerificationReceipt | None = None
    error: str | None = None
    observed_cost_usd: float = 0.0
    tokens_used: int = 0
    ambiguous_outcome: bool = False
    provider_operation_ids: tuple[str, ...] = ()


BridgeExecutor = Callable[[BridgeRequest], BridgeExecutionResult]
BridgeExecutionAuthorityVerifier = Callable[
    [BridgeRequest, BridgeExecutionResult], tuple[bool, str | None]
]


@dataclass(frozen=True, slots=True)
class TrustedBridgeConfig:
    """Static bridge configuration and required trust anchors."""

    shared_secret: str | None = None
    expected_audience: str = DEFAULT_BRIDGE_AUDIENCE
    expected_target: str = "tests/fixtures/reset_vault"
    expected_source_commit: str = ""
    request_ttl_seconds: int = DEFAULT_BRIDGE_REQUEST_TTL_SECONDS
    nebius_api_key: str | None = None
    nebius_project_id: str | None = None
    live_execution_enabled: bool = False
    route_path: str = LIVE_BRIDGE_ROUTE

    @classmethod
    def from_env(cls) -> TrustedBridgeConfig:
        expected_commit = os.environ.get("EXPECTED_SOURCE_COMMIT", "").strip().lower()
        if not expected_commit:
            expected_commit = os.environ.get("BASEBREAK_BUILD_COMMIT_SHA", "").strip().lower()
        return cls(
            shared_secret=os.environ.get("TRUSTED_VERIFIER_BRIDGE_SHARED_SECRET"),
            expected_audience=os.environ.get(
                "TRUSTED_VERIFIER_BRIDGE_AUDIENCE", DEFAULT_BRIDGE_AUDIENCE
            ).strip()
            or DEFAULT_BRIDGE_AUDIENCE,
            expected_target=os.environ.get(
                "ALLOWLISTED_TARGET", "tests/fixtures/reset_vault"
            ).strip()
            or "tests/fixtures/reset_vault",
            expected_source_commit=expected_commit,
            request_ttl_seconds=int(
                os.environ.get(
                    "TRUSTED_VERIFIER_BRIDGE_REQUEST_TTL_SECONDS",
                    str(DEFAULT_BRIDGE_REQUEST_TTL_SECONDS),
                )
            ),
            nebius_api_key=os.environ.get("NEBIUS_API_KEY"),
            nebius_project_id=os.environ.get("NEBIUS_PROJECT_ID"),
            live_execution_enabled=os.environ.get("BASEBREAK_LIVE_EXECUTION_ENABLED", "false")
            .strip()
            .lower()
            == "true",
            route_path=os.environ.get("TRUSTED_VERIFIER_BRIDGE_ROUTE", LIVE_BRIDGE_ROUTE).strip()
            or LIVE_BRIDGE_ROUTE,
        )


def _normalize_execution_fact(fact: Any) -> dict[str, Any]:
    if fact is None:
        raise BridgeValidationError("Receipt proof requires an execution fact.")
    outcome = getattr(fact, "outcome", None)
    if outcome is not None and hasattr(outcome, "value"):
        outcome_value = str(getattr(outcome, "value"))
    else:
        outcome_value = str(outcome)
    return {
        "outcome": outcome_value,
        "exit_code": getattr(fact, "exit_code", None),
        "sandbox_id": str(getattr(fact, "sandbox_id", "")).strip(),
        "source_commit_id": str(getattr(fact, "source_commit_id", "")).strip().lower() or None,
        "tree_digest": str(getattr(fact, "tree_digest", "")).strip().lower() or None,
        "stdout_digest": str(getattr(fact, "stdout_digest", "")).strip().lower() or None,
        "stderr_digest": str(getattr(fact, "stderr_digest", "")).strip().lower() or None,
    }


def build_receipt_proof_payload(
    receipt: PublicVerificationReceipt, *, issuer_id: str
) -> dict[str, Any]:
    executions: dict[str, Any] = {}
    for execution in receipt.executions:
        world = getattr(execution.world, "value", str(execution.world))
        executions[world] = _normalize_execution_fact(execution)

    counterfactual_execution = None
    if receipt.counterfactual is not None and receipt.counterfactual.execution_fact is not None:
        counterfactual_execution = _normalize_execution_fact(receipt.counterfactual.execution_fact)

    return {
        "schema_version": BRIDGE_PROOF_SCHEMA_VERSION,
        "receipt_digest": receipt.receipt_digest,
        "source_commit_id": receipt.source_commit_id,
        "candidate_tree_digest": receipt.candidate_tree_digest,
        "candidate_patch_digest": receipt.candidate_patch_digest,
        "overall_verdict": receipt.overall_verdict.value,
        "provenance": receipt.provenance.value,
        "issued_at_utc": str(receipt.timing.get("created_at_utc", "")),
        "issuer_id": issuer_id,
        "base_execution": executions.get("BASE"),
        "candidate_execution": executions.get("CANDIDATE"),
        "counterfactual_execution": counterfactual_execution,
    }


def create_receipt_proof(
    receipt: PublicVerificationReceipt,
    *,
    signer: _PrivilegedVerifierSigner,
    issuer_id: str,
) -> dict[str, Any]:
    if receipt.provenance != EvidenceProvenance.LIVE_NEBIUS:
        raise BridgeValidationError(
            f"Receipt proof requires LIVE_NEBIUS provenance, got {receipt.provenance.value}."
        )
    payload = build_receipt_proof_payload(receipt, issuer_id=issuer_id)
    proof_digest = _compute_sha256_hex(_canonical_json(payload))
    signature = signer.sign_attestation_digest(proof_digest)
    return {
        **payload,
        "proof_digest": proof_digest,
        "signature": signature,
    }


def verify_receipt_proof(
    receipt: PublicVerificationReceipt,
    proof: Mapping[str, Any],
    *,
    modulus: int = PINNED_VERIFIER_MODULUS,
    exponent: int = PINNED_VERIFIER_EXPONENT,
) -> bool:
    try:
        payload = {
            "schema_version": proof["schema_version"],
            "receipt_digest": proof["receipt_digest"],
            "source_commit_id": proof["source_commit_id"],
            "candidate_tree_digest": proof["candidate_tree_digest"],
            "candidate_patch_digest": proof.get("candidate_patch_digest"),
            "overall_verdict": proof["overall_verdict"],
            "provenance": proof["provenance"],
            "issued_at_utc": proof["issued_at_utc"],
            "issuer_id": proof["issuer_id"],
            "base_execution": proof["base_execution"],
            "candidate_execution": proof["candidate_execution"],
            "counterfactual_execution": proof.get("counterfactual_execution"),
        }
        expected_digest = _compute_sha256_hex(_canonical_json(payload))
        if str(proof.get("proof_digest", "")).strip().lower() != expected_digest:
            return False

        signature = str(proof.get("signature", "")).strip().lower()
        if not signature:
            return False

        digest_bytes = hashlib.sha256(expected_digest.encode("utf-8")).digest()
        expected_message = int.from_bytes(digest_bytes, "big")
        recovered_message = pow(int(signature, 16), exponent, modulus)
        if recovered_message != expected_message:
            return False

        verify_public_receipt_integrity(receipt)
        if str(proof.get("receipt_digest", "")).strip().lower() != receipt.receipt_digest.lower():
            return False
        if (
            str(proof.get("source_commit_id", "")).strip().lower()
            != receipt.source_commit_id.lower()
        ):
            return False
        if (
            str(proof.get("candidate_tree_digest", "")).strip().lower()
            != receipt.candidate_tree_digest.lower()
        ):
            return False
        if str(proof.get("overall_verdict", "")).strip() != receipt.overall_verdict.value:
            return False
        if str(proof.get("provenance", "")).strip() != receipt.provenance.value:
            return False
    except Exception:
        return False
    return True


class TrustedVerifierBridge:
    """Fail-closed bridge controller between the Worker and Python verifier boundary."""

    def __init__(
        self,
        *,
        config: TrustedBridgeConfig,
        executor: BridgeExecutor | None = None,
        signer: _PrivilegedVerifierSigner | None = None,
        execution_authority_verifier: BridgeExecutionAuthorityVerifier | None = None,
    ) -> None:
        self.config = config
        self.executor = executor
        self.signer = signer or _PrivilegedVerifierSigner.from_environment()
        self.execution_authority_verifier = execution_authority_verifier

    def _error(
        self,
        status_code: int,
        status: str,
        error: str,
        *,
        ambiguous_outcome: bool = False,
    ) -> tuple[int, dict[str, Any]]:
        return status_code, {
            "ok": False,
            "status": status,
            "error": error,
            "ambiguous_outcome": ambiguous_outcome,
        }

    def _verify_request_auth(
        self,
        *,
        headers: Mapping[str, str],
        method: str,
        path: str,
        raw_body: bytes,
    ) -> tuple[bool, str | None]:
        if not self.config.shared_secret:
            return False, "Trusted bridge shared secret is not configured."

        timestamp = str(headers.get("X-Basebreak-Bridge-Timestamp", "")).strip()
        audience = str(headers.get("X-Basebreak-Bridge-Audience", "")).strip()
        signature = str(headers.get("X-Basebreak-Bridge-Signature", "")).strip().lower()
        if not timestamp or not audience or not signature:
            return False, "Missing trusted bridge authentication headers."

        try:
            timestamp_ms = int(timestamp)
        except ValueError:
            return False, "Bridge timestamp header is malformed."

        if abs(time.time() * 1000 - timestamp_ms) > self.config.request_ttl_seconds * 1000:
            return False, "Bridge request timestamp is outside the allowed replay window."

        if audience != self.config.expected_audience:
            return False, "Bridge request audience is invalid."

        try:
            body = json.loads(raw_body.decode("utf-8"))
        except Exception:
            return False, "Bridge request body is not valid JSON."

        expected_signature = sign_bridge_request(
            shared_secret=self.config.shared_secret,
            method=method,
            path=path,
            timestamp=timestamp,
            audience=audience,
            body=body,
        )
        if not hmac.compare_digest(signature, expected_signature):
            return False, "Bridge signature verification failed."
        return True, None

    def _validate_request(self, request: BridgeRequest) -> tuple[int, dict[str, Any]] | None:
        if request.receipt_audience != self.config.expected_audience:
            return self._error(403, "INVALID_AUDIENCE", "Bridge request audience mismatch.")
        if request.target != self.config.expected_target:
            return self._error(
                400,
                "INVALID_TARGET",
                f"Target substitution rejected. Expected {self.config.expected_target!r}.",
            )
        if not self.config.expected_source_commit:
            return self._error(
                503,
                "NOT_READY_FOR_DEPLOYMENT",
                "Bridge expected_source_commit is not configured.",
            )
        if request.source_commit_id.lower() != self.config.expected_source_commit.lower():
            return self._error(
                400,
                "INVALID_SOURCE",
                "Source commit substitution rejected by the trusted bridge.",
            )
        if request.max_estimated_cost_usd <= 0.0:
            return self._error(
                422,
                "BLOCKED_ESTIMATED_COST_UNKNOWN",
                "Maximum estimated live cost must be positive.",
            )
        return None

    def handle_http_request(
        self,
        *,
        method: str,
        path: str,
        headers: Mapping[str, str],
        raw_body: bytes,
    ) -> tuple[int, dict[str, Any]]:
        if method.upper() != "POST":
            return self._error(405, "METHOD_NOT_ALLOWED", "Only POST is supported.")
        if path != self.config.route_path:
            return self._error(404, "NOT_FOUND", f"Unknown bridge route: {path}")

        auth_ok, auth_error = self._verify_request_auth(
            headers=headers,
            method=method,
            path=path,
            raw_body=raw_body,
        )
        if not auth_ok:
            if auth_error == "Trusted bridge shared secret is not configured.":
                return self._error(503, "NOT_READY_FOR_DEPLOYMENT", auth_error)
            return self._error(401, "UNAUTHORIZED", auth_error or "Bridge authentication failed.")

        try:
            request_obj = BridgeRequest.from_dict(json.loads(raw_body.decode("utf-8")))
        except BridgeValidationError as exc:
            return self._error(400, "INVALID_INPUT", str(exc))

        validation_error = self._validate_request(request_obj)
        if validation_error is not None:
            return validation_error

        if not self.config.live_execution_enabled:
            return self._error(
                503,
                "BLOCKED_LIVE_DISABLED",
                "Trusted bridge is configured but live execution remains disabled "
                "pending operator authorization.",
            )

        if not self.config.nebius_api_key or not self.config.nebius_project_id:
            return self._error(
                503,
                "BLOCKED_MISSING_PROVIDER_CREDENTIALS",
                "Nebius API key or project ID is missing; trusted bridge cannot start "
                "provider execution.",
            )

        if self.signer is None:
            return self._error(
                503,
                "BLOCKED_MISSING_SIGNING_AUTHORITY",
                "Trusted verifier signing authority is unavailable; bridge cannot certify "
                "the result.",
            )

        if self.executor is None:
            return self._error(
                503,
                "NOT_READY_FOR_DEPLOYMENT",
                "Trusted verifier executor is not configured.",
            )

        result = self.executor(request_obj)
        if result.receipt is None:
            return self._error(
                502 if result.ambiguous_outcome else 503,
                result.status,
                result.error
                or "Trusted bridge executor completed without an authenticated public receipt.",
                ambiguous_outcome=result.ambiguous_outcome,
            )

        try:
            verify_public_receipt_integrity(result.receipt)
        except Exception as exc:
            return self._error(
                502,
                "FAILED",
                f"Bridge receipt integrity verification failed: {exc}",
            )

        if result.receipt.provenance != EvidenceProvenance.LIVE_NEBIUS:
            return self._error(
                502,
                "FAILED",
                "Bridge executor returned a non-LIVE_NEBIUS receipt for a live request.",
            )

        if self.execution_authority_verifier is None:
            return self._error(
                503,
                "NOT_READY_FOR_DEPLOYMENT",
                "Independent live execution authority is not configured. Trusted bridge "
                "cannot certify executor-reported LIVE_NEBIUS receipts; run remains NOT_RUN.",
            )

        try:
            authority_verified, authority_error = self.execution_authority_verifier(
                request_obj, result
            )
        except Exception as exc:
            return self._error(
                502,
                "FAILED",
                f"Independent live execution authority check failed: {exc}",
            )

        if not authority_verified:
            return self._error(
                502,
                "FAILED",
                authority_error
                or "Independent live execution authority rejected the executor-reported receipt.",
            )

        proof = create_receipt_proof(
            result.receipt,
            signer=self.signer,
            issuer_id="basebreak:verifier:nebius:worker",
        )
        return 201, {
            "ok": True,
            "status": "COMPLETED",
            "receipt": result.receipt.to_dict(),
            "receipt_proof": proof,
            "observed_cost_usd": result.observed_cost_usd,
            "tokens_used": result.tokens_used,
            "provider_operation_ids": list(result.provider_operation_ids),
        }


class BasebreakLiveBridgeRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler exposing the trusted verifier bridge route."""

    bridge: TrustedVerifierBridge

    def _send_json(self, status_code: int, payload: Mapping[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        content_length = int(self.headers.get("Content-Length", "0") or "0")
        raw_body = self.rfile.read(content_length) if content_length > 0 else b""
        status_code, payload = self.bridge.handle_http_request(
            method="POST",
            path=self.path,
            headers={k: v for k, v in self.headers.items()},
            raw_body=raw_body,
        )
        self._send_json(status_code, payload)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return None


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class BasebreakLiveBridgeServer:
    """Minimal stdlib HTTP server for the trusted verifier bridge."""

    def __init__(
        self,
        *,
        bridge: TrustedVerifierBridge,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.bridge = bridge
        self.host = host
        self.port = port
        self._httpd: _ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        if self._httpd is None:
            raise RuntimeError("Bridge server is not started.")
        address = self._httpd.server_address
        host = address[0]
        port = int(address[1])
        if isinstance(host, bytes):
            host = host.decode("utf-8")
        return f"http://{host}:{port}"

    def start(self) -> None:
        if self._httpd is not None:
            return
        handler = type(
            "ConfiguredBasebreakLiveBridgeRequestHandler",
            (BasebreakLiveBridgeRequestHandler,),
            {"bridge": self.bridge},
        )
        self._httpd = _ThreadingHTTPServer((self.host, self.port), handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is None:
            return
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        self._thread = None
        self._httpd = None
