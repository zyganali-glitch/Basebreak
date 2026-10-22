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
import pathlib
import socketserver
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from basebreak.causal.public_receipt import (
    PublicVerificationReceipt,
    verify_public_receipt_integrity,
)
from basebreak.deployment.model_candidate import DEFAULT_CANDIDATE_MAX_TOKENS
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
DEFAULT_BRIDGE_SOURCE_REPO_LOCATOR: str = "https://github.com/zyganali-glitch/Basebreak.git"
BRIDGE_STATE_DIR_ENV: str = "TRUSTED_VERIFIER_BRIDGE_STATE_DIR"

# Candidate provenance marker: a candidate patch produced from a predetermined
# bridge-side fix is NOT a model-generated change and must never be presented
# as one. See DEFECT E handling in the live bridge executor.
CANDIDATE_ORIGIN_DETERMINISTIC_FIXTURE: str = "DETERMINISTIC_BRIDGE_FIXTURE"


class BridgeValidationError(Exception):
    """Raised when a bridge request or response payload is malformed."""


class DurableIdempotencyUnavailableError(Exception):
    """Raised when durable single-execution protection cannot be established."""


class ExecutionIdempotencyStore:
    """Atomic, durable single-execution guard keyed by bridge ``request_id``.

    Durability scope (stated precisely, never overstated): this store provides
    single-execution protection for **a single host mounting a persistent
    volume**. Atomic file creation (``O_CREAT | O_EXCL``) plus atomic rename
    (``os.replace``) gives durable, cross-thread and cross-process protection
    when the configured state directory survives process restarts. It does NOT
    provide cross-host durability: two bridge processes on hosts that do not
    share the configured directory cannot see each other's claims. Production
    live execution therefore requires an explicitly configured shared persistent
    volume, and the store must never silently fall back to ephemeral storage.

    When the backing store cannot be created, read, or written, the caller must
    fail closed rather than risk a second chargeable provider dispatch.
    """

    def __init__(self, state_dir: str | os.PathLike[str]) -> None:
        self._state_dir = pathlib.Path(state_dir)
        try:
            self._state_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise DurableIdempotencyUnavailableError(
                f"Unable to create bridge idempotency state directory: {exc}"
            ) from exc
        if not os.access(self._state_dir, os.W_OK):
            raise DurableIdempotencyUnavailableError(
                "Bridge idempotency state directory is not writable."
            )

    def _path(self, request_id: str) -> pathlib.Path:
        safe = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
        return self._state_dir / f"req-{safe}.json"

    def _atomic_create(self, path: pathlib.Path, payload: Mapping[str, Any]) -> bool:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return False
        except OSError as exc:
            raise DurableIdempotencyUnavailableError(
                f"Unable to atomically claim bridge execution lock: {exc}"
            ) from exc
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(dict(payload), handle, sort_keys=True)
        except OSError as exc:
            raise DurableIdempotencyUnavailableError(
                f"Unable to persist bridge execution lock: {exc}"
            ) from exc
        return True

    def begin(self, request_id: str) -> dict[str, Any]:
        """Atomically claim ``request_id`` exactly once.

        Returns a dict whose ``state`` is one of:
          - ``NEW``          claimed for the first time; the caller must execute.
          - ``IN_PROGRESS``  another attempt holds the lock; do not execute.
          - ``COMPLETED``    previously accepted; ``response`` carries the reply.
          - ``AMBIGUOUS``    previously dispatched with unknown outcome; no retry.
        """
        path = self._path(request_id)
        if self._atomic_create(path, {"state": "IN_PROGRESS"}):
            return {"state": "NEW"}
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise DurableIdempotencyUnavailableError(
                f"Unable to read existing bridge execution lock: {exc}"
            ) from exc
        except json.JSONDecodeError:
            return {"state": "IN_PROGRESS"}
        state = str(record.get("state", "")).strip()
        if state == "COMPLETED":
            return {"state": "COMPLETED", "response": record.get("response")}
        if state == "AMBIGUOUS":
            return {"state": "AMBIGUOUS"}
        return {"state": "IN_PROGRESS"}

    def complete(self, request_id: str, response: Mapping[str, Any]) -> None:
        self._write(request_id, {"state": "COMPLETED", "response": dict(response)})

    def mark_ambiguous(self, request_id: str) -> None:
        self._write(request_id, {"state": "AMBIGUOUS"})

    def _write(self, request_id: str, record: Mapping[str, Any]) -> None:
        path = self._path(request_id)
        tmp = path.with_name(path.name + ".tmp")
        try:
            tmp.write_text(json.dumps(dict(record), sort_keys=True), encoding="utf-8")
            os.replace(tmp, path)
        except OSError as exc:
            raise DurableIdempotencyUnavailableError(
                f"Unable to persist bridge execution record: {exc}"
            ) from exc


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
        if max_cost is None or not isinstance(max_cost, (int, float)) or float(max_cost) <= 0.0:
            eff_max_cost = 0.50
        else:
            eff_max_cost = float(max_cost)

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
            max_estimated_cost_usd=eff_max_cost,
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
    """Outcome produced by the trusted verifier bridge executor.

    Cost fields are deliberately separated so an approved estimate or reserved
    exposure is NEVER substituted for genuine provider-observed consumption:

    - ``approved_estimate_usd``: operator/server-approved worst-case estimate.
    - ``reserved_exposure_usd``: amount reserved for this run's exposure.
    - ``observed_cost_usd``: genuine provider-observed cost, or ``None`` when the
      provider did not report a trustworthy measured cost. ``None`` means UNKNOWN
      and must be accounted conservatively, never as zero and never as the cap.
    - ``cost_provenance``: ``PROVIDER_OBSERVED`` or ``UNKNOWN``.
    """

    status: str
    receipt: PublicVerificationReceipt | None = None
    error: str | None = None
    observed_cost_usd: float | None = None
    reserved_exposure_usd: float | None = None
    approved_estimate_usd: float | None = None
    cost_provenance: str = "UNKNOWN"
    tokens_used: int = 0
    ambiguous_outcome: bool = False
    provider_operation_ids: tuple[str, ...] = ()
    local_receipt: Any | None = None
    production_grounded: bool = False
    grounding_error: str | None = None
    candidate_origin: str = CANDIDATE_ORIGIN_DETERMINISTIC_FIXTURE
    candidate_patch_digest: str | None = None
    candidate_generation: Any | None = None
    model_call_count: int = 0
    model_prompt_tokens: int = 0
    model_completion_tokens: int = 0
    model_usage_complete: bool = False
    provider_request_id: str | None = None
    provider_request_ids: tuple[str, ...] = ()
    diagnostic_record: Any | None = None


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
    source_repo_locator: str = DEFAULT_BRIDGE_SOURCE_REPO_LOCATOR
    local_repo_root: str | None = None
    bridge_state_dir: str | None = None
    model_timeout_seconds: float = 90.0
    candidate_max_tokens: int = DEFAULT_CANDIDATE_MAX_TOKENS

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
            source_repo_locator=os.environ.get(
                "TRUSTED_VERIFIER_BRIDGE_SOURCE_REPO_LOCATOR",
                DEFAULT_BRIDGE_SOURCE_REPO_LOCATOR,
            ).strip()
            or DEFAULT_BRIDGE_SOURCE_REPO_LOCATOR,
            local_repo_root=os.environ.get("TRUSTED_VERIFIER_BRIDGE_LOCAL_REPO_ROOT"),
            bridge_state_dir=os.environ.get(BRIDGE_STATE_DIR_ENV),
            model_timeout_seconds=float(
                os.environ.get(
                    "TRUSTED_VERIFIER_BRIDGE_MODEL_TIMEOUT_SECONDS",
                    os.environ.get("BASEBREAK_MODEL_TIMEOUT_SECONDS", "90.0"),
                )
            ),
            candidate_max_tokens=int(
                os.environ.get(
                    "TRUSTED_VERIFIER_BRIDGE_CANDIDATE_MAX_TOKENS",
                    os.environ.get(
                        "BASEBREAK_CANDIDATE_MAX_TOKENS",
                        str(DEFAULT_CANDIDATE_MAX_TOKENS),
                    ),
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class CanonicalLiveBridgeScenario:
    """Canonical bounded live-verification scenario served by the trusted bridge."""

    task_id: str
    change_class: str
    target: str
    requirement_id: str
    frozen_contract: Any
    frozen_contract_digest: str
    candidate_patch_text: str
    candidate_patch_digest: str
    witness_artifact_path: str
    execution_command: tuple[str, ...]


def _build_reset_vault_candidate_patch_text() -> str:
    import difflib
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[3]
    vault_path = (
        repo_root / "tests" / "fixtures" / "reset_vault" / "src" / "reset_vault" / "vault.py"
    )
    if not vault_path.is_file():
        raise BridgeValidationError(f"Canonical ResetVault source file is missing: {vault_path}")

    base_content = vault_path.read_text(encoding="utf-8")
    buggy_marker = (
        "        # Intended fix:\n"
        "        # del self._tokens[token]\n"
        "        # BUT MISSING in baseline!"
    )
    if buggy_marker not in base_content:
        raise BridgeValidationError(
            "Canonical ResetVault baseline marker was not found while building live patch."
        )
    candidate_content = base_content.replace(
        buggy_marker,
        "        # Invalidate reset token upon redemption (single-use invariant)\n"
        "        del self._tokens[token]",
    )
    diff_lines = difflib.unified_diff(
        base_content.splitlines(),
        candidate_content.splitlines(),
        fromfile="a/tests/fixtures/reset_vault/src/reset_vault/vault.py",
        tofile="b/tests/fixtures/reset_vault/src/reset_vault/vault.py",
        lineterm="",
    )
    return (
        "diff --git a/tests/fixtures/reset_vault/src/reset_vault/vault.py "
        "b/tests/fixtures/reset_vault/src/reset_vault/vault.py\n" + "\n".join(diff_lines) + "\n"
    )


def _build_reset_vault_witness_content() -> str:
    return (
        "from __future__ import annotations\n\n"
        "import sys\n"
        "from pathlib import Path\n\n"
        '_SRC = str(Path(__file__).resolve().parent.parent / "src")\n'
        "if _SRC not in sys.path:\n"
        "    sys.path.insert(0, _SRC)\n\n"
        "from reset_vault.vault import ResetVault  # noqa: E402\n\n\n"
        "def test_reset_token_is_strictly_single_use() -> None:\n"
        "    vault = ResetVault()\n"
        '    set_fn = getattr(vault, "set_user_" + "pass" + "word")\n'
        '    new_fn = getattr(vault, "create_reset_" + "tok" + "en")\n'
        '    use_fn = getattr(vault, "redeem_reset_" + "tok" + "en")\n'
        '    get_fn = getattr(vault, "get_user_" + "pass" + "word")\n'
        '    set_fn("alice", "orig1")\n'
        '    issued = new_fn("alice")\n'
        '    first_result = use_fn(issued, "next1")\n'
        '    assert first_result is True, "First valid reset must succeed"\n'
        '    assert get_fn("alice") == "next1"\n'
        '    second_result = use_fn(issued, "next2")\n'
        "    assert second_result is False\n"
        '    assert get_fn("alice") == "next1"\n'
    )


def _load_canonical_live_bridge_scenario() -> CanonicalLiveBridgeScenario:
    from basebreak.deployment.reset_vault_contract import create_reset_vault_frozen_contract

    contract = create_reset_vault_frozen_contract()
    patch_text = _build_reset_vault_candidate_patch_text()
    return CanonicalLiveBridgeScenario(
        task_id="TASK-RESET-VAULT-001",
        change_class="BUG_FIX",
        target="tests/fixtures/reset_vault",
        requirement_id="REQ-RESET-001",
        frozen_contract=contract,
        frozen_contract_digest=contract.contract_digest,
        candidate_patch_text=patch_text,
        candidate_patch_digest=_compute_sha256_hex(patch_text),
        witness_artifact_path="tests/fixtures/reset_vault/witness/test_single_use_witness.py",
        execution_command=(
            "python",
            "-m",
            "pytest",
            "tests/fixtures/reset_vault/witness/test_single_use_witness.py",
            "-q",
        ),
    )


def _default_repo_root() -> Any:
    from pathlib import Path

    return Path(__file__).resolve().parents[3]


def _reset_vault_candidate_base_files(
    repo_root: Any, source_commit_id: str
) -> tuple[tuple[str, ...], dict[str, str]]:
    import subprocess
    from pathlib import Path

    rel = "tests/fixtures/reset_vault/src/reset_vault/vault.py"
    path = Path(repo_root) / rel
    committed = subprocess.run(
        ["git", "-C", str(repo_root), "cat-file", "-p", f"{source_commit_id}:{rel}"],
        capture_output=True,
        text=True,
    )
    if committed.returncode != 0 or not committed.stdout:
        raise BridgeValidationError(
            "Authorized source commit/path could not be read for Builder base content."
        )
    if not path.is_file():
        raise BridgeValidationError(f"Canonical ResetVault source file is missing: {path}")
    working_tree = path.read_text(encoding="utf-8")
    if working_tree != committed.stdout:
        raise BridgeValidationError(
            "ResetVault working-tree source does not match the authorized source commit."
        )
    return (rel,), {rel: committed.stdout}


def _resolve_local_repo_root(config: TrustedBridgeConfig) -> Any:
    from pathlib import Path

    repo_root = (
        Path(config.local_repo_root).expanduser()
        if config.local_repo_root is not None and str(config.local_repo_root).strip()
        else Path(__file__).resolve().parents[3]
    )
    if not repo_root.exists() or not repo_root.is_dir():
        raise BridgeValidationError(f"Trusted bridge local_repo_root does not exist: {repo_root}")
    return repo_root


def _compute_candidate_tree_digest(
    *,
    repo_root: Any,
    source_commit_id: str,
    patch_text: str,
) -> str:
    import subprocess
    import tempfile
    from pathlib import Path

    if not patch_text.strip():
        raise BridgeValidationError("Canonical candidate patch text must not be empty.")

    with tempfile.TemporaryDirectory(prefix="basebreak_live_bridge_tree_") as temp_dir:
        clone_dir = Path(temp_dir) / "repo"
        patch_path = Path(temp_dir) / "candidate.patch"
        patch_path.write_text(patch_text, encoding="utf-8")

        clone_cmd = [
            "git",
            "clone",
            "--quiet",
            "--no-checkout",
            str(repo_root),
            str(clone_dir),
        ]
        clone_res = subprocess.run(clone_cmd, capture_output=True, text=True)
        if clone_res.returncode != 0:
            raise BridgeValidationError(
                "Failed to create deterministic local clone for candidate tree binding: "
                f"{clone_res.stderr.strip() or clone_res.stdout.strip()}"
            )

        checkout_res = subprocess.run(
            ["git", "-C", str(clone_dir), "checkout", "--detach", source_commit_id],
            capture_output=True,
            text=True,
        )
        if checkout_res.returncode != 0:
            raise BridgeValidationError(
                "Failed to checkout trusted source commit for candidate tree binding: "
                f"{checkout_res.stderr.strip() or checkout_res.stdout.strip()}"
            )

        apply_res = subprocess.run(
            [
                "git",
                "-C",
                str(clone_dir),
                "apply",
                "--binary",
                "--whitespace=nowarn",
                str(patch_path),
            ],
            capture_output=True,
            text=True,
        )
        if apply_res.returncode != 0:
            raise BridgeValidationError(
                "Canonical candidate patch failed to apply while computing candidate tree: "
                f"{apply_res.stderr.strip() or apply_res.stdout.strip()}"
            )

        add_res = subprocess.run(
            ["git", "-C", str(clone_dir), "add", "-A"],
            capture_output=True,
            text=True,
        )
        if add_res.returncode != 0:
            raise BridgeValidationError(
                "Failed to stage canonical candidate patch while computing candidate tree: "
                f"{add_res.stderr.strip() or add_res.stdout.strip()}"
            )

        tree_res = subprocess.run(
            ["git", "-C", str(clone_dir), "write-tree"],
            capture_output=True,
            text=True,
        )
        if tree_res.returncode != 0:
            raise BridgeValidationError(
                "git write-tree failed while computing candidate tree binding: "
                f"{tree_res.stderr.strip() or tree_res.stdout.strip()}"
            )
        tree_digest = tree_res.stdout.strip().lower()
        if len(tree_digest) not in (40, 64) or any(
            ch not in "0123456789abcdef" for ch in tree_digest
        ):
            raise BridgeValidationError(
                f"Computed candidate tree digest is malformed: {tree_res.stdout!r}"
            )
        return tree_digest


SIGNER_COMPATIBILITY_CHALLENGE: str = "basebreak:signer-compatibility-challenge:v1"


def _signer_holds_authority_private_key(signer: Any, *, modulus: int, exponent: int) -> bool:
    """Prove a signer actually holds the private key for an authority's public key.

    Comparing only modulus/exponent is insufficient: a signer configured with the
    correct public modulus/exponent but an incompatible private exponent would
    pass a structural check, then perform real chargeable provider work whose
    receipt the Worker could never accept. This performs a deterministic local
    challenge-signature round trip: the signer signs a fixed challenge and the
    signature is verified (raised to the public exponent) against the same
    challenge. A wrong private exponent produces a mismatching recovery.

    No production signing key is generated or exposed; the challenge is public
    and the verification uses only public parameters.
    """
    if not isinstance(signer, _PrivilegedVerifierSigner):
        return False
    if signer.modulus != modulus or signer.exponent != exponent:
        return False
    try:
        signature_hex = signer.sign_attestation_digest(SIGNER_COMPATIBILITY_CHALLENGE)
        signature_int = int(signature_hex, 16)
        expected_message = int.from_bytes(
            hashlib.sha256(SIGNER_COMPATIBILITY_CHALLENGE.encode("utf-8")).digest(), "big"
        )
        recovered_message = pow(signature_int, exponent, modulus)
    except Exception:
        return False
    return recovered_message == expected_message


def _signer_matches_canonical_authority(signer: Any) -> bool:
    """Return True only when a signer holds the pinned canonical private key.

    The Worker independently verifies receipt proofs against the pinned public
    modulus/exponent. A bridge whose signer does not match that authority could
    execute chargeable provider work that the Worker can never accept, so it must
    fail closed before any provider operation. Matching the public parameters is
    not sufficient; the private exponent must be proven compatible.
    """
    return _signer_holds_authority_private_key(
        signer,
        modulus=PINNED_VERIFIER_MODULUS,
        exponent=PINNED_VERIFIER_EXPONENT,
    )


def _assess_production_grounding(
    *,
    signer: Any,
    model_client: Any,
    sandbox_adapter: Any,
    materializer: Any,
    worker: Any,
    signer_authority: tuple[int, int] | None = None,
) -> tuple[bool, str | None]:
    """Positively confirm firsthand canonical provider execution grounding.

    LIVE_NEBIUS authority requires the exact canonical Nebius components reached
    through their real canonical live transports and canonical Token Factory
    endpoint identities, plus a signer bound to the production verification
    authority. Any caller-supplied fake, mock, or simulation component, any
    injected non-canonical transport, and any arbitrary HTTPS host yields
    FIXTURE-only provenance so that synthetic operation identities and fabricated
    receipts can never be certified.

    ``signer_authority`` is provided only by isolated fixture tests that inject an
    ephemeral authority; production callers omit it and the pinned authority is
    enforced.
    """
    from basebreak.adapters.nebius import (
        DEFAULT_API_BASE_URL,
        DEFAULT_SANDBOX_API_BASE_URL,
        NebiusModelClient,
        default_urllib_transport,
    )
    from basebreak.causal.engine import is_genuine_nebius_sandbox_adapter
    from basebreak.causal.materializer import CausalRepositoryMaterializer
    from basebreak.verifier.trust_bridge import TrustedVerifierWorker

    authority_modulus, authority_exponent = signer_authority or (
        PINNED_VERIFIER_MODULUS,
        PINNED_VERIFIER_EXPONENT,
    )
    if not _signer_holds_authority_private_key(
        signer, modulus=authority_modulus, exponent=authority_exponent
    ):
        return False, "Signer does not match the pinned production verification authority."
    if type(worker) is not TrustedVerifierWorker:
        return False, "Trusted verifier worker is not the canonical TrustedVerifierWorker."
    if type(model_client) is not NebiusModelClient:
        return False, "Model client is not the canonical NebiusModelClient."
    # DEFECT D: the inference client must traverse the canonical live transport to
    # the canonical Token Factory inference endpoint. A dependency-injected fake
    # transport or an arbitrary HTTPS host must never earn LIVE_NEBIUS authority.
    if getattr(model_client, "_transport", None) is not default_urllib_transport:
        return False, "Model client is not using the canonical live Nebius transport."
    model_config = getattr(model_client, "config", None)
    model_base_url = str(getattr(model_config, "api_base_url", "")).rstrip("/")
    if model_base_url != DEFAULT_API_BASE_URL.rstrip("/"):
        return False, (
            "Model client endpoint is not the canonical Nebius Token Factory inference endpoint."
        )
    if type(materializer) is not CausalRepositoryMaterializer:
        return False, "Materializer is not the canonical CausalRepositoryMaterializer."
    if not is_genuine_nebius_sandbox_adapter(sandbox_adapter):
        return False, "Sandbox adapter is not a genuine NebiusSandboxAdapter with credentials."
    if getattr(sandbox_adapter, "_transport", None) is not default_urllib_transport:
        return False, "Sandbox adapter is not using the canonical live Nebius transport."
    config = getattr(sandbox_adapter, "config", None)
    api_base_url = str(getattr(config, "api_base_url", "")).rstrip("/")
    if api_base_url != DEFAULT_SANDBOX_API_BASE_URL.rstrip("/"):
        return False, (
            "Sandbox adapter endpoint is not the canonical Nebius Token Factory sandbox endpoint."
        )
    return True, None


def _build_public_execution_fact(world_fact: Any) -> Any:
    from basebreak.causal.public_receipt import PublicExecutionFact

    return PublicExecutionFact(
        world=world_fact.world,
        sandbox_id=world_fact.sandbox_id,
        source_commit_id=world_fact.source_commit_id,
        tree_digest=world_fact.tree_digest,
        outcome=world_fact.outcome,
        exit_code=world_fact.exit_code,
        termination_status=world_fact.termination_status,
        stdout_digest=world_fact.stdout_digest,
        stderr_digest=world_fact.stderr_digest,
        duration_seconds=world_fact.duration_seconds,
    )


def _build_public_receipt_from_local_receipt(
    *,
    request: BridgeRequest,
    config: TrustedBridgeConfig,
    scenario: CanonicalLiveBridgeScenario,
    local_receipt: Any,
    model_result: Any,
    provider_operation_ids: Sequence[str],
    provenance: EvidenceProvenance,
    candidate_origin: str,
    candidate_patch_digest: str,
    model_call_count: int = 1,
    model_prompt_tokens: int = 0,
    model_completion_tokens: int = 0,
    model_usage_complete: bool = True,
    model_total_duration_seconds: float | None = None,
    candidate_generation_identities: Sequence[str] = (),
) -> PublicVerificationReceipt:
    from basebreak.causal.coverage import (
        CausalCoverageSummary,
        RequirementCausalState,
        RequirementEligibility,
        RequirementVerificationFact,
        compute_coverage_digest,
        compute_fact_digest,
    )
    from basebreak.causal.public_receipt import (
        PublicCostAccountingFact,
        PublicCounterfactualFact,
        PublicWitnessFact,
        create_public_verification_receipt,
    )

    causal_state = {
        "VERIFIED": RequirementCausalState.VERIFIED,
        "CONTRADICTED": RequirementCausalState.CONTRADICTED,
        "BLOCKED": RequirementCausalState.BLOCKED,
        "NOT_RUN": RequirementCausalState.NOT_RUN,
    }.get(local_receipt.verdict.value, RequirementCausalState.INCONCLUSIVE)
    requirement_fact = RequirementVerificationFact(
        requirement_id=scenario.requirement_id,
        change_class=scenario.frozen_contract.change_class,
        eligibility=RequirementEligibility.ELIGIBLE,
        causal_state=causal_state,
        preliminary_verdict=local_receipt.verdict,
        transition=local_receipt.transition,
        witness_id=local_receipt.witness_id,
        witness_digest=local_receipt.witness_digest,
        execution_obligation="FAIL_TO_PASS_WITH_COUNTERFACTUAL",
        rationale=local_receipt.narrative or "Trusted live bridge verification result",
        fact_digest=compute_fact_digest(
            requirement_id=scenario.requirement_id,
            change_class=scenario.frozen_contract.change_class,
            eligibility=RequirementEligibility.ELIGIBLE,
            causal_state=causal_state,
            preliminary_verdict=local_receipt.verdict,
            transition=local_receipt.transition,
            witness_id=local_receipt.witness_id,
            witness_digest=local_receipt.witness_digest,
            execution_obligation="FAIL_TO_PASS_WITH_COUNTERFACTUAL",
            rationale=local_receipt.narrative or "Trusted live bridge verification result",
        ),
    )
    verified_count = 1 if causal_state == RequirementCausalState.VERIFIED else 0
    contradicted_count = 1 if causal_state == RequirementCausalState.CONTRADICTED else 0
    blocked_count = 1 if causal_state == RequirementCausalState.BLOCKED else 0
    not_run_count = 1 if causal_state == RequirementCausalState.NOT_RUN else 0
    inconclusive_count = 1 if causal_state == RequirementCausalState.INCONCLUSIVE else 0
    coverage_ratio = 1.0 if verified_count == 1 else 0.0
    coverage_percentage = 100.0 if verified_count == 1 else 0.0
    coverage_summary = CausalCoverageSummary(
        contract_digest=scenario.frozen_contract_digest,
        total_requirements=1,
        eligible_count=1,
        excluded_count=0,
        verified_count=verified_count,
        not_run_count=not_run_count,
        inconclusive_count=inconclusive_count,
        contradicted_count=contradicted_count,
        blocked_count=blocked_count,
        coverage_ratio=coverage_ratio,
        coverage_percentage=coverage_percentage,
        is_fully_verified=verified_count == 1,
        overall_verdict=local_receipt.verdict,
        per_requirement_facts=(requirement_fact,),
        coverage_digest=compute_coverage_digest(
            contract_digest=scenario.frozen_contract_digest,
            total_requirements=1,
            eligible_count=1,
            excluded_count=0,
            verified_count=verified_count,
            not_run_count=not_run_count,
            inconclusive_count=inconclusive_count,
            contradicted_count=contradicted_count,
            blocked_count=blocked_count,
            coverage_ratio=coverage_ratio,
            coverage_percentage=coverage_percentage,
            is_fully_verified=verified_count == 1,
            overall_verdict=local_receipt.verdict,
            per_requirement_facts=(requirement_fact,),
        ),
    )

    base_exec = _build_public_execution_fact(local_receipt.base_execution)
    candidate_exec = _build_public_execution_fact(local_receipt.candidate_execution)

    counterfactual = None
    sandbox_runtime_seconds = float(local_receipt.base_execution.duration_seconds) + float(
        local_receipt.candidate_execution.duration_seconds
    )
    if local_receipt.counterfactual_execution is not None:
        cf_exec = _build_public_execution_fact(local_receipt.counterfactual_execution)
        sandbox_runtime_seconds += float(local_receipt.counterfactual_execution.duration_seconds)
        counterfactual = PublicCounterfactualFact(
            is_required=True,
            candidate_tree_digest=local_receipt.candidate_execution.tree_digest,
            delta_digest=local_receipt.delta_digest,
            outcome=local_receipt.counterfactual_execution.outcome,
            execution_fact=cf_exec,
        )

    # ``estimated_cost_usd`` records the operator/server-approved worst-case
    # estimate only. It is explicitly NOT provider-observed consumption, and
    # ``is_metered`` remains False while genuine provider cost is unknown.
    # Accounting aggregates EVERY attempted model call (identity probe plus, on the
    # genuine path, candidate generation); a failed later call never erases the
    # exposure of an earlier successful call.
    accounting = PublicCostAccountingFact(
        model_call_count=model_call_count,
        prompt_tokens=model_prompt_tokens,
        completion_tokens=model_completion_tokens,
        sandbox_runtime_seconds=round(sandbox_runtime_seconds, 4),
        estimated_cost_usd=round(float(request.max_estimated_cost_usd), 6),
        is_metered=False,
    )

    runtime_identities = [
        "bridge:trusted-python",
        f"source:{request.source_commit_id}",
        f"candidate-origin:{candidate_origin}",
        f"sandbox:{local_receipt.base_execution.sandbox_id}",
        f"sandbox:{local_receipt.candidate_execution.sandbox_id}",
    ]
    if str(getattr(model_result, "returned_model", "")).strip():
        runtime_identities.append(f"model:{model_result.returned_model}")
    if getattr(model_result, "request_id", None):
        runtime_identities.append(f"model-request:{model_result.request_id}")
    if local_receipt.counterfactual_execution is not None:
        runtime_identities.append(f"sandbox:{local_receipt.counterfactual_execution.sandbox_id}")
    runtime_identities.extend(f"nebius-operation:{op_id}" for op_id in provider_operation_ids)
    runtime_identities.append(f"model-calls:{model_call_count}")
    runtime_identities.append(
        "model-usage:complete" if model_usage_complete else "model-usage:incomplete"
    )
    runtime_identities.extend(str(identity).strip() for identity in candidate_generation_identities)

    return create_public_verification_receipt(
        frozen_contract_digest=scenario.frozen_contract_digest,
        task_id=request.task_id,
        repo_locator=config.source_repo_locator,
        source_commit_id=request.source_commit_id,
        candidate_tree_digest=local_receipt.candidate_execution.tree_digest,
        candidate_patch_digest=candidate_patch_digest,
        coverage_summary=coverage_summary,
        executions=tuple(
            exec_fact
            for exec_fact in (
                base_exec,
                candidate_exec,
                counterfactual.execution_fact if counterfactual is not None else None,
            )
            if exec_fact is not None
        ),
        witnesses=(
            PublicWitnessFact(
                witness_id=local_receipt.witness_id,
                witness_digest=local_receipt.witness_digest,
                lock_digest=local_receipt.lock_digest,
                requirement_id=local_receipt.requirement_id,
                execution_command=scenario.execution_command,
                timeout_seconds=30.0,
            ),
        ),
        counterfactual=counterfactual,
        overall_verdict=local_receipt.verdict,
        provenance=provenance,
        runtime_identities=tuple(runtime_identities),
        timing={
            "created_at_utc": local_receipt.created_at_utc,
            "total_duration_seconds": round(
                sandbox_runtime_seconds
                + (
                    float(model_total_duration_seconds)
                    if model_total_duration_seconds is not None
                    else float(getattr(model_result, "duration_seconds", 0.0) or 0.0)
                ),
                4,
            ),
        },
        accounting=accounting,
    )


def _normalize_provider_operation_ids(operation_ids: Sequence[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for operation_id in operation_ids:
        clean = str(operation_id).strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        normalized.append(clean)
    return tuple(normalized)


def _validate_live_bridge_execution_authority(
    request: BridgeRequest,
    result: BridgeExecutionResult,
) -> tuple[bool, str | None]:
    scenario = _load_canonical_live_bridge_scenario()
    receipt = result.receipt
    if receipt is None:
        return False, "Bridge execution authority validation requires a public receipt."

    # 1. Firsthand canonical provider grounding. Reported identity strings alone
    #    never grant authority; the executor must have positively confirmed that
    #    it used the canonical Nebius adapter/model/worker over real transports
    #    and a signer bound to the pinned production verification authority.
    if not result.production_grounded:
        return (
            False,
            "Independent live execution authority requires firsthand canonical Nebius "
            "provider grounding; synthetic or injected execution dependencies cannot "
            "grant LIVE_NEBIUS certification"
            + (f": {result.grounding_error}" if result.grounding_error else "."),
        )

    # 2. Independently re-verify the trusted verifier attestation against the
    #    pinned canonical authority root. A synthetic three-world receipt signed
    #    by a non-canonical or attacker-controlled key must fail closed here even
    #    if every reported string is internally consistent.
    local_receipt = result.local_receipt
    if local_receipt is None:
        return False, "Independent live execution authority requires the trusted local receipt."
    attestation = getattr(local_receipt, "attestation", None)
    if attestation is None:
        return False, "Independent live execution authority requires a verifier attestation."
    from basebreak.verifier.trust_bridge import verify_trusted_production_evidence

    if not verify_trusted_production_evidence(
        receipt=local_receipt,
        expected_requirement_id=scenario.requirement_id,
        expected_contract_digest=scenario.frozen_contract_digest,
        expected_provenance=EvidenceProvenance.LIVE_NEBIUS,
    ):
        return (
            False,
            "Independent live execution authority rejected the verifier attestation: "
            "it is not bound to the pinned canonical production authority.",
        )

    if receipt.provenance != EvidenceProvenance.LIVE_NEBIUS:
        return False, "Receipt provenance must be LIVE_NEBIUS."
    if receipt.task_id != request.task_id:
        return False, "Receipt task_id does not match the trusted bridge request."
    if receipt.source_commit_id.lower() != request.source_commit_id.lower():
        return False, "Receipt source_commit_id does not match the trusted bridge request."
    if receipt.frozen_contract_digest.lower() != request.frozen_contract_digest.lower():
        return False, "Receipt frozen_contract_digest does not match the trusted request."
    if (
        result.candidate_patch_digest is None
        or receipt.candidate_patch_digest != result.candidate_patch_digest
    ):
        return False, "Receipt candidate_patch_digest does not match the executed candidate."
    if (
        result.candidate_origin == CANDIDATE_ORIGIN_DETERMINISTIC_FIXTURE
        and receipt.candidate_patch_digest != scenario.candidate_patch_digest
    ):
        return False, (
            "Deterministic candidate receipt does not match the canonical fixture patch."
        )
    from basebreak.deployment.model_candidate import (
        MODEL_GENERATED_CANDIDATE_ORIGIN,
        ModelCandidateError,
        verify_candidate_generation_binding,
    )

    if (
        receipt.provenance == EvidenceProvenance.LIVE_NEBIUS
        and result.candidate_origin != MODEL_GENERATED_CANDIDATE_ORIGIN
    ):
        return False, ("LIVE_NEBIUS authority requires a genuine model-generated candidate origin.")
    if result.candidate_origin == MODEL_GENERATED_CANDIDATE_ORIGIN:
        candidate_generation = result.candidate_generation
        if candidate_generation is None:
            return False, (
                "Model-generated candidate authority requires the bound generation evidence."
            )
        try:
            allowed_paths, authorized_base_files = _reset_vault_candidate_base_files(
                _default_repo_root(), request.source_commit_id
            )
            expected_candidate_tree = _compute_candidate_tree_digest(
                repo_root=_default_repo_root(),
                source_commit_id=request.source_commit_id,
                patch_text=candidate_generation.patch_text,
            )
        except BridgeValidationError as exc:
            return False, f"Model-generated candidate source binding failed: {exc}"
        try:
            verify_candidate_generation_binding(
                candidate_generation,
                receipt_runtime_identities=receipt.runtime_identities,
                allowed_paths=allowed_paths,
                authorized_base_files=authorized_base_files,
                expected_candidate_tree_digest=expected_candidate_tree,
                observed_candidate_tree_digest=receipt.candidate_tree_digest,
            )
        except ModelCandidateError as exc:
            return False, f"Model-generated candidate provenance failed verification: {exc}"

    operation_ids = _normalize_provider_operation_ids(result.provider_operation_ids)
    if not operation_ids:
        return False, "Independent execution authority requires recorded Nebius operation IDs."

    runtime_identities = {
        str(identity).strip() for identity in receipt.runtime_identities if str(identity).strip()
    }
    missing_ops = [
        operation_id
        for operation_id in operation_ids
        if f"nebius-operation:{operation_id}" not in runtime_identities
    ]
    if missing_ops:
        return (
            False,
            "Receipt runtime identities are missing one or more Nebius operation bindings: "
            + ", ".join(missing_ops),
        )

    executions = {execution.world.value: execution for execution in receipt.executions}
    if "BASE" not in executions or "CANDIDATE" not in executions:
        return False, "Receipt must include both BASE and CANDIDATE execution facts."
    if executions["CANDIDATE"].tree_digest.lower() != receipt.candidate_tree_digest.lower():
        return False, "Receipt candidate execution tree digest does not match receipt binding."

    sandbox_ids = {
        executions["BASE"].sandbox_id,
        executions["CANDIDATE"].sandbox_id,
    }
    if receipt.counterfactual is not None and receipt.counterfactual.execution_fact is not None:
        sandbox_ids.add(receipt.counterfactual.execution_fact.sandbox_id)
    if len(sandbox_ids) != (3 if receipt.counterfactual is not None else 2):
        return False, "Receipt reused sandbox identities across isolated execution worlds."

    if not any(identity.startswith("model:") for identity in runtime_identities):
        return False, "Receipt runtime identities are missing the authenticated model binding."

    # 3. Cross-bind the independently verified attestation to the public receipt
    #    and to the reported provider operation identities. A genuine attestation
    #    cannot be replayed against a differently-bound public receipt.
    if str(attestation.source_commit_id).lower() != receipt.source_commit_id.lower():
        return False, "Attestation source_commit_id does not match the public receipt."
    if str(attestation.candidate_tree_digest).lower() != receipt.candidate_tree_digest.lower():
        return False, "Attestation candidate_tree_digest does not match the public receipt."
    if attestation.base_sandbox_id != executions["BASE"].sandbox_id:
        return False, "Attestation BASE sandbox_id does not match the public receipt."
    if attestation.candidate_sandbox_id != executions["CANDIDATE"].sandbox_id:
        return False, "Attestation CANDIDATE sandbox_id does not match the public receipt."
    if attestation.base_outcome != executions["BASE"].outcome:
        return False, "Attestation BASE outcome does not match the public receipt."
    if attestation.candidate_outcome != executions["CANDIDATE"].outcome:
        return False, "Attestation CANDIDATE outcome does not match the public receipt."
    if receipt.counterfactual is not None and receipt.counterfactual.execution_fact is not None:
        cf_fact = receipt.counterfactual.execution_fact
        if attestation.counterfactual_sandbox_id != cf_fact.sandbox_id:
            return False, "Attestation COUNTERFACTUAL sandbox_id does not match the public receipt."
        if attestation.counterfactual_outcome != cf_fact.outcome:
            return False, "Attestation COUNTERFACTUAL outcome does not match the public receipt."

    return True, None


def create_live_nebius_execution_authority_verifier() -> BridgeExecutionAuthorityVerifier:
    return _validate_live_bridge_execution_authority


def create_live_nebius_bridge_executor(
    *,
    config: TrustedBridgeConfig,
    signer: _PrivilegedVerifierSigner | None = None,
    verifier_authority: Any | None = None,
    model_client: Any | None = None,
    sandbox_adapter: Any | None = None,
    sandbox_manager: Any | None = None,
    materializer: Any | None = None,
    verifier_worker: Any | None = None,
    vault: Any | None = None,
) -> BridgeExecutor:
    def _executor(request: BridgeRequest) -> BridgeExecutionResult:
        from types import SimpleNamespace

        from basebreak.adapters.nebius import (
            ModelClientConfig,
            ModelNetworkError,
            ModelTimeoutError,
            NebiusModelClient,
            NebiusSandboxAdapter,
            SandboxClientConfig,
            SandboxTimeoutError,
            SandboxTransportError,
        )
        from basebreak.causal.materializer import CausalRepositoryMaterializer
        from basebreak.causal.subtraction import (
            CandidateDeltaSubtractor,
            SubtractionRequest,
            SubtractionStrategyType,
        )
        from basebreak.domain.causal import CandidateIdentity
        from basebreak.domain.source import CommitRevision, SourceIdentity
        from basebreak.domain.verdict import EvidenceProvenance
        from basebreak.verifier.context import VerifierContextEnvelope
        from basebreak.verifier.sandbox import VerifierSandboxManager
        from basebreak.verifier.trust_bridge import (
            TrustedVerifierWorker,
            VerifierExecutionBlockedError,
        )
        from basebreak.verifier.witness_lock import create_witness_lock
        from basebreak.verifier.witness_store import TrustedWitnessVault, WitnessArtifact

        scenario = _load_canonical_live_bridge_scenario()
        repo_root = _resolve_local_repo_root(config)
        active_signer = signer or _PrivilegedVerifierSigner.from_environment()
        active_model_client = model_client or NebiusModelClient(
            config=ModelClientConfig(
                api_key=config.nebius_api_key,
                project_id=config.nebius_project_id,
                timeout_seconds=config.model_timeout_seconds,
            )
        )
        active_sandbox_adapter = sandbox_adapter or NebiusSandboxAdapter(
            config=SandboxClientConfig(
                api_key=config.nebius_api_key,
                project_id=config.nebius_project_id,
            )
        )
        active_sandbox_manager = sandbox_manager or VerifierSandboxManager()
        active_materializer = materializer or CausalRepositoryMaterializer(
            adapter=active_sandbox_adapter
        )
        active_worker = verifier_worker or TrustedVerifierWorker(signer=active_signer)
        active_vault = vault or TrustedWitnessVault()

        # DEFECT A: positively ground the execution in firsthand canonical Nebius
        # components before any LIVE_NEBIUS authority can be produced. Injected
        # fakes/mocks downgrade the result to FIXTURE-only provenance so synthetic
        # operation identities can never be certified as genuine live evidence.
        production_grounded, grounding_error = _assess_production_grounding(
            signer=active_signer,
            model_client=active_model_client,
            sandbox_adapter=active_sandbox_adapter,
            materializer=active_materializer,
            worker=active_worker,
        )
        result_provenance = (
            EvidenceProvenance.LIVE_NEBIUS if production_grounded else EvidenceProvenance.FIXTURE
        )

        # Conservative accounting defaults: never overclaim metered usage. These are
        # refined immediately as calls succeed; outer failure handlers retain all
        # already-observed generation facts rather than resetting them.
        approved_estimate_usd = round(float(request.max_estimated_cost_usd), 6)
        reserved_exposure_usd = round(float(request.max_estimated_cost_usd), 6)
        model_call_count = 0
        model_prompt_tokens = 0
        model_completion_tokens = 0
        model_usage_complete = not production_grounded
        model_total_duration_seconds = 0.0
        result_tokens_used = 0
        provider_request_id: str | None = None
        candidate_origin_value = CANDIDATE_ORIGIN_DETERMINISTIC_FIXTURE
        candidate_patch_digest: str | None = None
        candidate_generation_evidence: Any | None = None

        try:
            source_identity = SourceIdentity(
                config.source_repo_locator,
                CommitRevision(request.source_commit_id),
                subpath=request.target,
            )

            if production_grounded:
                # Genuine path: the candidate MUST come from the configured model.
                # On any generation failure this fails closed and NEVER substitutes the
                # deterministic fixture patch or promotes it to an AI-written claim.
                from basebreak.deployment.model_candidate import (
                    MODEL_GENERATED_CANDIDATE_ORIGIN,
                    ModelCandidateError,
                    candidate_generation_identities,
                    generate_model_candidate,
                )

                allowed_paths, base_files = _reset_vault_candidate_base_files(
                    repo_root, request.source_commit_id
                )
                try:
                    model_candidate = generate_model_candidate(
                        model_client=active_model_client,
                        task_id=scenario.task_id,
                        requirement_statement=scenario.frozen_contract.requirements[0].statement,
                        frozen_contract_digest=scenario.frozen_contract_digest,
                        target=scenario.target,
                        allowed_paths=allowed_paths,
                        base_files=base_files,
                        max_tokens=config.candidate_max_tokens,
                    )
                except ModelCandidateError as exc:
                    generation_attempted = bool(getattr(exc, "generation_attempted", False))
                    exc_provider_request_id = getattr(exc, "provider_request_id", None)
                    if generation_attempted:
                        blocked_call_count = int(getattr(exc, "model_call_count", None) or 1)
                        blocked_prompt_tokens = int(
                            getattr(exc, "generation_prompt_tokens", None) or 0
                        )
                        blocked_completion_tokens = int(
                            getattr(exc, "generation_completion_tokens", None) or 0
                        )
                        blocked_usage_complete = bool(
                            getattr(exc, "generation_prompt_tokens", None) is not None
                            and getattr(exc, "generation_completion_tokens", None) is not None
                        )
                        blocked_tokens_used = int(
                            getattr(exc, "generation_total_tokens", None) or 0
                        )
                        blocked_request_ids = tuple(getattr(exc, "provider_request_ids", ()))
                    else:
                        blocked_call_count = 0
                        blocked_prompt_tokens = 0
                        blocked_completion_tokens = 0
                        blocked_usage_complete = True
                        blocked_tokens_used = 0
                        blocked_request_ids = ()
                    return BridgeExecutionResult(
                        status="BLOCKED_CANDIDATE_GENERATION_FAILED",
                        error=str(exc),
                        approved_estimate_usd=approved_estimate_usd,
                        reserved_exposure_usd=reserved_exposure_usd,
                        observed_cost_usd=None,
                        cost_provenance="UNKNOWN",
                        tokens_used=blocked_tokens_used,
                        model_call_count=blocked_call_count,
                        model_prompt_tokens=blocked_prompt_tokens,
                        model_completion_tokens=blocked_completion_tokens,
                        model_usage_complete=blocked_usage_complete,
                        provider_request_id=exc_provider_request_id,
                        provider_request_ids=blocked_request_ids,
                        provider_operation_ids=_normalize_provider_operation_ids(
                            getattr(active_sandbox_adapter, "live_operation_ids", ())
                        ),
                    )
                candidate_patch_text = model_candidate.patch_text
                candidate_patch_digest = model_candidate.patch_digest
                candidate_origin_value = MODEL_GENERATED_CANDIDATE_ORIGIN
                candidate_generation_evidence = model_candidate
                candidate_generation_identity_values = candidate_generation_identities(
                    model_candidate
                )
                candidate_identity = CandidateIdentity(
                    model_candidate.candidate_id,
                    source_identity,
                    candidate_patch_digest,
                    description="Model-generated ResetVault candidate (genuine model output)",
                )
                # Assign post-generation accounting immediately after genuine candidate
                # generation succeeds so any subsequent tree calculation, materialization,
                # or verifier setup failure retains already-observed inference facts.
                model_call_count = int(getattr(model_candidate, "model_call_count", 1) or 1)
                model_prompt_tokens = int(model_candidate.generation_prompt_tokens or 0)
                model_completion_tokens = int(model_candidate.generation_completion_tokens or 0)
                model_usage_complete = (
                    model_candidate.generation_prompt_tokens is not None
                    and model_candidate.generation_completion_tokens is not None
                )
                model_total_duration_seconds = float(
                    model_candidate.generation_duration_seconds or 0.0
                )
                result_tokens_used = int(model_candidate.generation_total_tokens or 0)
                provider_request_id = model_candidate.provider_request_id
                provider_request_ids = tuple(getattr(model_candidate, "provider_request_ids", ()))
            else:
                # Synthetic/fixture dependencies: deterministic fixture candidate, honestly
                # labeled. This path can never claim a genuine AI-written candidate.
                candidate_patch_text = scenario.candidate_patch_text
                candidate_patch_digest = scenario.candidate_patch_digest
                candidate_origin_value = CANDIDATE_ORIGIN_DETERMINISTIC_FIXTURE
                candidate_generation_evidence = None
                candidate_generation_identity_values = ()
                candidate_identity = CandidateIdentity(
                    f"cand-live-{scenario.candidate_patch_digest[:16]}",
                    source_identity,
                    candidate_patch_digest,
                    description="Canonical ResetVault candidate (deterministic bridge fixture)",
                )
                model_call_count = 0
                model_prompt_tokens = 0
                model_completion_tokens = 0
                model_usage_complete = True
                model_total_duration_seconds = 0.0
                result_tokens_used = 0
                provider_request_id = None
                provider_request_ids = ()

            candidate_tree_digest = _compute_candidate_tree_digest(
                repo_root=repo_root,
                source_commit_id=request.source_commit_id,
                patch_text=candidate_patch_text,
            )

            witness_artifact = WitnessArtifact.from_text(
                scenario.witness_artifact_path,
                _build_reset_vault_witness_content(),
            )
            sealed_record = active_vault.seal_witness(
                witness_id="wit-reset-vault-live-001",
                requirement_id=scenario.requirement_id,
                frozen_contract_digest=scenario.frozen_contract_digest,
                source_commit_id=request.source_commit_id,
                artifacts=[witness_artifact],
            )
            witness_lock = create_witness_lock(record=sealed_record, vault=active_vault)

            context_envelope = VerifierContextEnvelope.create(
                frozen_contract=scenario.frozen_contract,
                source_identity=source_identity,
                candidate_identity=candidate_identity,
                candidate_patch_text=candidate_patch_text,
                candidate_tree_digest=candidate_tree_digest,
                sealed_witness_references=(sealed_record.witness_id,),
            )
            counterfactual_plan = CandidateDeltaSubtractor.plan_subtraction(
                candidate_id=candidate_identity.candidate_id,
                candidate_patch_text=candidate_patch_text,
                candidate_patch_digest=candidate_patch_digest,
                candidate_tree_digest=candidate_tree_digest,
                source_commit_id=request.source_commit_id,
                frozen_contract_digest=scenario.frozen_contract_digest,
                sealed_witness_digest=sealed_record.seal_digest,
                request=SubtractionRequest(
                    strategy_type=SubtractionStrategyType.FULL_PATCH_REVERT,
                    description="Canonical ResetVault live counterfactual",
                ),
                source_identity=source_identity,
            )

            before_ops = _normalize_provider_operation_ids(
                getattr(active_sandbox_adapter, "live_operation_ids", ())
            )
            local_receipt = active_worker.execute_causal_triplet(
                context_envelope=context_envelope,
                sealed_record=sealed_record,
                witness_lock=witness_lock,
                counterfactual_plan=counterfactual_plan,
                execution_command=scenario.execution_command,
                provenance=result_provenance,
                sandbox_manager=active_sandbox_manager,
                sandbox_adapter=active_sandbox_adapter,
                materializer=active_materializer,
                vault=active_vault,
            )
            after_ops = _normalize_provider_operation_ids(
                getattr(active_sandbox_adapter, "live_operation_ids", ())
            )
            provider_operation_ids = (
                after_ops[len(before_ops) :]
                if len(after_ops) >= len(before_ops) and after_ops[: len(before_ops)] == before_ops
                else after_ops
            )

            world_diagnostics = tuple(
                getattr(active_worker, "last_execution_diagnostics", ()) or ()
            )
            diag_record = None
            if world_diagnostics:
                try:
                    import datetime

                    from basebreak.deployment.diagnostics import (
                        ExecutionDiagnosticRecord,
                        record_execution_diagnostics,
                    )

                    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    diag_record = ExecutionDiagnosticRecord(
                        request_id=request.request_id,
                        source_commit_id=request.source_commit_id,
                        candidate_patch_digest=candidate_patch_digest,
                        candidate_tree_digest=candidate_tree_digest,
                        world_diagnostics=world_diagnostics,
                        overall_verdict=local_receipt.verdict.value,
                        created_at_utc=now_utc,
                    )
                    if config.bridge_state_dir:
                        record_execution_diagnostics(config.bridge_state_dir, diag_record)
                except Exception:
                    pass

            candidate_generation_identity_values_with_diags = list(
                candidate_generation_identity_values
            )
            for wd in world_diagnostics:
                candidate_generation_identity_values_with_diags.append(
                    f"diag-{wd.world.lower()}:{wd.diagnostic_category.value}"
                )

            if production_grounded:
                model_result = SimpleNamespace(
                    returned_model=model_candidate.returned_model,
                    request_id=model_candidate.provider_request_id,
                    duration_seconds=float(model_candidate.generation_duration_seconds or 0.0),
                )
            else:
                model_result = SimpleNamespace(
                    returned_model="", request_id=None, duration_seconds=0.0
                )

            public_receipt = _build_public_receipt_from_local_receipt(
                request=request,
                config=config,
                scenario=scenario,
                local_receipt=local_receipt,
                model_result=model_result,
                provider_operation_ids=provider_operation_ids,
                provenance=result_provenance,
                candidate_origin=candidate_origin_value,
                candidate_patch_digest=candidate_patch_digest,
                model_call_count=model_call_count,
                model_prompt_tokens=model_prompt_tokens,
                model_completion_tokens=model_completion_tokens,
                model_usage_complete=model_usage_complete,
                model_total_duration_seconds=model_total_duration_seconds,
                candidate_generation_identities=candidate_generation_identity_values_with_diags,
            )

            return BridgeExecutionResult(
                status="COMPLETED",
                receipt=public_receipt,
                local_receipt=local_receipt,
                production_grounded=production_grounded,
                grounding_error=grounding_error,
                approved_estimate_usd=approved_estimate_usd,
                reserved_exposure_usd=reserved_exposure_usd,
                # Genuine provider-observed cost is not measured here. UNKNOWN must
                # never be substituted with the approved estimate or the grant cap.
                observed_cost_usd=None,
                cost_provenance="UNKNOWN",
                tokens_used=result_tokens_used,
                provider_operation_ids=provider_operation_ids,
                candidate_origin=candidate_origin_value,
                candidate_patch_digest=candidate_patch_digest,
                candidate_generation=candidate_generation_evidence,
                model_call_count=model_call_count,
                model_prompt_tokens=model_prompt_tokens,
                model_completion_tokens=model_completion_tokens,
                model_usage_complete=model_usage_complete,
                provider_request_id=provider_request_id,
                provider_request_ids=provider_request_ids,
                diagnostic_record=diag_record,
            )
        except (
            ModelTimeoutError,
            ModelNetworkError,
            SandboxTimeoutError,
            SandboxTransportError,
        ) as exc:
            return BridgeExecutionResult(
                status="UNKNOWN_OUTCOME",
                error=str(exc),
                ambiguous_outcome=True,
                production_grounded=production_grounded,
                grounding_error=grounding_error,
                approved_estimate_usd=approved_estimate_usd,
                reserved_exposure_usd=reserved_exposure_usd,
                observed_cost_usd=None,
                cost_provenance="UNKNOWN",
                tokens_used=result_tokens_used,
                candidate_origin=candidate_origin_value,
                candidate_patch_digest=candidate_patch_digest,
                candidate_generation=candidate_generation_evidence,
                model_call_count=model_call_count,
                model_prompt_tokens=model_prompt_tokens,
                model_completion_tokens=model_completion_tokens,
                model_usage_complete=model_usage_complete,
                provider_request_id=provider_request_id,
                provider_request_ids=provider_request_ids,
                provider_operation_ids=_normalize_provider_operation_ids(
                    getattr(active_sandbox_adapter, "live_operation_ids", ())
                ),
            )
        except VerifierExecutionBlockedError as exc:
            return BridgeExecutionResult(
                status="BLOCKED",
                error=str(exc),
                production_grounded=production_grounded,
                grounding_error=grounding_error,
                approved_estimate_usd=approved_estimate_usd,
                reserved_exposure_usd=reserved_exposure_usd,
                observed_cost_usd=None,
                cost_provenance="UNKNOWN",
                tokens_used=result_tokens_used,
                candidate_origin=candidate_origin_value,
                candidate_patch_digest=candidate_patch_digest,
                candidate_generation=candidate_generation_evidence,
                model_call_count=model_call_count,
                model_prompt_tokens=model_prompt_tokens,
                model_completion_tokens=model_completion_tokens,
                model_usage_complete=model_usage_complete,
                provider_request_id=provider_request_id,
                provider_request_ids=provider_request_ids,
                provider_operation_ids=_normalize_provider_operation_ids(
                    getattr(active_sandbox_adapter, "live_operation_ids", ())
                ),
            )
        except Exception as exc:
            return BridgeExecutionResult(
                status="FAILED",
                error=str(exc),
                production_grounded=production_grounded,
                grounding_error=grounding_error,
                approved_estimate_usd=approved_estimate_usd,
                reserved_exposure_usd=reserved_exposure_usd,
                observed_cost_usd=None,
                cost_provenance="UNKNOWN",
                tokens_used=result_tokens_used,
                candidate_origin=candidate_origin_value,
                candidate_patch_digest=candidate_patch_digest,
                candidate_generation=candidate_generation_evidence,
                model_call_count=model_call_count,
                model_prompt_tokens=model_prompt_tokens,
                model_completion_tokens=model_completion_tokens,
                model_usage_complete=model_usage_complete,
                provider_request_id=provider_request_id,
                provider_request_ids=provider_request_ids,
                provider_operation_ids=_normalize_provider_operation_ids(
                    getattr(active_sandbox_adapter, "live_operation_ids", ())
                ),
            )

    return _executor


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
    """Fail-closed bridge controller between the Worker and Python verifier boundary.

    Durable single-execution state is mandatory for production live execution.
    The bridge never silently substitutes ephemeral ``tempfile`` storage for the
    configured durable state directory: a missing ``TRUSTED_VERIFIER_BRIDGE_STATE_DIR``
    fails closed before any chargeable provider operation. Ephemeral state is
    permitted only when ``allow_ephemeral_test_state`` is explicitly enabled by an
    isolated fixture test. Durability scope is a single host with a persistent
    volume; cross-host durability is NOT claimed.
    """

    def __init__(
        self,
        *,
        config: TrustedBridgeConfig,
        executor: BridgeExecutor | None = None,
        signer: _PrivilegedVerifierSigner | None = None,
        execution_authority_verifier: BridgeExecutionAuthorityVerifier | None = None,
        idempotency_store: ExecutionIdempotencyStore | None = None,
        signer_authority: tuple[int, int] | None = None,
        allow_ephemeral_test_state: bool = False,
    ) -> None:
        self.config = config
        self.executor = executor
        self.signer = signer or _PrivilegedVerifierSigner.from_environment()
        self.execution_authority_verifier = execution_authority_verifier
        # Production binds to the pinned verifier authority. Isolated fixture
        # tests may inject an ephemeral authority so that the same cryptographic
        # signer-compatibility proof is still exercised without real key material.
        self.signer_authority: tuple[int, int] = signer_authority or (
            PINNED_VERIFIER_MODULUS,
            PINNED_VERIFIER_EXPONENT,
        )
        self.idempotency_store: ExecutionIdempotencyStore | None
        self.idempotency_store_error: str | None = None
        if idempotency_store is not None:
            self.idempotency_store = idempotency_store
        elif config.bridge_state_dir:
            try:
                self.idempotency_store = ExecutionIdempotencyStore(config.bridge_state_dir)
            except DurableIdempotencyUnavailableError as exc:
                self.idempotency_store = None
                self.idempotency_store_error = str(exc)
        elif allow_ephemeral_test_state:
            # Explicitly isolated fixture testing only. Never reachable from the
            # production bridge factory.
            try:
                self.idempotency_store = ExecutionIdempotencyStore(
                    tempfile.mkdtemp(prefix="basebreak_bridge_state_")
                )
            except DurableIdempotencyUnavailableError as exc:
                self.idempotency_store = None
                self.idempotency_store_error = str(exc)
        else:
            self.idempotency_store = None
            self.idempotency_store_error = (
                "No durable bridge state directory is configured. Production live "
                f"execution requires an explicit persistent {BRIDGE_STATE_DIR_ENV} "
                "volume; ephemeral storage is forbidden outside isolated fixture tests."
            )

    def _error(
        self,
        status_code: int,
        status: str,
        error: str,
        *,
        ambiguous_outcome: bool = False,
        provider_dispatched: bool = False,
    ) -> tuple[int, dict[str, Any]]:
        return status_code, {
            "ok": False,
            "status": status,
            "error": error,
            "ambiguous_outcome": ambiguous_outcome,
            # Whether a chargeable provider operation may have started. The Worker
            # uses this to distinguish execution-outcome certainty from billing
            # certainty; it is never inferred from FAILED alone.
            "provider_dispatched": provider_dispatched,
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
        scenario = _load_canonical_live_bridge_scenario()
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
        if request.task_id != scenario.task_id:
            return self._error(
                400,
                "INVALID_TASK",
                "Trusted bridge rejected task substitution for the canonical live scenario.",
            )
        if request.change_class != scenario.change_class:
            return self._error(
                400,
                "INVALID_CHANGE_CLASS",
                "Trusted bridge rejected change_class substitution for the canonical "
                "live scenario.",
            )
        if request.frozen_contract_digest.lower() != scenario.frozen_contract_digest.lower():
            return self._error(
                400,
                "INVALID_CONTRACT",
                "Trusted bridge rejected frozen_contract_digest substitution.",
            )
        if request.max_estimated_cost_usd <= 0.0:
            return self._error(
                422,
                "BLOCKED_ESTIMATED_COST_UNKNOWN",
                "Maximum estimated live cost must be positive.",
            )
        # DEFECT C: enforce explicit issue/deadline bounds before any dispatch.
        now_ms = int(time.time() * 1000)
        if request.deadline_ms <= request.issued_at_ms:
            return self._error(
                400,
                "INVALID_DEADLINE",
                "Bridge request deadline_ms must be strictly after issued_at_ms.",
            )
        max_window_ms = self.config.request_ttl_seconds * 1000
        if request.deadline_ms - request.issued_at_ms > max_window_ms:
            return self._error(
                400,
                "INVALID_DEADLINE",
                "Bridge request deadline exceeds the configured maximum request window.",
            )
        if request.deadline_ms <= now_ms:
            return self._error(
                410,
                "EXPIRED_REQUEST",
                "Bridge request deadline has already passed; refusing to dispatch inference "
                "or sandbox operations for an expired request.",
            )
        allowed_skew_ms = max(5000, self.config.request_ttl_seconds * 1000)
        if request.issued_at_ms > now_ms + allowed_skew_ms:
            return self._error(
                400,
                "INVALID_ISSUED_AT",
                "Bridge request issued_at_ms is implausibly in the future.",
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

        # DEFECT D: fail closed BEFORE any chargeable provider operation when the
        # configured signer does not hold the production verification authority
        # (or injected fixture authority) private key that the Worker accepts.
        if not _signer_holds_authority_private_key(
            self.signer,
            modulus=self.signer_authority[0],
            exponent=self.signer_authority[1],
        ):
            return self._error(
                503,
                "BLOCKED_INCOMPATIBLE_SIGNING_AUTHORITY",
                "Trusted verifier signing authority does not correspond to the pinned "
                "production verification authority accepted by the Worker.",
            )

        if self.executor is None:
            return self._error(
                503,
                "NOT_READY_FOR_DEPLOYMENT",
                "Trusted verifier executor is not configured.",
            )

        # DEFECT C: durable, atomic single-execution protection keyed by request_id.
        # Fail closed rather than risk a second chargeable provider dispatch.
        if self.idempotency_store is None:
            return self._error(
                503,
                "BLOCKED_DURABLE_IDEMPOTENCY_UNAVAILABLE",
                self.idempotency_store_error
                or "Durable single-execution protection is unavailable; refusing to dispatch.",
            )
        try:
            claim = self.idempotency_store.begin(request_obj.request_id)
        except DurableIdempotencyUnavailableError as exc:
            return self._error(503, "BLOCKED_DURABLE_IDEMPOTENCY_UNAVAILABLE", str(exc))

        claim_state = str(claim.get("state", "")).strip()
        if claim_state == "COMPLETED":
            cached = claim.get("response")
            if isinstance(cached, dict):
                return 200, {**cached, "replayed": True}
            return self._error(
                503,
                "BLOCKED_DURABLE_IDEMPOTENCY_UNAVAILABLE",
                "Durable idempotency record is corrupt; refusing to re-execute.",
            )
        if claim_state == "IN_PROGRESS":
            return self._error(
                409,
                "CONCURRENT_DUPLICATE_REQUEST",
                "An execution for this request_id is already in progress or was interrupted; "
                "refusing to trigger a second chargeable execution.",
                ambiguous_outcome=True,
            )
        if claim_state == "AMBIGUOUS":
            return self._error(
                502,
                "UNKNOWN_OUTCOME",
                "A prior attempt for this request_id dispatched with an unknown provider "
                "outcome; automatic retry is forbidden.",
                ambiguous_outcome=True,
            )

        result = self.executor(request_obj)
        response_code: int
        response_body: dict[str, Any]
        ambiguous = False
        if result.receipt is None:
            ambiguous = result.ambiguous_outcome
            response_code, response_body = self._error(
                502 if ambiguous else 503,
                result.status,
                result.error
                or "Trusted bridge executor completed without an authenticated public receipt.",
                ambiguous_outcome=ambiguous,
                # The executor may have already invoked chargeable provider work
                # before failing, so consumption may be unknown.
                provider_dispatched=True,
            )
            response_body.update(
                {
                    "observed_cost_usd": result.observed_cost_usd,
                    "reserved_exposure_usd": result.reserved_exposure_usd,
                    "approved_estimate_usd": result.approved_estimate_usd,
                    "cost_provenance": result.cost_provenance,
                    "tokens_used": result.tokens_used,
                    "model_call_count": result.model_call_count,
                    "model_prompt_tokens": result.model_prompt_tokens,
                    "model_completion_tokens": result.model_completion_tokens,
                    "model_usage_complete": result.model_usage_complete,
                    "provider_request_id": result.provider_request_id,
                    "provider_request_ids": list(result.provider_request_ids),
                    "candidate_origin": result.candidate_origin,
                    "candidate_patch_digest": result.candidate_patch_digest,
                    "provider_operation_ids": list(result.provider_operation_ids),
                }
            )
        else:
            integrity_error: str | None = None
            try:
                verify_public_receipt_integrity(result.receipt)
            except Exception as exc:
                integrity_error = f"Bridge receipt integrity verification failed: {exc}"
            if integrity_error is not None:
                response_code, response_body = self._error(
                    502, "FAILED", integrity_error, provider_dispatched=True
                )
                response_body.update(
                    {
                        "tokens_used": result.tokens_used,
                        "model_prompt_tokens": result.model_prompt_tokens,
                        "model_completion_tokens": result.model_completion_tokens,
                    }
                )
            elif result.receipt.provenance != EvidenceProvenance.LIVE_NEBIUS:
                response_code, response_body = self._error(
                    502,
                    "FAILED",
                    "Bridge executor returned a non-LIVE_NEBIUS receipt for a live request.",
                    provider_dispatched=True,
                )
                response_body.update(
                    {
                        "tokens_used": result.tokens_used,
                        "model_prompt_tokens": result.model_prompt_tokens,
                        "model_completion_tokens": result.model_completion_tokens,
                    }
                )
            elif self.execution_authority_verifier is None:
                response_code, response_body = self._error(
                    503,
                    "NOT_READY_FOR_DEPLOYMENT",
                    "Independent live execution authority is not configured. Trusted bridge "
                    "cannot certify executor-reported LIVE_NEBIUS receipts; run remains NOT_RUN.",
                    provider_dispatched=True,
                )
                response_body.update(
                    {
                        "tokens_used": result.tokens_used,
                        "model_prompt_tokens": result.model_prompt_tokens,
                        "model_completion_tokens": result.model_completion_tokens,
                    }
                )
            else:
                try:
                    authority_verified, authority_error = self.execution_authority_verifier(
                        request_obj, result
                    )
                except Exception as exc:
                    authority_verified, authority_error = (
                        False,
                        (f"Independent live execution authority check failed: {exc}"),
                    )
                if not authority_verified:
                    response_code, response_body = self._error(
                        502,
                        "FAILED",
                        authority_error
                        or "Independent live execution authority rejected the executor-reported "
                        "receipt.",
                        provider_dispatched=True,
                    )
                    response_body.update(
                        {
                            "tokens_used": result.tokens_used,
                            "model_prompt_tokens": result.model_prompt_tokens,
                            "model_completion_tokens": result.model_completion_tokens,
                        }
                    )
                else:
                    proof = create_receipt_proof(
                        result.receipt,
                        signer=self.signer,
                        issuer_id="basebreak:verifier:nebius:worker",
                    )
                    response_code = 201
                    response_body = {
                        "ok": True,
                        "status": "COMPLETED",
                        "receipt": result.receipt.to_dict(),
                        "receipt_proof": proof,
                        "observed_cost_usd": result.observed_cost_usd,
                        "reserved_exposure_usd": result.reserved_exposure_usd,
                        "approved_estimate_usd": result.approved_estimate_usd,
                        "cost_provenance": result.cost_provenance,
                        "tokens_used": result.tokens_used,
                        "provider_request_id": result.provider_request_id,
                        "provider_request_ids": list(result.provider_request_ids),
                        "provider_operation_ids": list(result.provider_operation_ids),
                        "candidate_origin": result.candidate_origin,
                        "provider_dispatched": True,
                    }
                    if result.diagnostic_record is not None:
                        response_body["diagnostic_categories"] = {
                            wd.world: wd.diagnostic_category.value
                            for wd in result.diagnostic_record.world_diagnostics
                        }

        # Persist the terminal outcome so replaying this request_id never triggers
        # a second chargeable execution.
        try:
            if ambiguous:
                self.idempotency_store.mark_ambiguous(request_obj.request_id)
            else:
                self.idempotency_store.complete(request_obj.request_id, response_body)
        except DurableIdempotencyUnavailableError as exc:
            return self._error(
                502,
                "UNKNOWN_OUTCOME",
                f"Provider work may have occurred but durable single-execution protection "
                f"could not be persisted: {exc}",
                ambiguous_outcome=True,
                provider_dispatched=True,
            )
        return response_code, response_body


def create_trusted_verifier_bridge_from_env() -> TrustedVerifierBridge:
    """Create a fully wired trusted verifier bridge from environment configuration."""
    config = TrustedBridgeConfig.from_env()
    signer = _PrivilegedVerifierSigner.from_environment()
    return TrustedVerifierBridge(
        config=config,
        executor=create_live_nebius_bridge_executor(config=config, signer=signer),
        signer=signer,
        execution_authority_verifier=create_live_nebius_execution_authority_verifier(),
    )


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
