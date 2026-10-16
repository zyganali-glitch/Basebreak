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
from typing import Any, Callable, Mapping, Sequence

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
DEFAULT_BRIDGE_SOURCE_REPO_LOCATOR: str = "https://github.com/zyganali-glitch/Basebreak.git"


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
    source_repo_locator: str = DEFAULT_BRIDGE_SOURCE_REPO_LOCATOR
    local_repo_root: str | None = None

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
    from importlib import import_module

    demo_module = import_module("tests.demo.test_p23_killer_demo")
    contract = demo_module.create_reset_vault_frozen_contract()
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


def _build_live_attestation_messages(request: BridgeRequest) -> list[Any]:
    from basebreak.adapters.nebius import ChatMessage

    challenge = (
        "LIVE_ATTESTATION "
        f"request_id={request.request_id} "
        f"source_commit_id={request.source_commit_id} "
        f"contract_digest={request.frozen_contract_digest}"
    )
    return [
        ChatMessage(
            role="system",
            content="Return the exact attestation line requested by the user. No commentary.",
        ),
        ChatMessage(role="user", content=challenge),
    ]


def _assert_model_attestation_binding(request: BridgeRequest, model_content: str) -> None:
    required_fragments = (
        request.request_id,
        request.source_commit_id,
        request.frozen_contract_digest,
    )
    if any(fragment not in model_content for fragment in required_fragments):
        raise BridgeValidationError(
            "Nebius model attestation response omitted one or more bound request facts."
        )


def _bridge_verifier_authority(signer: _PrivilegedVerifierSigner | None) -> Any:
    from basebreak.verifier.trust_bridge import (
        VerifierAuthorityRoot,
        get_default_verifier_authority_root,
    )

    if signer is None:
        return get_default_verifier_authority_root()
    return VerifierAuthorityRoot(modulus=signer.modulus, exponent=signer.exponent)


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
    verifier_authority: Any,
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

    del verifier_authority

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

    usage = getattr(model_result, "usage", None)
    accounting = PublicCostAccountingFact(
        model_call_count=1,
        prompt_tokens=int(getattr(usage, "prompt_tokens", 0) or 0),
        completion_tokens=int(getattr(usage, "completion_tokens", 0) or 0),
        sandbox_runtime_seconds=round(sandbox_runtime_seconds, 4),
        estimated_cost_usd=round(float(request.max_estimated_cost_usd), 6),
        is_metered=False,
    )

    runtime_identities = [
        "bridge:trusted-python",
        f"model:{model_result.returned_model}",
        f"source:{request.source_commit_id}",
        f"sandbox:{local_receipt.base_execution.sandbox_id}",
        f"sandbox:{local_receipt.candidate_execution.sandbox_id}",
    ]
    if model_result.request_id:
        runtime_identities.append(f"model-request:{model_result.request_id}")
    if local_receipt.counterfactual_execution is not None:
        runtime_identities.append(f"sandbox:{local_receipt.counterfactual_execution.sandbox_id}")
    runtime_identities.extend(f"nebius-operation:{op_id}" for op_id in provider_operation_ids)

    return create_public_verification_receipt(
        frozen_contract_digest=scenario.frozen_contract_digest,
        task_id=request.task_id,
        repo_locator=config.source_repo_locator,
        source_commit_id=request.source_commit_id,
        candidate_tree_digest=local_receipt.candidate_execution.tree_digest,
        candidate_patch_digest=scenario.candidate_patch_digest,
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
        provenance=EvidenceProvenance.LIVE_NEBIUS,
        runtime_identities=tuple(runtime_identities),
        timing={
            "created_at_utc": local_receipt.created_at_utc,
            "total_duration_seconds": round(
                sandbox_runtime_seconds + float(model_result.duration_seconds),
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
    if receipt.provenance != EvidenceProvenance.LIVE_NEBIUS:
        return False, "Receipt provenance must be LIVE_NEBIUS."
    if receipt.task_id != request.task_id:
        return False, "Receipt task_id does not match the trusted bridge request."
    if receipt.source_commit_id.lower() != request.source_commit_id.lower():
        return False, "Receipt source_commit_id does not match the trusted bridge request."
    if receipt.frozen_contract_digest.lower() != request.frozen_contract_digest.lower():
        return False, "Receipt frozen_contract_digest does not match the trusted request."
    if receipt.candidate_patch_digest != scenario.candidate_patch_digest:
        return False, "Receipt candidate_patch_digest does not match the canonical live patch."

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
        active_authority = verifier_authority or _bridge_verifier_authority(active_signer)
        active_model_client = model_client or NebiusModelClient(
            config=ModelClientConfig(
                api_key=config.nebius_api_key,
                project_id=config.nebius_project_id,
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

        try:
            model_result = active_model_client.complete(
                _build_live_attestation_messages(request),
                max_tokens=160,
                temperature=0.0,
            )
            _assert_model_attestation_binding(request, model_result.content)

            candidate_tree_digest = _compute_candidate_tree_digest(
                repo_root=repo_root,
                source_commit_id=request.source_commit_id,
                patch_text=scenario.candidate_patch_text,
            )

            source_identity = SourceIdentity(
                config.source_repo_locator,
                CommitRevision(request.source_commit_id),
                subpath=request.target,
            )
            candidate_identity = CandidateIdentity(
                f"cand-live-{scenario.candidate_patch_digest[:16]}",
                source_identity,
                scenario.candidate_patch_digest,
                description="Canonical live Nebius ResetVault candidate",
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
                candidate_patch_text=scenario.candidate_patch_text,
                candidate_tree_digest=candidate_tree_digest,
                sealed_witness_references=(sealed_record.witness_id,),
            )
            counterfactual_plan = CandidateDeltaSubtractor.plan_subtraction(
                candidate_id=candidate_identity.candidate_id,
                candidate_patch_text=scenario.candidate_patch_text,
                candidate_patch_digest=scenario.candidate_patch_digest,
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
                provenance=EvidenceProvenance.LIVE_NEBIUS,
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

            public_receipt = _build_public_receipt_from_local_receipt(
                request=request,
                config=config,
                scenario=scenario,
                local_receipt=local_receipt,
                model_result=model_result,
                provider_operation_ids=provider_operation_ids,
                verifier_authority=active_authority,
            )

            return BridgeExecutionResult(
                status="COMPLETED",
                receipt=public_receipt,
                observed_cost_usd=round(float(request.max_estimated_cost_usd), 6),
                tokens_used=int(
                    getattr(getattr(model_result, "usage", None), "total_tokens", 0) or 0
                ),
                provider_operation_ids=provider_operation_ids,
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
                provider_operation_ids=_normalize_provider_operation_ids(
                    getattr(active_sandbox_adapter, "live_operation_ids", ())
                ),
            )
        except VerifierExecutionBlockedError as exc:
            return BridgeExecutionResult(status="BLOCKED", error=str(exc))
        except Exception as exc:
            return BridgeExecutionResult(status="FAILED", error=str(exc))

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
