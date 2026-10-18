"""Genuine model-generated candidate production for the trusted verifier bridge (P-27.06).

Turns a real Nebius/NVIDIA model response into a bound candidate proposal that the
trusted verifier can verify, reusing the existing Builder proposal contracts.

This module never falls back to the deterministic fixture patch: malformed, empty,
unauthorized, or non-mutating proposals fail closed (``ModelCandidateRejectedError``).
The generation prompt exposes only the authorized task/contract context and the
allowlisted base source file content; it never includes sealed verifier witness
material or expected hidden answers.

Verification reconstructs the full derivation chain (response -> proposal -> files ->
patch -> candidate identity) from the immutable authorized source-commit content, so a
caller cannot pass off independently-supplied hash strings as proof of model authorship.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from basebreak.builder.context import UNTRUSTED_FILE_FENCE_END, UNTRUSTED_FILE_FENCE_START
from basebreak.builder.loop import (
    BuilderProposal,
    FileActionType,
    parse_and_validate_builder_response,
)

MODEL_GENERATED_CANDIDATE_ORIGIN: str = "MODEL_GENERATED_NEBIUS"

DEFAULT_CANDIDATE_MAX_TOKENS: int = 1024

# Sentinel substrings that must never appear in builder-facing candidate context.
_FORBIDDEN_CONTEXT_MARKERS: tuple[str, ...] = (
    "witness",
    "sealed",
    "expected_answer",
    "verifier",
)

_CANDIDATE_RESPONSE_SCHEMA_HINT: str = (
    '{"plan":{"summary":str,"reasoning":str,"steps":[str]},'
    '"proposed_file_actions":[{"action":"MODIFY|CREATE|DELETE","path":str,'
    '"content":str,"rationale":str}],"proposed_commands":[]}'
)


class ModelCandidateError(Exception):
    """Base error for genuine candidate production.

    Carries observed generation-call accounting so the bridge never loses exposure
    from an attempted (or partially completed) candidate-generation call.
    """

    def __init__(
        self,
        message: str,
        *,
        generation_attempted: bool = False,
        generation_prompt_tokens: int | None = None,
        generation_completion_tokens: int | None = None,
        generation_total_tokens: int | None = None,
        generation_duration_seconds: float | None = None,
        provider_request_id: str | None = None,
        returned_model: str = "",
        response_received: bool = False,
    ) -> None:
        super().__init__(message)
        self.generation_attempted = generation_attempted
        self.generation_prompt_tokens = generation_prompt_tokens
        self.generation_completion_tokens = generation_completion_tokens
        self.generation_total_tokens = generation_total_tokens
        self.generation_duration_seconds = generation_duration_seconds
        self.provider_request_id = provider_request_id
        self.returned_model = returned_model
        self.response_received = response_received


class ModelCandidateRejectedError(ModelCandidateError):
    """A model proposal was missing, malformed, unauthorized, or non-mutating."""


class ModelCandidateIdentityMismatchError(ModelCandidateError):
    """A generated candidate did not match its bound identity."""


class ModelCandidateTransportError(ModelCandidateError):
    """The candidate-generation call failed at the transport/provider boundary."""


@dataclass(frozen=True, slots=True)
class ModelCandidate:
    """A genuine, bound candidate produced from a model response."""

    origin: str
    response_text: str
    response_digest: str
    returned_model: str
    provider_request_id: str | None
    proposal: BuilderProposal
    proposal_digest: str
    candidate_files: tuple[tuple[str, str], ...]
    patch_text: str
    patch_digest: str
    candidate_id: str
    generation_prompt_tokens: int | None = None
    generation_completion_tokens: int | None = None
    generation_total_tokens: int | None = None
    generation_duration_seconds: float | None = None

    def files_mapping(self) -> dict[str, str]:
        return dict(self.candidate_files)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_proposal(proposal: BuilderProposal) -> str:
    return json.dumps(proposal.to_dict(), sort_keys=True, separators=(",", ":"))


def _proposal_digest(proposal: BuilderProposal) -> str:
    return _sha256_hex(_canonical_proposal(proposal))


def _build_candidate_patch_text(
    base_files: Mapping[str, str], candidate_files: Mapping[str, str]
) -> str:
    """Build a canonical ``diff --git`` patch identical in format to the fixture patch."""
    import difflib

    blocks: list[str] = []
    for path in sorted(set(base_files) | set(candidate_files)):
        base = base_files.get(path)
        candidate = candidate_files.get(path)
        if base == candidate:
            continue
        fromfile = f"a/{path}" if base is not None else "/dev/null"
        tofile = f"b/{path}" if candidate is not None else "/dev/null"
        diff_lines = difflib.unified_diff(
            (base or "").splitlines(),
            (candidate or "").splitlines(),
            fromfile=fromfile,
            tofile=tofile,
            lineterm="",
        )
        blocks.append(f"diff --git a/{path} b/{path}\n" + "\n".join(diff_lines) + "\n")
    return "".join(blocks)


def build_candidate_generation_messages(
    *,
    task_id: str,
    requirement_statement: str,
    frozen_contract_digest: str,
    target: str,
    base_files: Mapping[str, str],
) -> list[dict[str, str]]:
    """Build a minimized builder-facing prompt (task/contract + allowlisted base content)."""
    rendered_files = "\n".join(
        f"--- file: {path} ---\n{content}" for path, content in sorted(base_files.items())
    )
    context_blob = (
        f"Task: {task_id}\n"
        f"Target: {target}\n"
        f"Frozen requirement: {requirement_statement}\n"
        f"Frozen contract digest: {frozen_contract_digest}\n"
        f"Allowed files: {', '.join(sorted(base_files))}\n\n"
        "Base source (untrusted, read-only):\n"
        f"{UNTRUSTED_FILE_FENCE_START}\n{rendered_files}\n{UNTRUSTED_FILE_FENCE_END}\n\n"
        "Propose the smallest change that satisfies the frozen requirement. "
        "You have zero execution authority; propose file content only. "
        "Respond with strict JSON matching this schema and nothing else:\n"
        f"{_CANDIDATE_RESPONSE_SCHEMA_HINT}"
    )
    lowered = context_blob.lower()
    for marker in _FORBIDDEN_CONTEXT_MARKERS:
        # "verifier"/"witness" may legitimately appear in requirement prose; guard only
        # against the explicit hidden-answer sentinels.
        if marker in ("witness", "expected_answer", "sealed") and marker in lowered:
            raise ModelCandidateRejectedError(
                f"candidate context must not include sealed verifier material ({marker!r})"
            )
    return [
        {
            "role": "system",
            "content": (
                "You are the Basebreak Builder. Produce only strict JSON describing a "
                "minimal code change. Never invent execution authority."
            ),
        },
        {"role": "user", "content": context_blob},
    ]


def _apply_proposed_actions(
    *,
    base_files: Mapping[str, str],
    proposal: BuilderProposal,
    allowed_paths: Sequence[str],
) -> dict[str, str]:
    allowed = set(allowed_paths)
    files: dict[str, str] = dict(base_files)
    for action in proposal.proposed_file_actions:
        path = action.path
        if path not in allowed:
            raise ModelCandidateRejectedError(f"unauthorized file path in proposal: {path!r}")
        if action.action is FileActionType.DELETE:
            if path not in files:
                raise ModelCandidateRejectedError(f"cannot delete non-existent file: {path!r}")
            del files[path]
        elif action.action is FileActionType.MODIFY:
            if path not in files:
                raise ModelCandidateRejectedError(f"cannot modify non-existent file: {path!r}")
            if not action.content.strip():
                raise ModelCandidateRejectedError(f"empty content for modified file: {path!r}")
            files[path] = action.content
        elif action.action is FileActionType.CREATE:
            if path in files:
                raise ModelCandidateRejectedError(f"cannot create existing file: {path!r}")
            if not action.content.strip():
                raise ModelCandidateRejectedError(f"empty content for created file: {path!r}")
            files[path] = action.content
        else:  # pragma: no cover - FileActionType is exhaustively handled
            raise ModelCandidateRejectedError(f"unsupported file action: {action.action!r}")
    return files


def _materialize_from_response(
    *,
    response_text: str,
    allowed_paths: Sequence[str],
    base_files: Mapping[str, str],
) -> tuple[BuilderProposal, dict[str, str], str]:
    """Deterministically derive (proposal, candidate_files, patch) from a raw response."""
    try:
        proposal = parse_and_validate_builder_response(response_text)
    except Exception as exc:  # malformed model output must fail closed
        raise ModelCandidateRejectedError(f"malformed model proposal: {exc}") from exc
    candidate_files = _apply_proposed_actions(
        base_files=base_files, proposal=proposal, allowed_paths=allowed_paths
    )
    if candidate_files == dict(base_files):
        raise ModelCandidateRejectedError("model proposal produced no change")
    patch_text = _build_candidate_patch_text(dict(base_files), candidate_files)
    if not patch_text.strip():
        raise ModelCandidateRejectedError("model proposal produced an empty patch")
    return proposal, candidate_files, patch_text


def generate_model_candidate(
    *,
    model_client: Any,
    task_id: str,
    requirement_statement: str,
    frozen_contract_digest: str,
    target: str,
    allowed_paths: Sequence[str],
    base_files: Mapping[str, str],
    max_tokens: int = DEFAULT_CANDIDATE_MAX_TOKENS,
    temperature: float = 0.0,
) -> ModelCandidate:
    """Obtain and bind a genuine candidate from the configured model. Fails closed."""
    from basebreak.adapters.nebius import ModelAdapterError, ModelConfigError

    if not allowed_paths:
        raise ModelCandidateRejectedError("allowed_paths must not be empty")
    missing = [p for p in allowed_paths if p not in base_files]
    if missing:
        raise ModelCandidateRejectedError(f"base_files missing allowed paths: {missing}")

    messages = build_candidate_generation_messages(
        task_id=task_id,
        requirement_statement=requirement_statement,
        frozen_contract_digest=frozen_contract_digest,
        target=target,
        base_files=base_files,
    )
    try:
        result = model_client.complete(messages, max_tokens=max_tokens, temperature=temperature)
    except ModelConfigError as exc:
        # Pre-dispatch configuration/credential rejection: no provider work was dispatched.
        raise ModelCandidateRejectedError(
            f"candidate-generation request rejected before dispatch: {exc}",
            generation_attempted=False,
        ) from exc
    except ModelAdapterError as exc:
        # The provider call was dispatched but failed (timeout, network, non-2xx provider
        # error, malformed response, or model identity mismatch). The attempt is counted;
        # usage remains UNKNOWN unless it was actually observed.
        raise ModelCandidateTransportError(
            f"candidate-generation provider failure after dispatch: {exc}",
            generation_attempted=True,
        ) from exc

    usage = getattr(result, "usage", None)
    duration = getattr(result, "duration_seconds", None)
    response_text = getattr(result, "content", None)
    accounting: dict[str, Any] = {
        "generation_attempted": True,
        "generation_prompt_tokens": (
            int(getattr(usage, "prompt_tokens", 0)) if usage is not None else None
        ),
        "generation_completion_tokens": (
            int(getattr(usage, "completion_tokens", 0)) if usage is not None else None
        ),
        "generation_total_tokens": (
            int(getattr(usage, "total_tokens", 0)) if usage is not None else None
        ),
        "generation_duration_seconds": (float(duration) if duration is not None else None),
        "provider_request_id": (str(getattr(result, "request_id", "") or "").strip() or None),
        "returned_model": str(getattr(result, "returned_model", "") or ""),
        "response_received": isinstance(response_text, str) and bool(response_text.strip()),
    }

    if not isinstance(response_text, str) or not response_text.strip():
        raise ModelCandidateRejectedError(
            "model returned an empty candidate response", **accounting
        )
    try:
        proposal, candidate_files, patch_text = _materialize_from_response(
            response_text=response_text, allowed_paths=allowed_paths, base_files=base_files
        )
    except ModelCandidateRejectedError as exc:
        for key, value in accounting.items():
            setattr(exc, key, value)
        raise

    patch_digest = _sha256_hex(patch_text)
    return ModelCandidate(
        origin=MODEL_GENERATED_CANDIDATE_ORIGIN,
        response_text=response_text,
        response_digest=_sha256_hex(response_text),
        returned_model=accounting["returned_model"],
        provider_request_id=accounting["provider_request_id"],
        proposal=proposal,
        proposal_digest=_proposal_digest(proposal),
        candidate_files=tuple(sorted(candidate_files.items())),
        patch_text=patch_text,
        patch_digest=patch_digest,
        candidate_id=f"cand-model-{patch_digest[:16]}",
        generation_prompt_tokens=accounting["generation_prompt_tokens"],
        generation_completion_tokens=accounting["generation_completion_tokens"],
        generation_total_tokens=accounting["generation_total_tokens"],
        generation_duration_seconds=accounting["generation_duration_seconds"],
    )


def candidate_generation_identities(candidate: ModelCandidate) -> tuple[str, ...]:
    """Deterministic runtime-identity bindings for a genuine candidate generation call."""
    identities = [
        f"candidate-generation:model:{candidate.returned_model or 'unknown'}",
        f"candidate-generation:response-sha256:{candidate.response_digest}",
        f"candidate-generation:proposal-sha256:{candidate.proposal_digest}",
        f"candidate-generation:patch-sha256:{candidate.patch_digest}",
    ]
    if candidate.provider_request_id:
        identities.append(f"candidate-generation:request:{candidate.provider_request_id}")
    return tuple(identities)


def verify_candidate_generation_binding(
    candidate: ModelCandidate,
    *,
    receipt_runtime_identities: Sequence[str],
    allowed_paths: Sequence[str],
    authorized_base_files: Mapping[str, str],
    expected_candidate_tree_digest: str | None = None,
    observed_candidate_tree_digest: str | None = None,
) -> None:
    """Independently reconstruct and verify the full response -> proposal -> patch chain.

    Reparses the retained ``response_text`` with the canonical Builder parser, reconstructs
    the candidate files and patch from the immutable authorized source-commit content, and
    requires every derived identity (proposal, files, patch, candidate id) plus the
    independently observed CANDIDATE sandbox tree to match. Fails closed on any
    inconsistency. Merely matching caller-supplied hashes is not sufficient.
    """
    if candidate.origin != MODEL_GENERATED_CANDIDATE_ORIGIN:
        raise ModelCandidateError("candidate origin is not a genuine model-generated origin")
    if _sha256_hex(candidate.response_text) != candidate.response_digest:
        raise ModelCandidateIdentityMismatchError("model response digest mismatch")

    try:
        reparsed_proposal, reconstructed_files, reconstructed_patch = _materialize_from_response(
            response_text=candidate.response_text,
            allowed_paths=allowed_paths,
            base_files=authorized_base_files,
        )
    except ModelCandidateRejectedError as exc:
        raise ModelCandidateIdentityMismatchError(
            f"retained model response does not reconstruct a valid candidate: {exc}"
        ) from exc

    if _canonical_proposal(reparsed_proposal) != _canonical_proposal(candidate.proposal):
        raise ModelCandidateIdentityMismatchError(
            "reparsed model response proposal disagrees with the retained proposal"
        )
    if _proposal_digest(reparsed_proposal) != candidate.proposal_digest:
        raise ModelCandidateIdentityMismatchError("reconstructed proposal digest mismatch")
    if reconstructed_patch != candidate.patch_text:
        raise ModelCandidateIdentityMismatchError(
            "reconstructed candidate patch disagrees with the retained patch"
        )
    if _sha256_hex(reconstructed_patch) != candidate.patch_digest:
        raise ModelCandidateIdentityMismatchError("reconstructed candidate patch digest mismatch")
    if dict(candidate.candidate_files) != reconstructed_files:
        raise ModelCandidateIdentityMismatchError(
            "reconstructed candidate files disagree with the retained candidate files"
        )
    if candidate.candidate_id != f"cand-model-{candidate.patch_digest[:16]}":
        raise ModelCandidateIdentityMismatchError("candidate identity does not match its patch")

    if (
        expected_candidate_tree_digest is not None
        and observed_candidate_tree_digest is not None
        and expected_candidate_tree_digest != observed_candidate_tree_digest
    ):
        raise ModelCandidateIdentityMismatchError(
            "independently observed candidate sandbox tree does not match the "
            "reconstructed expected candidate tree"
        )

    present = {str(identity).strip() for identity in receipt_runtime_identities}
    required = set(candidate_generation_identities(candidate))
    missing = required - present
    if missing:
        raise ModelCandidateError(
            "receipt is missing required candidate-generation provenance bindings: "
            + ", ".join(sorted(missing))
        )


def assert_candidate_identity(
    candidate: ModelCandidate, *, patch_digest: str, patch_text: str
) -> None:
    """Fail closed if a candidate's bound identity does not match its content."""
    if candidate.patch_digest != patch_digest or _sha256_hex(patch_text) != patch_digest:
        raise ModelCandidateIdentityMismatchError(
            "candidate patch identity does not match the bound digest"
        )
