"""Genuine model-generated candidate production for the trusted verifier bridge (P-27.06).

Turns a real Nebius/NVIDIA model response into a bound candidate proposal that the
trusted verifier can verify, reusing the existing Builder proposal contracts and
candidate capture helpers.

This module never falls back to the deterministic fixture patch: malformed, empty,
unauthorized, or non-mutating proposals fail closed (``ModelCandidateRejectedError``).
The generation prompt exposes only the authorized task/contract context and the
allowlisted base source file content; it never includes sealed verifier witness
material or expected hidden answers.
"""

from __future__ import annotations

import hashlib
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
    """Base error for genuine candidate production."""


class ModelCandidateRejectedError(ModelCandidateError):
    """A model proposal was missing, malformed, unauthorized, or non-mutating."""


class ModelCandidateIdentityMismatchError(ModelCandidateError):
    """A generated candidate did not match its bound identity."""


@dataclass(frozen=True, slots=True)
class ModelCandidate:
    """A genuine, bound candidate produced from a model response."""

    origin: str
    response_text: str
    proposal: BuilderProposal
    candidate_files: tuple[tuple[str, str], ...]
    patch_text: str
    patch_digest: str
    candidate_id: str

    def files_mapping(self) -> dict[str, str]:
        return dict(self.candidate_files)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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
    result = model_client.complete(messages, max_tokens=max_tokens, temperature=temperature)
    response_text = getattr(result, "content", None)
    if not isinstance(response_text, str) or not response_text.strip():
        raise ModelCandidateRejectedError("model returned an empty candidate response")

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

    patch_digest = _sha256_hex(patch_text)
    return ModelCandidate(
        origin=MODEL_GENERATED_CANDIDATE_ORIGIN,
        response_text=response_text,
        proposal=proposal,
        candidate_files=tuple(sorted(candidate_files.items())),
        patch_text=patch_text,
        patch_digest=patch_digest,
        candidate_id=f"cand-model-{patch_digest[:16]}",
    )


def assert_candidate_identity(
    candidate: ModelCandidate, *, patch_digest: str, patch_text: str
) -> None:
    """Fail closed if a candidate's bound identity does not match its content."""
    if candidate.patch_digest != patch_digest or _sha256_hex(patch_text) != patch_digest:
        raise ModelCandidateIdentityMismatchError(
            "candidate patch identity does not match the bound digest"
        )
