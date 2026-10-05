"""Nemotron witness-plan generation and deterministic validation contracts.

P-09.01: Implement Nemotron witness-plan generation from frozen contract + trusted source.
P-09.02: Validate witness plans against scope/security/runtime policy.

Core Invariants:
1. Zero Builder authority: Input originates strictly from trusted VerifierContextEnvelope
   and trusted repository source. No Builder proposals, reasoning, workspaces, or claims.
2. Exact binding: Witness plan carries and binds to exact frozen contract digest,
   requirement ID, source commit SHA, and verifier context.
3. Structured output & bounded execution: JSON extraction fails closed; model output
   is strictly a proposal (is_authoritative=False, grants_pass=False).
4. Deterministic validation: Validator enforces BUG_FIX scope, bounded execution,
   path normalization, protected-surface enforcement, secret absence, and command safety.
5. Provider neutrality: Model invocation through canonical bounded client; zero broad
   TypeError trial-and-error retry loops.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from basebreak.domain.semantics import ChangeClass
from basebreak.security.protected_surfaces import (
    PathSecurityError,
    PathTraversalError,
    ProtectedSurfaceManifest,
    get_canonical_basebreak_protected_manifest,
    is_path_protected,
    normalize_repo_path,
)
from basebreak.security.secret_policy import contains_secret
from basebreak.verifier.boundary import VERIFIER_DIRECTORY_PREFIXES
from basebreak.verifier.context import (
    AUTHORITY_SMUGGLING_KEYS,
    FORBIDDEN_BUILDER_KEYS,
    VerifierContextEnvelope,
)

_HEX_40_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SAFE_COMMAND_TOKEN = re.compile(r"^[a-zA-Z0-9_\-\.\:\/\\=\+@]+$")
_FORBIDDEN_SHELL_CHARS = frozenset({"|", "&", ";", ">", "<", "`", "$", "(", ")", "{", "}"})

ALLOWED_TEST_EXECUTABLES = frozenset(
    {"python", "python3", "pytest", "uv", "pytest.exe", "python.exe"}
)

VERIFIER_WITNESS_PLAN_SYSTEM_INSTRUCTIONS: str = (
    "You are the Basebreak Witness Generator.\n"
    "Your mandate is to design an independent behavioral test witness for a BUG_FIX requirement.\n"
    "RULES:\n"
    "1. The witness test must test the required behavior: fail on base, pass on candidate.\n"
    "2. The witness must contain meaningful pytest test functions with real assertions.\n"
    "3. No network, no credentials, no destructive actions.\n"
    "4. You MUST preserve the exact 'requirement_id', 'frozen_contract_digest', and\n"
    "   'source_commit_id' values provided in the prompt. Do not rename or translate them.\n"
    "5. Return ONLY a single valid JSON object. Do NOT output thinking, commentary, or markdown.\n"
)


# --- Exceptions ---


class WitnessPlanError(Exception):
    """Base exception for all witness plan errors."""


class MalformedWitnessPlanError(WitnessPlanError):
    """Raised when model output is missing required fields or cannot be parsed."""


class WitnessPlanScopeError(WitnessPlanError):
    """Raised when witness plan exceeds allowed scope (e.g. non-BUG_FIX)."""


class WitnessPlanSecurityError(WitnessPlanError):
    """Raised when witness plan violates path, protected-surface, or secret security rules."""


class WitnessPlanAuthoritySmugglingError(WitnessPlanError):
    """Raised when witness plan attempts to smuggle self-certification or authority."""


class WitnessPlanBindingMismatchError(WitnessPlanError):
    """Raised when witness plan identifiers do not match context envelope."""


# --- Data Records ---


@dataclass(frozen=True, slots=True)
class ProposedWitnessArtifact:
    """A proposed test file belonging to a witness plan proposal."""

    path: str
    content: str
    rationale: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path.strip():
            raise MalformedWitnessPlanError(
                "ProposedWitnessArtifact path must be a non-empty string"
            )
        if not isinstance(self.content, str):
            raise TypeError("ProposedWitnessArtifact content must be a string")
        if not isinstance(self.rationale, str):
            raise TypeError("ProposedWitnessArtifact rationale must be a string")

    def to_dict(self) -> dict[str, Any]:
        return {
            "content": self.content,
            "path": self.path,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ProposedWitnessArtifact:
        if not isinstance(data, Mapping):
            raise TypeError(f"Expected mapping, got {type(data).__name__}")
        return cls(
            path=str(data.get("path", "")),
            content=str(data.get("content", "")),
            rationale=str(data.get("rationale", "")),
        )


@dataclass(frozen=True, slots=True)
class WitnessPlanProposal:
    """Model-proposed behavioral witness test plan. Advisory only."""

    witness_id: str
    requirement_id: str
    frozen_contract_digest: str
    source_commit_id: str
    change_class: ChangeClass
    plan_summary: str
    target_files: tuple[str, ...]
    artifacts: tuple[ProposedWitnessArtifact, ...]
    execution_command: tuple[str, ...]
    expected_failure_at_base: str
    expected_success_at_candidate: str
    is_authoritative: bool = False
    grants_pass: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.witness_id, str) or not self.witness_id.strip():
            raise MalformedWitnessPlanError("witness_id must be a non-empty string")
        if not isinstance(self.requirement_id, str) or not self.requirement_id.strip():
            raise MalformedWitnessPlanError("requirement_id must be a non-empty string")
        if not isinstance(self.frozen_contract_digest, str) or not _HEX_64_PATTERN.match(
            self.frozen_contract_digest
        ):
            raise MalformedWitnessPlanError("frozen_contract_digest must be a 64-char hex string")
        if not isinstance(self.source_commit_id, str) or not _HEX_40_PATTERN.match(
            self.source_commit_id
        ):
            raise MalformedWitnessPlanError("source_commit_id must be a 40-char commit SHA")
        if not isinstance(self.change_class, ChangeClass):
            raise TypeError("change_class must be an instance of ChangeClass")
        if not isinstance(self.plan_summary, str) or not self.plan_summary.strip():
            raise MalformedWitnessPlanError("plan_summary must be a non-empty string")

        if not isinstance(self.target_files, tuple):
            if isinstance(self.target_files, Sequence):
                object.__setattr__(self, "target_files", tuple(str(f) for f in self.target_files))
            else:
                raise TypeError("target_files must be a sequence of strings")

        if not isinstance(self.artifacts, tuple):
            if isinstance(self.artifacts, Sequence):
                object.__setattr__(self, "artifacts", tuple(self.artifacts))
            else:
                raise TypeError("artifacts must be a sequence of ProposedWitnessArtifact")

        if not self.artifacts:
            raise MalformedWitnessPlanError(
                "Witness plan proposal must contain at least one artifact"
            )

        for idx, art in enumerate(self.artifacts):
            if not isinstance(art, ProposedWitnessArtifact):
                art_type = type(art).__name__
                raise TypeError(
                    f"artifact at index {idx} must be ProposedWitnessArtifact, got {art_type}"
                )

        if not isinstance(self.execution_command, tuple):
            if isinstance(self.execution_command, Sequence):
                object.__setattr__(
                    self, "execution_command", tuple(str(c) for c in self.execution_command)
                )
            else:
                raise TypeError("execution_command must be a sequence of strings")

        if not self.execution_command:
            raise MalformedWitnessPlanError("execution_command must not be empty")

        if not isinstance(self.expected_failure_at_base, str):
            raise TypeError("expected_failure_at_base must be a string")
        if not isinstance(self.expected_success_at_candidate, str):
            raise TypeError("expected_success_at_candidate must be a string")

        if self.is_authoritative is not False:
            raise WitnessPlanAuthoritySmugglingError("is_authoritative must be strictly False")
        if self.grants_pass is not False:
            raise WitnessPlanAuthoritySmugglingError("grants_pass must be strictly False")

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifacts": [a.to_dict() for a in self.artifacts],
            "change_class": self.change_class.value,
            "execution_command": list(self.execution_command),
            "expected_failure_at_base": self.expected_failure_at_base,
            "expected_success_at_candidate": self.expected_success_at_candidate,
            "frozen_contract_digest": self.frozen_contract_digest,
            "grants_pass": self.grants_pass,
            "is_authoritative": self.is_authoritative,
            "plan_summary": self.plan_summary,
            "requirement_id": self.requirement_id,
            "source_commit_id": self.source_commit_id,
            "target_files": list(self.target_files),
            "witness_id": self.witness_id,
        }


@dataclass(frozen=True, slots=True)
class ValidatedWitnessArtifact:
    """An individual artifact validated against path, secret, and protected-surface policies."""

    path: str
    content: str
    content_digest: str
    byte_size: int
    rationale: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path:
            raise WitnessPlanSecurityError("path must be a non-empty string")
        if not isinstance(self.content, str):
            raise TypeError("content must be a string")
        if not isinstance(self.content_digest, str) or not _HEX_64_PATTERN.match(
            self.content_digest
        ):
            raise WitnessPlanSecurityError("content_digest must be a 64-char hex string")
        if (
            isinstance(self.byte_size, bool)
            or not isinstance(self.byte_size, int)
            or self.byte_size < 0
        ):
            raise TypeError("byte_size must be a non-negative integer")

    def to_dict(self) -> dict[str, Any]:
        return {
            "byte_size": self.byte_size,
            "content": self.content,
            "content_digest": self.content_digest,
            "path": self.path,
            "rationale": self.rationale,
        }


@dataclass(frozen=True, slots=True)
class ValidatedWitnessPlan:
    """A deterministically validated witness plan ready for executable witness construction."""

    witness_id: str
    requirement_id: str
    frozen_contract_digest: str
    source_commit_id: str
    change_class: ChangeClass
    plan_summary: str
    target_files: tuple[str, ...]
    artifacts: tuple[ValidatedWitnessArtifact, ...]
    execution_command: tuple[str, ...]
    expected_failure_at_base: str
    expected_success_at_candidate: str
    plan_digest: str
    is_authoritative: bool = False
    grants_pass: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.witness_id, str) or not self.witness_id.strip():
            raise WitnessPlanSecurityError("witness_id must be a non-empty string")
        if not isinstance(self.requirement_id, str) or not self.requirement_id.strip():
            raise WitnessPlanSecurityError("requirement_id must be a non-empty string")
        if not isinstance(self.frozen_contract_digest, str) or not _HEX_64_PATTERN.match(
            self.frozen_contract_digest
        ):
            raise WitnessPlanSecurityError("frozen_contract_digest must be a 64-char hex string")
        if not isinstance(self.source_commit_id, str) or not _HEX_40_PATTERN.match(
            self.source_commit_id
        ):
            raise WitnessPlanSecurityError("source_commit_id must be a 40-char commit SHA")
        if not isinstance(self.change_class, ChangeClass):
            raise TypeError("change_class must be ChangeClass")
        if not isinstance(self.plan_digest, str) or not _HEX_64_PATTERN.match(self.plan_digest):
            raise WitnessPlanSecurityError("plan_digest must be a 64-char hex string")

        if not isinstance(self.artifacts, tuple) or not self.artifacts:
            raise WitnessPlanSecurityError("artifacts must be a non-empty tuple")
        for art in self.artifacts:
            if not isinstance(art, ValidatedWitnessArtifact):
                raise TypeError(
                    f"artifact must be ValidatedWitnessArtifact, got {type(art).__name__}"
                )

        if not isinstance(self.execution_command, tuple) or not self.execution_command:
            raise WitnessPlanSecurityError("execution_command must be a non-empty tuple")

        if self.is_authoritative is not False:
            raise WitnessPlanAuthoritySmugglingError("is_authoritative must be strictly False")
        if self.grants_pass is not False:
            raise WitnessPlanAuthoritySmugglingError("grants_pass must be strictly False")

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifacts": [a.to_dict() for a in self.artifacts],
            "change_class": self.change_class.value,
            "execution_command": list(self.execution_command),
            "expected_failure_at_base": self.expected_failure_at_base,
            "expected_success_at_candidate": self.expected_success_at_candidate,
            "frozen_contract_digest": self.frozen_contract_digest,
            "grants_pass": self.grants_pass,
            "is_authoritative": self.is_authoritative,
            "plan_digest": self.plan_digest,
            "plan_summary": self.plan_summary,
            "requirement_id": self.requirement_id,
            "source_commit_id": self.source_commit_id,
            "target_files": list(self.target_files),
            "witness_id": self.witness_id,
        }


# --- Helpers & Extraction ---


def _extract_json_from_model_output(raw_text: str) -> str:
    """Extract JSON string from model response, stripping markdown fences and think tags."""
    trimmed = raw_text.strip()
    trimmed = re.sub(r"<think>.*?</think>", "", trimmed, flags=re.DOTALL).strip()

    # 1. Look for ```json ... ``` or ``` ... ```
    fence_matches = re.findall(r"```(?:json)?\s*\n?(.*?)\n?```", trimmed, re.DOTALL | re.IGNORECASE)
    for block in fence_matches:
        candidate = str(block).strip()
        first_b = candidate.find("{")
        last_b = candidate.rfind("}")
        if first_b != -1 and last_b != -1 and last_b > first_b:
            candidate_json = str(candidate[first_b : last_b + 1]).strip()
            try:
                parsed = json.loads(candidate_json)
                if isinstance(parsed, dict) and "witness_id" in parsed:
                    return candidate_json
            except Exception:
                pass
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict) and "witness_id" in parsed:
                return candidate
        except Exception:
            pass

    # 2. Search for JSON object containing "witness_id" via brace balance
    wid_idx = trimmed.find('"witness_id"')
    if wid_idx != -1:
        brace_start = trimmed.rfind("{", 0, wid_idx)
        if brace_start != -1:
            depth = 0
            in_string = False
            escape = False
            for idx in range(brace_start, len(trimmed)):
                ch = trimmed[idx]
                if escape:
                    escape = False
                    continue
                if ch == "\\" and in_string:
                    escape = True
                    continue
                if ch == '"':
                    in_string = not in_string
                    continue
                if not in_string:
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            candidate = trimmed[brace_start : idx + 1].strip()
                            try:
                                parsed = json.loads(candidate)
                                if isinstance(parsed, dict):
                                    return candidate
                            except Exception:
                                pass
                            break

    # 3. Outermost JSON braces fallback
    first_b = trimmed.find("{")
    last_b = trimmed.rfind("}")
    if first_b != -1 and last_b != -1 and last_b > first_b:
        candidate = str(trimmed[first_b : last_b + 1]).strip()
        try:
            json.loads(candidate)
            return candidate
        except Exception:
            pass
        return candidate

    return trimmed


def parse_witness_plan_proposal(raw_text: str) -> WitnessPlanProposal:
    """Parse raw model response into structured WitnessPlanProposal. Fails closed."""
    if not isinstance(raw_text, str) or not raw_text.strip():
        raise MalformedWitnessPlanError("Model returned empty or non-string response")

    json_str = _extract_json_from_model_output(raw_text)

    try:
        data = json.loads(json_str)
    except Exception as exc:
        raise MalformedWitnessPlanError(
            f"Model response could not be parsed as JSON: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise MalformedWitnessPlanError(
            f"Model response root must be a JSON object, got {type(data).__name__}"
        )

    # Check for forbidden smuggled keys
    for k in AUTHORITY_SMUGGLING_KEYS:
        if k in data and data[k] is True:
            raise WitnessPlanAuthoritySmugglingError(
                f"Smuggled authority key {k!r} detected in model output"
            )

    for k in FORBIDDEN_BUILDER_KEYS:
        if k in data:
            raise WitnessPlanAuthoritySmugglingError(
                f"Forbidden Builder key {k!r} detected in model output"
            )

    raw_change_class = str(data.get("change_class", "")).upper()
    try:
        change_class = ChangeClass(raw_change_class)
    except ValueError as exc:
        raise WitnessPlanScopeError(f"Unsupported change class: {raw_change_class!r}") from exc

    raw_artifacts = data.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise MalformedWitnessPlanError("Witness plan must have non-empty 'artifacts' list")

    parsed_artifacts: list[ProposedWitnessArtifact] = []
    for idx, item in enumerate(raw_artifacts):
        if not isinstance(item, dict):
            raise MalformedWitnessPlanError(f"Artifact at index {idx} must be a dict")
        path = str(item.get("path", "")).strip()
        content = str(item.get("content", ""))
        rationale = str(item.get("rationale", ""))
        if not path:
            raise MalformedWitnessPlanError(f"Artifact at index {idx} has empty path")
        parsed_artifacts.append(
            ProposedWitnessArtifact(path=path, content=content, rationale=rationale)
        )

    raw_cmd = data.get("execution_command")
    if isinstance(raw_cmd, str):
        cmd_tokens = tuple(raw_cmd.split())
    elif isinstance(raw_cmd, list):
        cmd_tokens = tuple(str(c) for c in raw_cmd)
    else:
        raise MalformedWitnessPlanError(
            "execution_command must be a list of strings or command string"
        )

    raw_targets = data.get("target_files", [])
    if isinstance(raw_targets, list):
        targets = tuple(str(t) for t in raw_targets)
    elif isinstance(raw_targets, str):
        targets = (raw_targets,)
    else:
        targets = ()

    return WitnessPlanProposal(
        witness_id=str(data.get("witness_id", "")).strip(),
        requirement_id=str(data.get("requirement_id", "")).strip(),
        frozen_contract_digest=str(data.get("frozen_contract_digest", "")).strip(),
        source_commit_id=str(data.get("source_commit_id", "")).strip(),
        change_class=change_class,
        plan_summary=str(data.get("plan_summary", "")).strip(),
        target_files=targets,
        artifacts=tuple(parsed_artifacts),
        execution_command=cmd_tokens,
        expected_failure_at_base=str(data.get("expected_failure_at_base", "")),
        expected_success_at_candidate=str(data.get("expected_success_at_candidate", "")),
        is_authoritative=False,
        grants_pass=False,
    )


# --- Generation Function (P-09.01) ---


def generate_witness_plan(
    *,
    context_envelope: VerifierContextEnvelope,
    requirement_id: str,
    source_files: Mapping[str, str],
    model_client: Any,
    model_id: str | None = None,
    timeout_seconds: float | None = None,
) -> WitnessPlanProposal:
    """Generate an independent behavioral witness plan using canonical bounded Nemotron client.

    Invariants:
    - Input originates strictly from trusted VerifierContextEnvelope and source_files.
    - Zero Builder authority or proposal leakage.
    - Model client invoked once with bounded parameters.
    - Response strictly parsed into WitnessPlanProposal.
    """
    if not isinstance(context_envelope, VerifierContextEnvelope):
        env_type = type(context_envelope).__name__
        raise TypeError(f"context_envelope must be VerifierContextEnvelope, got {env_type}")

    clean_req_id = str(requirement_id).strip()
    if not clean_req_id:
        raise ValueError("requirement_id must not be empty")

    if not isinstance(source_files, Mapping):
        raise TypeError("source_files must be a mapping of path to content")

    # Verify no Builder data smuggled in source_files
    for key in source_files:
        if any(fk in key.lower() for fk in FORBIDDEN_BUILDER_KEYS):
            raise WitnessPlanAuthoritySmugglingError(
                f"Forbidden Builder data key {key!r} detected in source files"
            )

    # Find requirement in frozen contract if available
    req_statement = ""
    req_citation = ""
    if context_envelope.frozen_contract is not None:
        matched_req = None
        for req in context_envelope.frozen_contract.requirements:
            if req.requirement_id == clean_req_id:
                matched_req = req
                break
        if matched_req is None:
            raise WitnessPlanBindingMismatchError(
                f"Requirement {clean_req_id!r} not found in frozen contract"
            )
        req_statement = matched_req.statement
        req_citation = matched_req.citation

    # Format user prompt
    prompt_sections = [
        "### AUTHORITATIVE VERIFICATION TARGET",
        "Generate an independent behavioral test witness plan for BUG_FIX verification.",
        "Output ONLY a single valid JSON object following this exact structure:",
        "CRITICAL: Do NOT alter requirement_id, frozen_contract_digest, or source_commit_id!",
        "{\n"
        f'  "witness_id": "wit-{clean_req_id.lower()}",\n'
        f'  "requirement_id": "{clean_req_id}",\n'
        f'  "frozen_contract_digest": "{context_envelope.frozen_contract_digest}",\n'
        f'  "source_commit_id": "{context_envelope.source_commit_id}",\n'
        '  "change_class": "BUG_FIX",\n'
        '  "plan_summary": "Concise summary of behavioral test strategy",\n'
        '  "target_files": ["src/cli.py"],\n'
        '  "artifacts": [\n'
        "    {\n"
        '      "path": "tests/test_behavior.py",\n'
        '      "content": "def test_behavior():\\n    ...",\n'
        '      "rationale": "Asserts requirement fails on base and passes on candidate"\n'
        "    }\n"
        "  ],\n"
        '  "execution_command": ["pytest", "tests/test_behavior.py"],\n'
        '  "expected_failure_at_base": "Fails at base",\n'
        '  "expected_success_at_candidate": "Passes at candidate"\n'
        "}",
        f"\nRequirement Statement:\n{req_statement or 'Verify bug fix behavior'}",
    ]
    if req_citation:
        prompt_sections.append(f"Requirement Citation:\n{req_citation}")

    prompt_sections.append("\nTrusted Base Source Files:")
    for path, content in sorted(source_files.items()):
        prompt_sections.append(f"--- File: {path} ---\n{content}\n")

    prompt_sections.append(
        "\nReturn ONLY the JSON object. Do not include markdown fences, thinking, or commentary."
    )
    user_prompt = "\n".join(prompt_sections)

    if model_client is None:
        raise ValueError("model_client must not be None")

    chosen_model = model_id or "nvidia/Nemotron-3_5-Lightning"
    call_timeout = (
        timeout_seconds
        if timeout_seconds is not None
        else float(context_envelope.execution_policy.timeout_seconds)
    )

    # Single bounded invocation to canonical model client
    messages = [
        {"role": "system", "content": VERIFIER_WITNESS_PLAN_SYSTEM_INSTRUCTIONS},
        {"role": "user", "content": user_prompt},
    ]

    import inspect as _inspect

    complete_fn = getattr(model_client, "complete")
    sig = _inspect.signature(complete_fn)
    call_kwargs: dict[str, Any] = {}
    if "model" in sig.parameters:
        call_kwargs["model"] = chosen_model
    if "temperature" in sig.parameters:
        call_kwargs["temperature"] = 0.0
    if "max_tokens" in sig.parameters:
        call_kwargs["max_tokens"] = 4096
    if "timeout_seconds" in sig.parameters:
        call_kwargs["timeout_seconds"] = call_timeout

    param_list = list(sig.parameters.values())
    if (
        param_list
        and param_list[0].kind
        in (
            _inspect.Parameter.POSITIONAL_ONLY,
            _inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        and param_list[0].name == "messages"
    ):
        response = complete_fn(messages, **call_kwargs)
    elif "messages" in sig.parameters:
        call_kwargs["messages"] = messages
        response = complete_fn(**call_kwargs)
    else:
        response = complete_fn(messages)

    raw_content = getattr(response, "content", None)
    if raw_content is None and isinstance(response, dict):
        raw_content = response.get("content") or response.get("text")
    if not isinstance(raw_content, str):
        raise MalformedWitnessPlanError(f"Model response did not return text content: {response!r}")

    proposal = parse_witness_plan_proposal(raw_content)

    # Verify cryptographic binding against context envelope
    if proposal.requirement_id != clean_req_id:
        raise WitnessPlanBindingMismatchError(
            f"Model proposal requirement_id {proposal.requirement_id!r} does not match "
            f"requested requirement {clean_req_id!r}"
        )
    if proposal.frozen_contract_digest != context_envelope.frozen_contract_digest:
        p_dig = proposal.frozen_contract_digest
        e_dig = context_envelope.frozen_contract_digest
        raise WitnessPlanBindingMismatchError(
            f"Model proposal contract digest {p_dig!r} != envelope digest {e_dig!r}"
        )
    if proposal.source_commit_id != context_envelope.source_commit_id:
        raise WitnessPlanBindingMismatchError(
            f"Model proposal source_commit_id {proposal.source_commit_id!r} does not match "
            f"envelope commit {context_envelope.source_commit_id!r}"
        )

    return proposal


# --- Deterministic Plan Validator (P-09.02) ---


class WitnessPlanValidator:
    """Deterministically validates a proposed witness plan against security and scope policies.

    Enforces:
    - Exact frozen contract digest match.
    - Exact source commit match.
    - Scope strictly BUG_FIX.
    - Witness artifact paths normalized, non-traversing, non-protected.
    - Witness artifact contents free of secrets and malicious execution patterns.
    - Test execution command using approved executable and safe arguments.
    - No self-certification or authority smuggling.
    """

    def __init__(
        self,
        *,
        manifest: ProtectedSurfaceManifest | None = None,
        allowed_executables: frozenset[str] = ALLOWED_TEST_EXECUTABLES,
    ) -> None:
        self.manifest = manifest or get_canonical_basebreak_protected_manifest()
        self.allowed_executables = allowed_executables

    def validate(
        self,
        proposal: WitnessPlanProposal,
        *,
        context_envelope: VerifierContextEnvelope,
    ) -> ValidatedWitnessPlan:
        """Deterministically validate proposal against context envelope. Fails closed."""
        if not isinstance(proposal, WitnessPlanProposal):
            raise TypeError(f"Expected WitnessPlanProposal, got {type(proposal).__name__}")
        if not isinstance(context_envelope, VerifierContextEnvelope):
            raise TypeError(
                f"Expected VerifierContextEnvelope, got {type(context_envelope).__name__}"
            )

        # 1. Scope check: BUG_FIX only in P-09
        if proposal.change_class != ChangeClass.BUG_FIX:
            raise WitnessPlanScopeError(
                f"Only BUG_FIX is supported in P-09, got {proposal.change_class.value!r}"
            )

        # 2. Exact binding verification
        if proposal.requirement_id not in [
            r.requirement_id
            for r in (
                context_envelope.frozen_contract.requirements
                if context_envelope.frozen_contract
                else ()
            )
        ] and (context_envelope.frozen_contract is not None):
            raise WitnessPlanBindingMismatchError(
                f"Requirement {proposal.requirement_id!r} does not belong to frozen contract"
            )

        if proposal.frozen_contract_digest != context_envelope.frozen_contract_digest:
            raise WitnessPlanBindingMismatchError(
                f"Contract digest mismatch: plan {proposal.frozen_contract_digest!r} != "
                f"envelope {context_envelope.frozen_contract_digest!r}"
            )

        if proposal.source_commit_id != context_envelope.source_commit_id:
            raise WitnessPlanBindingMismatchError(
                f"Source commit mismatch: plan {proposal.source_commit_id!r} != "
                f"envelope {context_envelope.source_commit_id!r}"
            )

        # 3. Authority smuggling checks
        if proposal.is_authoritative is not False:
            raise WitnessPlanAuthoritySmugglingError("is_authoritative must be strictly False")
        if proposal.grants_pass is not False:
            raise WitnessPlanAuthoritySmugglingError("grants_pass must be strictly False")

        # 4. Command validation
        if not proposal.execution_command:
            raise WitnessPlanSecurityError("Execution command must not be empty")

        executable = proposal.execution_command[0].strip()
        # Extract base executable name (e.g. "pytest" from "pytest" or "/usr/bin/pytest")
        base_exe = executable.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        if base_exe not in self.allowed_executables:
            allowed_list = sorted(self.allowed_executables)
            raise WitnessPlanSecurityError(
                f"Disallowed test executable {executable!r}; allowed: {allowed_list}"
            )

        for arg in proposal.execution_command:
            if any(ch in arg for ch in _FORBIDDEN_SHELL_CHARS):
                raise WitnessPlanSecurityError(
                    f"Forbidden shell character detected in command argument: {arg!r}"
                )
            # Check for builder workspace inspection in arguments
            if "/builder_workspace" in arg or "/workspace/candidate" in arg:
                raise WitnessPlanSecurityError(
                    f"Command attempts to access Builder workspace: {arg!r}"
                )

        # 5. Artifact validation
        validated_artifacts: list[ValidatedWitnessArtifact] = []
        seen_paths: set[str] = set()

        for idx, art in enumerate(proposal.artifacts):
            # Path safety and normalization
            try:
                norm_path = normalize_repo_path(art.path)
            except (PathTraversalError, PathSecurityError) as exc:
                raise WitnessPlanSecurityError(
                    f"Artifact path security error at index {idx}: {exc}"
                ) from exc

            if norm_path in seen_paths:
                raise WitnessPlanSecurityError(f"Duplicate artifact path detected: {norm_path!r}")
            seen_paths.add(norm_path)

            # Protected surface collision check
            if is_path_protected(norm_path, self.manifest):
                raise WitnessPlanSecurityError(
                    f"Witness path {norm_path!r} collides with protected governance surface"
                )

            # Verifier internal directories check
            for prefix in VERIFIER_DIRECTORY_PREFIXES:
                if norm_path.startswith(prefix) or f"/{prefix}" in norm_path:
                    raise WitnessPlanSecurityError(
                        f"Witness path {norm_path!r} collides with verifier surface {prefix!r}"
                    )

            # Secret scan
            if contains_secret(art.content):
                raise WitnessPlanSecurityError(
                    f"Witness artifact {norm_path!r} contains credentials or secrets"
                )

            # Malicious execution pattern checks
            if (
                "/builder_workspace" in art.content
                or "builder_sandbox" in art.content
                or "UntrustedWitnessAuthorityError" in art.content
            ):
                raise WitnessPlanSecurityError(
                    f"Witness artifact {norm_path!r} references Builder/verifier internals"
                )

            encoded = art.content.encode("utf-8")
            digest = hashlib.sha256(encoded).hexdigest()
            validated_artifacts.append(
                ValidatedWitnessArtifact(
                    path=norm_path,
                    content=art.content,
                    content_digest=digest,
                    byte_size=len(encoded),
                    rationale=art.rationale,
                )
            )

        # 6. Compute deterministic plan digest
        sorted_arts = sorted(validated_artifacts, key=lambda a: a.path)
        payload = {
            "artifacts": [
                {
                    "byte_size": a.byte_size,
                    "content_digest": a.content_digest,
                    "path": a.path,
                }
                for a in sorted_arts
            ],
            "change_class": proposal.change_class.value,
            "execution_command": list(proposal.execution_command),
            "frozen_contract_digest": proposal.frozen_contract_digest,
            "requirement_id": proposal.requirement_id,
            "source_commit_id": proposal.source_commit_id,
            "witness_id": proposal.witness_id,
        }
        canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        plan_digest = hashlib.sha256(canonical_bytes).hexdigest()

        return ValidatedWitnessPlan(
            witness_id=proposal.witness_id,
            requirement_id=proposal.requirement_id,
            frozen_contract_digest=proposal.frozen_contract_digest,
            source_commit_id=proposal.source_commit_id,
            change_class=proposal.change_class,
            plan_summary=proposal.plan_summary,
            target_files=proposal.target_files,
            artifacts=tuple(sorted_arts),
            execution_command=proposal.execution_command,
            expected_failure_at_base=proposal.expected_failure_at_base,
            expected_success_at_candidate=proposal.expected_success_at_candidate,
            plan_digest=plan_digest,
            is_authoritative=False,
            grants_pass=False,
        )
