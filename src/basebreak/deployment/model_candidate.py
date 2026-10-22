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

DEFAULT_CANDIDATE_MAX_TOKENS: int = 32768
CANDIDATE_MAX_TOKENS_ENV_VAR: str = "BASEBREAK_CANDIDATE_MAX_TOKENS"


def resolve_candidate_max_tokens(configured: int | None = None) -> int:
    """Resolve the candidate generation max token budget.

    Supports operator configuration up to the model output limit (262,144 tokens),
    falling back to DEFAULT_CANDIDATE_MAX_TOKENS (32,768).
    The 1,048,576 context window bounds total sequence length (prompt + output),
    not the output token limit alone.
    """
    from basebreak.adapters.nebius.models import MAX_MAX_TOKENS

    if configured is not None and configured > 0:
        return max(1, min(configured, MAX_MAX_TOKENS))
    import os

    env_val = os.environ.get(CANDIDATE_MAX_TOKENS_ENV_VAR, "").strip()
    if env_val:
        try:
            parsed = int(env_val)
            if 1 <= parsed <= MAX_MAX_TOKENS:
                return parsed
        except ValueError:
            pass
    return DEFAULT_CANDIDATE_MAX_TOKENS


# Provider response format for genuine candidate generation.
# Reverted to text mode (None) because Nebius Token Factory with Nemotron-3.5-Lightning
# routes model output into reasoning_content when {"type": "json_object"} is passed,
# leaving choices[0].message.content null. Text mode allows full output into content,
# with strict JSON prompting and bounded control-character recovery.
CANDIDATE_RESPONSE_FORMAT: dict[str, str] | None = None

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
    '"content":"<COMPLETE_FULL_FILE_CONTENT>","rationale":str}],"proposed_commands":[]}'
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
        finish_reason: str | None = None,
        has_reasoning_content: bool = False,
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
        self.finish_reason = finish_reason
        self.has_reasoning_content = has_reasoning_content


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
    model_call_count: int = 1
    provider_request_ids: tuple[str, ...] = ()

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
        "CRITICAL FILE-ACTION RULES:\n"
        "1. For 'MODIFY' actions: the 'content' field MUST contain the COMPLETE, ENTIRE "
        "replacement source code for the file from line 1 to the end of the file. "
        "Never provide only a function, method, snippet, or diff. "
        "The file must be fully self-contained and syntactically valid Python, "
        "preserving all imports, existing classes (e.g. `class ResetVault:`), "
        "exception definitions (e.g. `class TokenError:`), and existing methods.\n"
        "2. For 'CREATE' actions: 'content' must be the complete file content.\n"
        "3. For 'DELETE' actions: 'content' must be empty string.\n"
        "4. Propose the smallest correct fix that satisfies the frozen requirement "
        "while keeping all other code, interfaces, and ordinary behavior intact.\n\n"
        "CRITICAL FORMAT INSTRUCTION: Output MUST be a single raw JSON object "
        "starting with '{' and ending with '}'. "
        "Do NOT wrap in markdown fences (no ```json or ```). "
        "Do NOT include any preamble, commentary, explanation, or "
        "postscript outside the JSON object.\n"
        "Keep the plan summary, reasoning, and steps concise (1-2 sentences each). "
        "Focus the token budget on exact proposed file content.\n"
        "Respond with strict JSON matching this schema exactly:\n"
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
                "You are the Basebreak Builder runtime agent.\n"
                "Produce ONLY a valid, raw JSON object matching the requested schema. "
                "Do NOT wrap in markdown fences or backticks. Do NOT include any preamble, "
                "explanation, or postscript outside the JSON object. "
                "For MODIFY actions, always provide the complete file content from line 1 to EOF. "
                "Be concise: keep plan reasoning and summaries brief so the entire JSON "
                "object completes within budget.\n"
                "Never invent execution authority. Propose file content only."
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


def validate_candidate_preexecution(
    *,
    candidate_files: Mapping[str, str],
    base_files: Mapping[str, str],
    target: str = "",
) -> tuple[bool, str | None, str | None]:
    """Validate candidate files for syntax, class/interface preservation, and ordinary behavior.

    Returns (is_valid, failed_path, error_message).
    """
    import ast

    # 1. AST syntax check on all python files
    for path, content in sorted(candidate_files.items()):
        if path.endswith(".py"):
            try:
                ast.parse(content, filename=path)
            except (SyntaxError, IndentationError) as exc:
                return (
                    False,
                    path,
                    f"Python syntax error at line {exc.lineno}: {type(exc).__name__}: {exc.msg}",
                )

    # 2. Public API class and function preservation
    for path, base_content in sorted(base_files.items()):
        if not path.endswith(".py"):
            continue
        cand_content = candidate_files.get(path)
        if cand_content is None:
            continue  # file was deleted
        try:
            base_tree = ast.parse(base_content, filename=path)
            cand_tree = ast.parse(cand_content, filename=path)
        except Exception:
            continue

        base_classes = {node.name for node in base_tree.body if isinstance(node, ast.ClassDef)}
        cand_classes = {node.name for node in cand_tree.body if isinstance(node, ast.ClassDef)}
        missing_classes = base_classes - cand_classes
        if missing_classes:
            return (
                False,
                path,
                f"Candidate file is missing required class(es): {sorted(missing_classes)}. "
                "For 'MODIFY' actions, 'content' must be the complete file preserving all classes.",
            )

        base_funcs = {
            node.name
            for node in base_tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        cand_funcs = {
            node.name
            for node in cand_tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        missing_funcs = base_funcs - cand_funcs
        if missing_funcs:
            missing_names = sorted(missing_funcs)
            return (
                False,
                path,
                f"Candidate file is missing required top-level function(s): {missing_names}.",
            )

    # 3. ResetVault ordinary behavior check (if target involves ResetVault)
    vault_rel = "tests/fixtures/reset_vault/src/reset_vault/vault.py"
    if vault_rel in candidate_files:
        vault_code = candidate_files[vault_rel]
        globs: dict[str, Any] = {}
        try:
            compiled = compile(vault_code, "vault.py", "exec")
            exec(compiled, globs)
        except Exception as exc:
            return (
                False,
                vault_rel,
                f"Candidate vault.py failed execution: {type(exc).__name__}: {exc}",
            )

        vault_cls = globs.get("ResetVault")
        if not isinstance(vault_cls, type):
            return (
                False,
                vault_rel,
                "Candidate vault.py does not define class 'ResetVault'",
            )

        try:
            inst = vault_cls()
            inst.set_user_password("alice", "initial_pass")
            token = inst.create_reset_token("alice")
            if not isinstance(token, str) or not token:
                return False, vault_rel, "create_reset_token did not return a valid token"
            res = inst.redeem_reset_token(token, "new_pass")
            if res is not True:
                return False, vault_rel, "First valid token redemption failed"
            if inst.get_user_password("alice") != "new_pass":
                return False, vault_rel, "Password was not updated after first valid redemption"
        except Exception as exc:
            return (
                False,
                vault_rel,
                f"Candidate failed ordinary ResetVault behavior: {type(exc).__name__}: {exc}",
            )

    return True, None, None


def generate_model_candidate(
    *,
    model_client: Any,
    task_id: str,
    requirement_statement: str,
    frozen_contract_digest: str,
    target: str,
    allowed_paths: Sequence[str],
    base_files: Mapping[str, str],
    max_tokens: int | None = None,
    temperature: float = 0.0,
    max_candidate_attempts: int = 3,
) -> ModelCandidate:
    """Obtain and bind a genuine candidate from the configured model. Fails closed."""
    from basebreak.adapters.nebius import (
        ModelAdapterError,
        ModelConfigError,
        ModelResponseFormatError,
        ModelTruncatedResponseError,
    )

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
    import inspect
    import os

    enable_thinking = os.environ.get(
        "BASEBREAK_CANDIDATE_ENABLE_THINKING", "false"
    ).strip().lower() in ("true", "1")
    chat_template_kwargs = {"enable_thinking": False} if not enable_thinking else None

    eff_max_tokens = resolve_candidate_max_tokens(max_tokens)
    complete_kwargs: dict[str, Any] = {
        "max_tokens": eff_max_tokens,
        "temperature": temperature,
        "response_format": CANDIDATE_RESPONSE_FORMAT,
        "reject_length_truncation": True,
    }
    if chat_template_kwargs is not None:
        try:
            sig = inspect.signature(model_client.complete)
            params = sig.parameters
            accepts_var_keyword = any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
            )
            if accepts_var_keyword or "chat_template_kwargs" in params:
                complete_kwargs["chat_template_kwargs"] = chat_template_kwargs
        except (ValueError, TypeError):
            complete_kwargs["chat_template_kwargs"] = chat_template_kwargs

    current_messages = list(messages)
    call_count = 0
    cum_prompt_tokens = 0
    cum_completion_tokens = 0
    cum_total_tokens = 0
    cum_duration = 0.0
    all_request_ids: list[str] = []

    last_response_text = ""
    last_returned_model = ""
    last_request_id: str | None = None
    last_finish_reason: str | None = None
    last_has_reasoning = False

    proposal: BuilderProposal | None = None
    candidate_files: dict[str, str] = {}
    patch_text: str = ""

    for attempt in range(max(1, max_candidate_attempts)):
        call_count += 1
        try:
            result = model_client.complete(
                current_messages,
                **complete_kwargs,
            )
        except ModelConfigError as exc:
            # Pre-dispatch configuration/credential rejection: no provider work was dispatched.
            raise ModelCandidateRejectedError(
                f"candidate-generation request rejected before dispatch: {exc}",
                generation_attempted=False,
            ) from exc
        except ModelAdapterError as exc:
            # The provider call was dispatched but failed (timeout, network, non-2xx provider
            # error, malformed response, or model identity mismatch). The attempt is counted;
            # actual token usage and response facts are retained when reported by the provider.
            usage = getattr(exc, "usage", None)
            err_prompt = int(usage.prompt_tokens) if usage is not None else None
            err_comp = int(usage.completion_tokens) if usage is not None else None
            err_total = int(usage.total_tokens) if usage is not None else None
            if err_prompt is not None:
                cum_prompt_tokens += err_prompt
            if err_comp is not None:
                cum_completion_tokens += err_comp
            if err_total is not None:
                cum_total_tokens += err_total
            err_req_id = getattr(exc, "request_id", None)
            if err_req_id:
                all_request_ids.append(str(err_req_id).strip())
            common_error_kwargs: dict[str, Any] = {
                "generation_attempted": True,
                "generation_prompt_tokens": cum_prompt_tokens or err_prompt,
                "generation_completion_tokens": cum_completion_tokens or err_comp,
                "generation_total_tokens": cum_total_tokens or err_total,
                "provider_request_id": str(err_req_id).strip() or None if err_req_id else None,
                "returned_model": str(getattr(exc, "returned_model", None) or ""),
                "response_received": False,
                "finish_reason": getattr(exc, "finish_reason", None),
                "has_reasoning_content": bool(getattr(exc, "has_reasoning_content", False)),
            }
            if isinstance(exc, (ModelResponseFormatError, ModelTruncatedResponseError)):
                raise ModelCandidateRejectedError(
                    f"candidate-generation response rejected: {exc}",
                    **common_error_kwargs,
                ) from exc
            raise ModelCandidateTransportError(
                f"candidate-generation provider failure after dispatch: {exc}",
                **common_error_kwargs,
            ) from exc

        usage = getattr(result, "usage", None)
        duration = getattr(result, "duration_seconds", None)
        response_text = getattr(result, "content", None)
        finish_reason = getattr(result, "finish_reason", None)
        has_reasoning = bool(getattr(result, "has_reasoning_content", False))

        p_tok = int(getattr(usage, "prompt_tokens", 0) or 0) if usage is not None else 0
        c_tok = int(getattr(usage, "completion_tokens", 0) or 0) if usage is not None else 0
        t_tok = int(getattr(usage, "total_tokens", 0) or 0) if usage is not None else 0
        cum_prompt_tokens += p_tok
        cum_completion_tokens += c_tok
        cum_total_tokens += t_tok
        if duration is not None:
            cum_duration += float(duration)

        req_id = str(getattr(result, "request_id", "") or "").strip() or None
        if req_id:
            all_request_ids.append(req_id)
        last_request_id = req_id
        last_returned_model = str(getattr(result, "returned_model", "") or "")
        last_finish_reason = finish_reason
        last_has_reasoning = has_reasoning
        last_response_text = response_text if isinstance(response_text, str) else ""

        accounting: dict[str, Any] = {
            "generation_attempted": True,
            "generation_prompt_tokens": cum_prompt_tokens if cum_prompt_tokens > 0 else None,
            "generation_completion_tokens": cum_completion_tokens
            if cum_completion_tokens > 0
            else None,
            "generation_total_tokens": cum_total_tokens if cum_total_tokens > 0 else None,
            "generation_duration_seconds": cum_duration if cum_duration > 0.0 else None,
            "provider_request_id": last_request_id,
            "returned_model": last_returned_model,
            "response_received": isinstance(response_text, str) and bool(response_text.strip()),
            "finish_reason": last_finish_reason,
            "has_reasoning_content": last_has_reasoning,
        }

        # Explicitly reject a truncated generation response before any parsing.
        if isinstance(finish_reason, str) and finish_reason.strip().lower() == "length":
            truncated = ModelCandidateRejectedError(
                "candidate-generation response was truncated (finish_reason='length')",
                **accounting,
            )
            raise truncated

        if not isinstance(response_text, str) or not response_text.strip():
            if attempt + 1 < max_candidate_attempts:
                continue
            raise ModelCandidateRejectedError(
                "model returned an empty candidate response", **accounting
            )

        try:
            proposal, candidate_files, patch_text = _materialize_from_response(
                response_text=response_text,
                allowed_paths=allowed_paths,
                base_files=base_files,
            )
        except ModelCandidateRejectedError as exc:
            for key, value in accounting.items():
                setattr(exc, key, value)
            raise

        is_valid, failed_path, val_error = validate_candidate_preexecution(
            candidate_files=candidate_files,
            base_files=base_files,
            target=target,
        )
        if is_valid:
            break

        if attempt + 1 < max_candidate_attempts:
            target_path = failed_path or allowed_paths[0]
            repair_feedback = (
                f"Your proposed file action for '{target_path}' failed pre-execution validation:\n"
                f"{val_error}\n\n"
                "CRITICAL INSTRUCTIONS:\n"
                "- For 'MODIFY' actions, the 'content' field MUST contain the COMPLETE, FULL\n"
                "  file content from line 1 to EOF.\n"
                "- Do NOT provide just the modified method, diff, or partial snippet.\n"
                "- Preserve all imports, classes (including 'class ResetVault:'),\n"
                "  and existing methods.\n"
                "- The code must be syntactically valid Python.\n\n"
                "Please provide a corrected proposal as a single raw JSON object\n"
                "matching the schema."
            )
            current_messages = [
                messages[0],
                messages[1],
                {"role": "assistant", "content": response_text},
                {"role": "user", "content": repair_feedback},
            ]
            continue
        else:
            rej = ModelCandidateRejectedError(
                f"candidate pre-execution validation failed after "
                f"{call_count} attempts: {val_error}",
                **accounting,
            )
            raise rej

    assert proposal is not None
    patch_digest = _sha256_hex(patch_text)
    return ModelCandidate(
        origin=MODEL_GENERATED_CANDIDATE_ORIGIN,
        response_text=last_response_text,
        response_digest=_sha256_hex(last_response_text),
        returned_model=last_returned_model,
        provider_request_id=last_request_id,
        proposal=proposal,
        proposal_digest=_proposal_digest(proposal),
        candidate_files=tuple(sorted(candidate_files.items())),
        patch_text=patch_text,
        patch_digest=patch_digest,
        candidate_id=f"cand-model-{patch_digest[:16]}",
        generation_prompt_tokens=cum_prompt_tokens if cum_prompt_tokens > 0 else None,
        generation_completion_tokens=cum_completion_tokens if cum_completion_tokens > 0 else None,
        generation_total_tokens=cum_total_tokens if cum_total_tokens > 0 else None,
        generation_duration_seconds=cum_duration if cum_duration > 0.0 else None,
        model_call_count=call_count,
        provider_request_ids=tuple(all_request_ids),
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
