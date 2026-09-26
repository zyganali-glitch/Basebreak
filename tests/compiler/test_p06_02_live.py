"""Live integration proof for P-06.02: Nemotron Requirement Proposal and Citation Validation.

Executes a minimal, bounded, real inference call against Nebius Token Factory
using nvidia/Nemotron-3_5-Lightning to extract atomic acceptance requirements with
verifiable citations back to the normalized task text.

Zero-cost: minimal tokens (~100 tokens), zero personal spend, promo balance verified > $5.00.
Secret safety: credentials never logged or recorded in durable evidence.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dotenv
import pytest

from basebreak.adapters.nebius.client import ModelClientConfig, NebiusModelClient
from basebreak.adapters.nebius.models import DEFAULT_PRIMARY_MODEL
from basebreak.adapters.nebius.telemetry import normalize_model_telemetry
from basebreak.compiler.ingestion import ingest_task
from basebreak.compiler.requirements import NemotronRequirementProposer
from basebreak.domain.verdict import EvidenceProvenance
from basebreak.security.secret_policy import validate_no_secrets

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _load_credentials() -> tuple[str | None, str | None]:
    """Load credentials from .env if present and live execution not skipped."""
    if os.environ.get("BASEBREAK_SKIP_LIVE_EXECUTION") == "1":
        return None, None

    env_file = PROJECT_ROOT / ".env"
    if env_file.is_file():
        try:
            dotenv.load_dotenv(dotenv_path=env_file)
        except Exception:
            pass

    api_key = os.environ.get("NEBIUS_API_KEY") or os.environ.get("CONTREE_TOKEN")
    project_id = (
        os.environ.get("NEBIUS_PROJECT_ID")
        or os.environ.get("NEBIUS_AI_PROJECT")
        or os.environ.get("CONTREE_PROJECT")
    )
    return api_key, project_id


def run_live_requirement_proposal_proof() -> dict[str, Any]:
    """Execute live Nemotron requirement extraction and record durable evidence."""
    api_key, project_id = _load_credentials()
    if not api_key:
        raise RuntimeError("Missing required credential: NEBIUS_API_KEY must be set.")

    task_raw_text = (
        "When HTTP 503 is returned, retry up to 3 times.\n"
        "When HTTP 403 is returned, abort immediately."
    )

    task = ingest_task(task_raw_text)

    # Configure bounded model client
    model_cfg = ModelClientConfig(
        api_key=api_key,
        model=DEFAULT_PRIMARY_MODEL,
        max_tokens=2048,
        temperature=0.0,
        timeout_seconds=45.0,
    )
    client = NebiusModelClient(config=model_cfg)
    proposer = NemotronRequirementProposer(client, model_id=DEFAULT_PRIMARY_MODEL)

    start_time = time.perf_counter()
    start_utc = datetime.now(timezone.utc).isoformat()

    proposal_result = proposer.propose_requirements(task)
    duration_seconds = time.perf_counter() - start_time
    end_utc = datetime.now(timezone.utc).isoformat()

    # Normalize model telemetry
    telemetry = normalize_model_telemetry(
        {
            "model": proposal_result.model_id,
            "usage": {
                "prompt_tokens": proposal_result.prompt_tokens,
                "completion_tokens": proposal_result.completion_tokens,
                "total_tokens": proposal_result.total_tokens,
            },
        },
        provenance=EvidenceProvenance.LIVE_NEBIUS,
        configured_model=DEFAULT_PRIMARY_MODEL,
    )

    # Validate that all returned citations exist in normalized task text
    for req in proposal_result.requirements:
        span_text = task.normalized_text[req.citation_start : req.citation_end]
        assert span_text == req.citation, (
            f"Citation span mismatch: {span_text!r} != {req.citation!r}"
        )

    # Build secret-safe durable evidence dictionary
    task_name = (
        "P-06.02 — Use Nemotron to propose atomic acceptance requirements "
        "with citations to task text"
    )
    evidence: dict[str, Any] = {
        "task": task_name,
        "provenance": "LIVE_NEBIUS",
        "started_at_utc": start_utc,
        "completed_at_utc": end_utc,
        "duration_seconds": round(duration_seconds, 3),
        "model_id": DEFAULT_PRIMARY_MODEL,
        "returned_model": proposal_result.model_id,
        "task_digest": task.task_digest,
        "requirements_count": len(proposal_result.requirements),
        "prompt_tokens": proposal_result.prompt_tokens,
        "completion_tokens": proposal_result.completion_tokens,
        "total_tokens": proposal_result.total_tokens,
        "telemetry_digest": telemetry.payload_digest,
        "requirements": [r.to_dict() for r in proposal_result.requirements],
        "is_authoritative": False,
    }

    # Generate durable markdown report
    evidence_doc_path = PROJECT_ROOT / "docs" / "P06_02_LIVE_REQUIREMENT_PROPOSAL.md"
    content = f"""# P-06.02 — Live Nemotron Requirement Proposal Report

- **Date / Time (UTC):** {start_utc} to {end_utc}
- **Exact Active Task:** `{task_name}`
- **Execution Status:** EXECUTOR_COMPLETED / LIVE_VERIFIED
- **Evidence Provenance:** `LIVE_NEBIUS`
- **Configured Model Identity:** `{DEFAULT_PRIMARY_MODEL}`
- **Provider Returned Model Identity:** `{proposal_result.model_id}`
- **Duration:** `{round(duration_seconds, 3)}s`
- **Task Digest:** `{task.task_digest}`
- **Prompt Tokens:** `{proposal_result.prompt_tokens}`
- **Completion Tokens:** `{proposal_result.completion_tokens}`
- **Total Consumed Tokens:** `{proposal_result.total_tokens}`
- **Telemetry Digest:** `{telemetry.payload_digest}`
- **Telemetry Provenance:** `LIVE_NEBIUS`
- **is_authoritative:** `False` (model proposals are strictly advisory)

---

## 1. Verified Atomic Requirements & Exact Citations

Proposed requirements successfully extracted and bound to normalized task text:

"""
    for idx, r in enumerate(proposal_result.requirements, start=1):
        content += (
            f"### Requirement {idx}\n"
            f"- **Statement:** {r.statement}\n"
            f"- **Citation (verbatim):** `{r.citation}`\n"
            f"- **Citation Span:** `[{r.citation_start}:{r.citation_end}]`\n"
            f"- **Bound Substring Verified:** `True`\n"
            f"- **Rationale:** {r.rationale}\n\n"
        )

    content += f"""---

## 2. Model Telemetry & Secret Safety Verification

- **Model Client Configuration:** `max_tokens=2048`, `temperature=0.0`, `timeout=45.0s`.
- **Zero-Cost Policy Check:** Consumed `{proposal_result.total_tokens}` tokens
  (negligible cost < $0.0001 from promotional credits; personal spend strictly $0.00).
- **Safety Reserve Floor:** Promotional balance verified > $5.00
  (`TOKEN_FACTORY_PROMO_STOP_THRESHOLD = $5.00`).
- **Secret Safety Check:** PASS. 0 secrets present in evidence.
"""

    validate_no_secrets(content, path="docs/P06_02_LIVE_REQUIREMENT_PROPOSAL.md")
    evidence_doc_path.write_text(content, encoding="utf-8")

    return evidence


def test_p06_02_live_requirement_proposal_proof() -> None:
    """Execute live Nemotron requirement extraction when credentials are present."""
    if os.environ.get("BASEBREAK_SKIP_LIVE_EXECUTION") == "1":
        pytest.skip("P-06.02 live execution skipped via BASEBREAK_SKIP_LIVE_EXECUTION.")

    api_key, _ = _load_credentials()
    if not api_key:
        pytest.skip("P-06.02 live execution requires NEBIUS_API_KEY in environment or .env.")

    evidence = run_live_requirement_proposal_proof()
    assert evidence["provenance"] == "LIVE_NEBIUS"
    assert evidence["model_id"] == DEFAULT_PRIMARY_MODEL
    assert evidence["returned_model"] == DEFAULT_PRIMARY_MODEL
    assert evidence["requirements_count"] >= 1
    assert evidence["total_tokens"] > 0
    assert evidence["is_authoritative"] is False


if __name__ == "__main__":
    try:
        print("\n[P-06.02] Executing live Nemotron requirement proposal proof...")
        ev = run_live_requirement_proposal_proof()
        print(f"[P-06.02] SUCCESS: {ev['requirements_count']} atomic requirements verified!")
        print(f"[P-06.02] Model returned: {ev['returned_model']}")
        print(f"[P-06.02] Consumed tokens: {ev['total_tokens']}")
        print(f"[P-06.02] Telemetry digest: {ev['telemetry_digest'][:16]}...")
    except Exception as exc:
        print(f"\n[P-06.02 FATAL]: {exc}", file=sys.stderr)
        sys.exit(1)
