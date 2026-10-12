"""Tests for Product Design, Judge Comprehension, and Accessibility (P-28.01 - P-28.05).

Validates:
1. P-28.01: 30-second comprehension structure (Thesis, verdicts, provenance prominent).
2. P-28.02: Simplified terminology around the memorable thesis and Green CI explainer.
3. P-28.03: 3-world causal transition prominently surfaced.
4. P-28.04: Distinct, honest, high-value views for all 5 verdict states.
5. P-28.05: WCAG contrast math, keyboard accessibility, responsive viewport, and escaping.
"""

from __future__ import annotations

import html

from basebreak.causal.coverage import compute_causal_coverage
from basebreak.causal.public_receipt import (
    PublicCounterfactualFact,
    PublicExecutionFact,
    PublicVerificationReceipt,
    PublicWitnessFact,
    create_public_verification_receipt,
)
from basebreak.causal.receipt import WorldExecutionFact, create_causal_receipt
from basebreak.causal.reconciliation import CausalTransition
from basebreak.compiler.freeze import FrozenContract, FrozenRequirement
from basebreak.compiler.semantics import CertaintyLevel
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.ui.models import build_judge_view_data
from basebreak.ui.renderer import render_judge_ui_html
from basebreak.verifier.witness_result import WitnessOutcome
from basebreak.verifier.witness_store import TrustedWitnessVault, WitnessArtifact


def _create_mock_receipt(
    verdict: PreliminaryVerdict = PreliminaryVerdict.VERIFIED,
) -> PublicVerificationReceipt:
    """Helper creating a valid PublicVerificationReceipt for testing."""
    req = FrozenRequirement(
        requirement_id="REQ-001",
        statement="Enforce token validation",
        citation="token validation",
        citation_start=0,
        citation_end=16,
        rationale="Fix auth bug",
    )
    contract = object.__new__(FrozenContract)
    object.__setattr__(contract, "schema_version", "1.0.0")
    object.__setattr__(contract, "task_digest", "f" * 64)
    object.__setattr__(contract, "change_class", ChangeClass.BUG_FIX)
    object.__setattr__(contract, "certainty", CertaintyLevel.CONFIDENT)
    object.__setattr__(contract, "requirements", (req,))
    object.__setattr__(contract, "contract_digest", "c" * 64)

    base_wef = WorldExecutionFact(
        world=ExecutionWorld.BASE,
        sandbox_id="sbx-test-base",
        source_commit_id="1" * 40,
        tree_digest="2" * 40,
        outcome=WitnessOutcome.FAIL
        if verdict != PreliminaryVerdict.CONTRADICTED
        else WitnessOutcome.PASS,
        exit_code=1 if verdict != PreliminaryVerdict.CONTRADICTED else 0,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="3" * 64,
        stderr_digest="4" * 64,
        result_digest="8" * 64,
        duration_seconds=1.2,
    )
    cand_wef = WorldExecutionFact(
        world=ExecutionWorld.CANDIDATE,
        sandbox_id="sbx-test-cand",
        source_commit_id="1" * 40,
        tree_digest="5" * 40,
        outcome=WitnessOutcome.PASS
        if verdict != PreliminaryVerdict.CONTRADICTED
        else WitnessOutcome.FAIL,
        exit_code=0 if verdict != PreliminaryVerdict.CONTRADICTED else 1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="6" * 64,
        stderr_digest="7" * 64,
        result_digest="9" * 64,
        duration_seconds=1.4,
    )
    vault = TrustedWitnessVault.create_authorized_vault()
    wa = WitnessArtifact.from_text(
        path="tests/test_witness.py",
        content="def test_w(): assert True\n",
    )
    rec = vault.seal_witness(
        witness_id="WIT-001",
        requirement_id="REQ-001",
        frozen_contract_digest="c" * 64,
        source_commit_id="1" * 40,
        artifacts=[wa],
    )
    vault.record_observed_execution(
        witness_id="WIT-001",
        witness_digest=rec.seal_digest,
        requirement_id="REQ-001",
        frozen_contract_digest="c" * 64,
        source_commit_id="1" * 40,
        candidate_tree_digest="5" * 40,
        sandbox_id=base_wef.sandbox_id,
        world=ExecutionWorld.BASE,
        command=("pytest", "-q"),
        exit_code=base_wef.exit_code,
        termination_status=base_wef.termination_status,
        stdout_digest=base_wef.stdout_digest,
        stderr_digest=base_wef.stderr_digest,
        result_digest=base_wef.result_digest,
        outcome=base_wef.outcome,
        provenance=EvidenceProvenance.FIXTURE,
    )
    vault.record_observed_execution(
        witness_id="WIT-001",
        witness_digest=rec.seal_digest,
        requirement_id="REQ-001",
        frozen_contract_digest="c" * 64,
        source_commit_id="1" * 40,
        candidate_tree_digest="5" * 40,
        sandbox_id=cand_wef.sandbox_id,
        world=ExecutionWorld.CANDIDATE,
        command=("pytest", "-q"),
        exit_code=cand_wef.exit_code,
        termination_status=cand_wef.termination_status,
        stdout_digest=cand_wef.stdout_digest,
        stderr_digest=cand_wef.stderr_digest,
        result_digest=cand_wef.result_digest,
        outcome=cand_wef.outcome,
        provenance=EvidenceProvenance.FIXTURE,
    )
    trans = (
        CausalTransition.CAUSAL_BUG_FIX_VERIFIED
        if verdict == PreliminaryVerdict.VERIFIED
        else CausalTransition.UNVERIFIED_REGRESSION
        if verdict == PreliminaryVerdict.CONTRADICTED
        else CausalTransition.NON_VERIFIED_TIMEOUT
        if verdict == PreliminaryVerdict.INCONCLUSIVE
        else CausalTransition.NON_VERIFIED_EXECUTION_ERROR
    )
    attestation = vault.attest_execution(
        requirement_id="REQ-001",
        frozen_contract_digest="c" * 64,
        witness_id="WIT-001",
        source_commit_id="1" * 40,
        candidate_tree_digest="5" * 40,
        base_execution=base_wef,
        candidate_execution=cand_wef,
        counterfactual_execution=None,
        transition=trans,
        verdict=verdict,
        provenance=EvidenceProvenance.FIXTURE,
    )
    local_receipt = create_causal_receipt(
        requirement_id="REQ-001",
        frozen_contract_digest="c" * 64,
        witness_id="WIT-001",
        witness_digest=rec.seal_digest,
        lock_digest="d" * 64,
        base_execution=base_wef,
        candidate_execution=cand_wef,
        transition=trans,
        verdict=verdict,
        provenance=EvidenceProvenance.FIXTURE,
        narrative="Transition executed",
        attestation=attestation,
    )
    coverage = compute_causal_coverage(
        frozen_contract=contract,
        results={"REQ-001": local_receipt},
        verifier_authority=vault,
    )
    witness = PublicWitnessFact(
        witness_id="WIT-001",
        witness_digest=rec.seal_digest,
        requirement_id="REQ-001",
        execution_command=("pytest", "-q"),
        timeout_seconds=30.0,
    )
    base_exec = PublicExecutionFact(
        world=ExecutionWorld.BASE,
        sandbox_id="sbx-test-base",
        source_commit_id="1" * 40,
        tree_digest="2" * 40,
        outcome=WitnessOutcome.FAIL
        if verdict != PreliminaryVerdict.CONTRADICTED
        else WitnessOutcome.PASS,
        exit_code=1 if verdict != PreliminaryVerdict.CONTRADICTED else 0,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="3" * 64,
        stderr_digest="4" * 64,
        duration_seconds=1.2,
    )
    cand_exec = PublicExecutionFact(
        world=ExecutionWorld.CANDIDATE,
        sandbox_id="sbx-test-cand",
        source_commit_id="1" * 40,
        tree_digest="5" * 40,
        outcome=WitnessOutcome.PASS
        if verdict != PreliminaryVerdict.CONTRADICTED
        else WitnessOutcome.FAIL,
        exit_code=0 if verdict != PreliminaryVerdict.CONTRADICTED else 1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="6" * 64,
        stderr_digest="7" * 64,
        duration_seconds=1.4,
    )
    cf_exec = PublicExecutionFact(
        world=ExecutionWorld.COUNTERFACTUAL,
        sandbox_id="sbx-test-cf",
        source_commit_id="1" * 40,
        tree_digest="5" * 40,
        outcome=WitnessOutcome.FAIL,
        exit_code=1,
        termination_status=TerminationStatus.COMPLETED,
        stdout_digest="8" * 64,
        stderr_digest="9" * 64,
        duration_seconds=1.3,
    )
    cf_fact = PublicCounterfactualFact(
        is_required=True,
        candidate_tree_digest="5" * 40,
        delta_digest="a" * 64,
        outcome=WitnessOutcome.FAIL,
        execution_fact=cf_exec,
    )
    return create_public_verification_receipt(
        frozen_contract_digest="c" * 64,
        task_id="TASK-P28-TEST",
        repo_locator="https://github.com/zyganali-glitch/Basebreak.git",
        source_commit_id="1" * 40,
        candidate_tree_digest="5" * 40,
        candidate_patch_digest="b" * 64,
        coverage_summary=coverage,
        executions=(base_exec, cand_exec),
        witnesses=(witness,),
        counterfactual=cf_fact,
        overall_verdict=verdict,
        provenance=EvidenceProvenance.LOCAL_EXECUTION,
        runtime_identities=("sbx-test-base", "sbx-test-cand"),
    )


def test_p28_01_thirty_second_comprehension_hierarchy() -> None:
    """Dashboard leads with Thesis, Verdict, and 3-World outcome within the first visual block."""
    rc = _create_mock_receipt(PreliminaryVerdict.VERIFIED)
    rendered = render_judge_ui_html(rc)

    # 1. Thesis is front-and-center
    assert "“If the patch matters, the base must break.”" in rendered
    assert "BASEBREAK VERIFICATION RUNTIME" in rendered

    # 2. Verdict badge and Provenance badge are rendered
    assert "badge-verified" in rendered
    assert "VERIFIED" in rendered
    assert "LOCAL_EXECUTION" in rendered

    # 3. 3-World Causal Verification appears before timeline or raw hashes
    world_pos = rendered.find("Three-World Causal Verification")
    timeline_pos = rendered.find("Execution Stage Timeline")
    receipt_pos = rendered.find("Cryptographic Public Receipt")

    assert world_pos != -1
    assert timeline_pos != -1
    assert receipt_pos != -1
    assert world_pos < timeline_pos, (
        "3-World verification must precede timeline for immediate comprehension"
    )
    assert world_pos < receipt_pos, "3-World verification must precede receipt technical hashes"


def test_p28_02_green_ci_explainer_card() -> None:
    """Dashboard includes the plain English 'Why Ordinary Green CI Lies' comparison."""
    rc = _create_mock_receipt(PreliminaryVerdict.VERIFIED)
    rendered = render_judge_ui_html(rc)

    assert "Why Ordinary Green CI Lies" in rendered
    assert "Only tests Candidate" in rendered
    assert "Basebreak Causal Verification" in rendered
    assert "Proves Causal Necessity" in rendered
    assert "Base = FAIL" in rendered
    assert "Candidate = PASS" in rendered
    assert "Counterfactual = FAIL" in rendered


def test_p28_03_three_world_step_tags() -> None:
    """Dashboard surfaces the 3-World step tags and causal transition formula."""
    rc = _create_mock_receipt(PreliminaryVerdict.VERIFIED)
    rendered = render_judge_ui_html(rc)

    assert "[1. Reproduce Defect on Base]" in rendered
    assert "[2. Confirm Fix on Candidate]" in rendered
    assert "[3. Prove Delta Necessity]" in rendered
    assert "Causal Transition:" in rendered
    assert "BASE=FAIL" in rendered
    assert "CANDIDATE=PASS" in rendered


def test_p28_04_all_five_verdict_views() -> None:
    """Dashboard produces distinct, honest, non-misleading views for all 5 verdict states."""
    verdict_cases = [
        (PreliminaryVerdict.VERIFIED, "banner-verified", "CAUSAL VERIFICATION SUCCESS"),
        (PreliminaryVerdict.CONTRADICTED, "banner-contradicted", "CAUSAL CONTRADICTION DETECTED"),
        (PreliminaryVerdict.INCONCLUSIVE, "banner-inconclusive", "INCONCLUSIVE EXECUTION"),
        (PreliminaryVerdict.BLOCKED, "banner-blocked", "EXECUTION BLOCKED"),
    ]

    for verdict, expected_class, expected_text in verdict_cases:
        rc = _create_mock_receipt(verdict)
        rendered = render_judge_ui_html(rc)
        assert expected_class in rendered, f"Expected {expected_class} in {verdict}"
        assert expected_text in rendered, f"Expected {expected_text} in {verdict}"

    # Test NOT_RUN case via view data override
    rc = _create_mock_receipt(PreliminaryVerdict.VERIFIED)
    vd = build_judge_view_data(rc)
    object.__setattr__(vd, "verdict", "NOT_RUN")
    object.__setattr__(vd, "verdict_badge_class", "badge-not-run")
    rendered_not_run = render_judge_ui_html(vd)

    assert "banner-not-run" in rendered_not_run
    assert "NOT_RUN / AWAITING EXECUTION" in rendered_not_run


def test_p28_05_wcag_color_contrast_ratios() -> None:
    """Validate that all core color palette values meet WCAG AA contrast against dark background."""
    bg_hex = "#0f172a"  # Dark Slate Background

    def _hex_to_luminance(hex_str: str) -> float:
        hex_clean = hex_str.lstrip("#")
        r, g, b = (int(hex_clean[i : i + 2], 16) / 255.0 for i in (0, 2, 4))

        def _lin(c: float) -> float:
            return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

        return 0.2126 * _lin(r) + 0.7152 * _lin(g) + 0.0722 * _lin(b)

    def _contrast_ratio(hex1: str, hex2: str) -> float:
        l1 = _hex_to_luminance(hex1)
        l2 = _hex_to_luminance(hex2)
        hi, lo = max(l1, l2), min(l1, l2)
        return (hi + 0.05) / (lo + 0.05)

    palette = {
        "text-main (#f8fafc)": "#f8fafc",
        "text-muted (#94a3b8)": "#94a3b8",
        "accent (#38bdf8)": "#38bdf8",
        "green (#4ade80)": "#4ade80",
        "red (#f87171)": "#f87171",
        "amber (#fbbf24)": "#fbbf24",
        "purple (#c084fc)": "#c084fc",
        "blue (#60a5fa)": "#60a5fa",
    }

    for name, hex_val in palette.items():
        ratio = _contrast_ratio(hex_val, bg_hex)
        # WCAG AA requires at least 4.5:1 for normal text
        assert ratio >= 4.5, (
            f"Color {name} contrast ratio {ratio:.2f}:1 fails WCAG AA 4.5:1 requirement"
        )


def test_p28_05_html_escaping_and_xss_safety() -> None:
    """Special characters and script injections in task, digests, and IDs are strictly escaped."""
    malicious_run_id = '<script>alert("xss")</script>'
    rc = _create_mock_receipt(PreliminaryVerdict.VERIFIED)
    vd = build_judge_view_data(rc)
    object.__setattr__(vd, "run_id", malicious_run_id)

    rendered = render_judge_ui_html(vd)

    # Raw script tags must never appear unescaped in rendered HTML
    assert "<script>" not in rendered
    assert html.escape(malicious_run_id) in rendered


def test_p28_05_keyboard_and_responsive_features() -> None:
    """HTML includes viewport meta tag, :focus-visible CSS, and scrollable table region."""
    rc = _create_mock_receipt(PreliminaryVerdict.VERIFIED)
    rendered = render_judge_ui_html(rc)

    assert '<meta name="viewport" content="width=device-width, initial-scale=1.0">' in rendered
    assert ":focus-visible" in rendered
    assert "word-break: break-all" in rendered
    assert 'role="region"' in rendered
    assert 'aria-label="Scrollable requirements table"' in rendered
