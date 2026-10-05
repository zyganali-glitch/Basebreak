"""Tests for P-09.03: Executable behavioral witness generator and vault registration.

Verifies:
1. ValidatedWitnessPlan artifact creation and authentic sealing in TrustedWitnessVault.
2. Rejection of Builder-authored test collisions and imports.
3. Strict BUG_FIX change semantics enforcement.
4. Tamper verification of freshly sealed records.
5. Provider purity (zero adapter imports in witness_generator).
"""

from __future__ import annotations

import ast
import inspect

import pytest

from basebreak.domain.semantics import ChangeClass
from basebreak.verifier.witness_generator import (
    BuilderTestContaminationError,
    WitnessGenerator,
)
from basebreak.verifier.witness_plan import (
    ValidatedWitnessArtifact,
    ValidatedWitnessPlan,
    WitnessPlanScopeError,
)
from basebreak.verifier.witness_store import (
    SealedWitnessRecord,
    TrustedWitnessVault,
)


@pytest.fixture
def sample_validated_plan() -> ValidatedWitnessPlan:
    content = "def test_boundary():\n    assert 1 == 1\n"
    encoded = content.encode("utf-8")
    import hashlib

    art = ValidatedWitnessArtifact(
        path="tests/witness/test_boundary.py",
        content=content,
        content_digest=hashlib.sha256(encoded).hexdigest(),
        byte_size=len(encoded),
        rationale="Boundary check",
    )
    return ValidatedWitnessPlan(
        witness_id="wit-gen-01",
        requirement_id="REQ-TEST-01",
        frozen_contract_digest="0" * 64,
        source_commit_id="a" * 40,
        change_class=ChangeClass.BUG_FIX,
        plan_summary="Plan",
        target_files=("src/buffer.py",),
        artifacts=(art,),
        execution_command=("pytest", "tests/witness/test_boundary.py"),
        expected_failure_at_base="Fail",
        expected_success_at_candidate="Pass",
        plan_digest="1" * 64,
        is_authoritative=False,
        grants_pass=False,
    )


def test_generate_and_seal_witness_success(sample_validated_plan: ValidatedWitnessPlan) -> None:
    vault = TrustedWitnessVault()
    generator = WitnessGenerator(vault)
    record = generator.generate_and_seal_witness(sample_validated_plan)

    assert isinstance(record, SealedWitnessRecord)
    assert record.witness_id == "wit-gen-01"
    assert record.requirement_id == "REQ-TEST-01"
    assert len(record.artifacts) == 1
    assert record.artifacts[0].path == "tests/witness/test_boundary.py"
    assert vault.verify_witness_integrity(record) is True
    assert record.witness_id in vault.list_sealed_witness_ids()


def test_generate_rejects_builder_test_collision(
    sample_validated_plan: ValidatedWitnessPlan,
) -> None:
    vault = TrustedWitnessVault()
    generator = WitnessGenerator(vault)
    # Builder test has same name as witness artifact
    with pytest.raises(BuilderTestContaminationError, match="collides with Builder-authored test"):
        generator.generate_and_seal_witness(
            sample_validated_plan,
            known_builder_test_names=("test_boundary.py",),
        )


def test_generate_rejects_builder_test_import() -> None:
    vault = TrustedWitnessVault()
    generator = WitnessGenerator(vault)
    art = ValidatedWitnessArtifact(
        path="tests/witness/test_custom.py",
        content="import test_builder_suite\ndef test_wit():\n    assert True\n",
        content_digest="86bb088d89cb2551532c259bdaec463661eb175f82638848d28e08616198f24d",
        byte_size=63,
    )
    plan = ValidatedWitnessPlan(
        witness_id="wit-gen-02",
        requirement_id="REQ-TEST-01",
        frozen_contract_digest="0" * 64,
        source_commit_id="a" * 40,
        change_class=ChangeClass.BUG_FIX,
        plan_summary="Plan",
        target_files=(),
        artifacts=(art,),
        execution_command=("pytest",),
        expected_failure_at_base="f",
        expected_success_at_candidate="p",
        plan_digest="2" * 64,
    )
    with pytest.raises(BuilderTestContaminationError, match="imports Builder test"):
        generator.generate_and_seal_witness(
            plan,
            known_builder_test_names=("test_builder_suite",),
        )


def test_generate_rejects_non_bug_fix() -> None:
    vault = TrustedWitnessVault()
    generator = WitnessGenerator(vault)
    art = ValidatedWitnessArtifact(
        path="tests/witness/test_custom.py",
        content="def test_wit(): pass",
        content_digest="1" * 64,
        byte_size=20,
    )
    plan = ValidatedWitnessPlan(
        witness_id="wit-gen-03",
        requirement_id="REQ-TEST-01",
        frozen_contract_digest="0" * 64,
        source_commit_id="a" * 40,
        change_class=ChangeClass.PERFORMANCE,
        plan_summary="Plan",
        target_files=(),
        artifacts=(art,),
        execution_command=("pytest",),
        expected_failure_at_base="f",
        expected_success_at_candidate="p",
        plan_digest="3" * 64,
    )
    with pytest.raises(WitnessPlanScopeError, match="requires BUG_FIX"):
        generator.generate_and_seal_witness(plan)


def test_witness_generator_provider_purity() -> None:
    import basebreak.verifier.witness_generator as wg_mod

    source = inspect.getsource(wg_mod)
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("basebreak.adapters"), (
                    f"witness_generator must not import adapters: {alias.name}"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert not node.module.startswith("basebreak.adapters"), (
                    f"witness_generator must not import adapters: {node.module}"
                )
