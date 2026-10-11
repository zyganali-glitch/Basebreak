"""Production Verifier Trust Bridge.

Provides a tamper-evident cryptographic trust bridge between the isolated
verifier execution boundary and receiving applications.

Core Invariants:
1. Zero Caller Production Authority: Caller-created objects or in-process vaults
   possess ZERO production authority. Production authority resides strictly
   in the trusted verifier execution boundary backed by VerifierAuthorityRoot.
2. Verified Execution Origin: Production evidence must carry an authenticated
   issuer_id and verified execution_origin matching the evidence provenance.
3. Firsthand Observation: The trusted verifier directly materializes, executes,
   and records observations in fresh isolated sandboxes.
4. Cryptographic Fact Binding: Attestations bind requirement, contract digest,
   witness seal, source commit, candidate tree digest, sandbox IDs, result digests,
   outcomes, transition, verdict, and issuer.
5. Independent Verification: The receiving application independently validates
   attestations against the authority root. Self-signed or tampered claims fail closed.
6. Fail-Closed Integrity: Missing isolation, missing credentials, or unobserved claims
   yield explicit BLOCKED / NOT_RUN, never silent fallback to FIXTURE.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from basebreak.causal.materializer import CounterfactualMaterializationError
from basebreak.causal.receipt import (
    LocalCausalReceipt,
    WorldExecutionFact,
    create_causal_receipt,
    create_causal_triplet_receipt,
)
from basebreak.causal.reconciliation import (
    reconcile_causal_transition,
    reconcile_causal_triplet,
)
from basebreak.causal.semantic_receipt import SemanticVerificationReceipt
from basebreak.causal.subtraction import CounterfactualDeltaPlan
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.context import VerifierContextEnvelope
from basebreak.verifier.sandbox import (
    VerifierMaterializationError,
    VerifierSandboxManager,
    VerifierSandboxSession,
    VerifierTreeDigestMismatchError,
)
from basebreak.verifier.vacuity import (
    analyze_artifact_code_vacuity,
    analyze_runtime_execution_vacuity,
)
from basebreak.verifier.witness_lock import (
    ImmutableWitnessLock,
    verify_witness_lock_chain,
)
from basebreak.verifier.witness_result import (
    WitnessOutcome,
    normalize_witness_execution,
)
from basebreak.verifier.witness_store import (
    SealedWitnessRecord,
    TrustedWitnessVault,
    UntrustedWitnessAuthorityError,
    VerifierExecutionAttestation,
    WitnessIntegrityError,
    build_canonical_execution_attestation_payload,
    compute_attestation_digest,
)

_HEX_40_PATTERN = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


class VerifierExecutionOrigin(str, Enum):
    """Authenticated execution boundary origins for verifier execution."""

    LOCAL_CONTAINER_ISOLATED_RUNTIME = "LOCAL_CONTAINER_ISOLATED_RUNTIME"
    NEBIUS_TOKEN_FACTORY_SANDBOX = "NEBIUS_TOKEN_FACTORY_SANDBOX"
    IN_PROCESS_FIXTURE_RUNTIME = "IN_PROCESS_FIXTURE_RUNTIME"


class VerifierExecutionBlockedError(Exception):
    """Raised when verifier execution is blocked due to missing isolation or credentials."""


# Canonical authorized issuer IDs for the trusted verifier execution boundary
AUTHORIZED_LOCAL_ISSUER_ID: str = "basebreak:verifier:local:worker"
AUTHORIZED_NEBIUS_ISSUER_ID: str = "basebreak:verifier:nebius:worker"
AUTHORIZED_ISSUER_IDS: frozenset[str] = frozenset(
    {
        AUTHORIZED_LOCAL_ISSUER_ID,
        AUTHORIZED_NEBIUS_ISSUER_ID,
        "basebreak:verifier:production:root",
    }
)

# Pinned canonical verifier public key parameters (2048-bit RSA)
# Unprivileged verification interface uses only this public modulus and exponent.
# The corresponding private signing key is never in source code.
PINNED_VERIFIER_MODULUS_HEX: str = (
    "4d1423bbc38536be16220fe57c834df1cf9e86717d73da34d6c2f541fb324d08a1d02a1bd5921216"
    "445c6e9e9c9751531348da426b1bf7f849194c2bb4c971b92d49f3f58196abaeabb2bbdccca0310b"
    "88c3bb72c73368ef8bba5fffbf1ea004b6c7da5dee7c00e10d7a9aceffcb3bfd0781b6c4e7b02f3c"
    "754aaa55cd1aaeca55a6a7ceea6a11b9ebf4935e86a4802bd0ae3d47b724f07c30a99a8841597b02"
    "cf1c747f2ca04d4fac087f477c091c3964f4c871ffc0c3bac6da8e41abe94a79746eb6e1ef53b6f4"
    "f078c6ac991f7df4234c23d5a30a13cd88a027638d5afd61b3671f45c7ea5f8813140ec42acb93f3"
    "e290b92b2520bd6e2560fda96545353f"
)
PINNED_VERIFIER_EXPONENT: int = 65537
PINNED_VERIFIER_MODULUS: int = int(PINNED_VERIFIER_MODULUS_HEX, 16)


class _PrivilegedVerifierSigner:
    """Privileged signing boundary inside the isolated verifier execution runtime.

    Accessible strictly within the trusted verifier execution boundary.
    Never exposed to Builder, caller contexts, or unprivileged application code.
    """

    def __init__(
        self,
        *,
        private_key_d: int,
        modulus_n: int = PINNED_VERIFIER_MODULUS,
        authorized_issuers: frozenset[str] = AUTHORIZED_ISSUER_IDS,
    ) -> None:
        self._private_key_d = private_key_d
        self._modulus_n = modulus_n
        self.authorized_issuers = authorized_issuers

    @property
    def modulus(self) -> int:
        return self._modulus_n

    @property
    def exponent(self) -> int:
        return PINNED_VERIFIER_EXPONENT

    @classmethod
    def from_environment(cls) -> _PrivilegedVerifierSigner | None:
        """Load private signing key from secure environment if authorized."""
        raw_key = os.environ.get("BASEBREAK_VERIFIER_SIGNING_KEY", "").strip()
        if not raw_key:
            return None
        try:
            d_val = int(raw_key, 16)
            return cls(private_key_d=d_val)
        except Exception:
            return None

    @classmethod
    def create_ephemeral_pair(
        cls,
    ) -> tuple[_PrivilegedVerifierSigner, VerifierAuthorityRoot]:
        """Generate an isolated ephemeral signer and paired verifier for boundary testing."""
        import secrets

        def _is_prime(n: int, k: int = 10) -> bool:
            if n < 2:
                return False
            if n in (2, 3):
                return True
            if n % 2 == 0:
                return False
            r, s = 0, n - 1
            while s % 2 == 0:
                r += 1
                s //= 2
            for _ in range(k):
                a = secrets.randbelow(n - 4) + 2
                x = pow(a, s, n)
                if x in (1, n - 1):
                    continue
                for _ in range(r - 1):
                    x = pow(x, 2, n)
                    if x == n - 1:
                        break
                else:
                    return False
            return True

        def _gen_prime(bits: int) -> int:
            while True:
                candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
                if _is_prime(candidate):
                    return candidate

        p = _gen_prime(512)
        q = _gen_prime(512)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)

        signer = cls(private_key_d=d, modulus_n=n)
        verifier = VerifierAuthorityRoot(modulus=n, exponent=e)
        return signer, verifier

    def sign_attestation_digest(self, digest: str) -> str:
        """Sign attestation digest using private key."""
        digest_bytes = hashlib.sha256(digest.encode("utf-8")).digest()
        m_int = int.from_bytes(digest_bytes, "big")
        sig_int = pow(m_int, self._private_key_d, self._modulus_n)
        return hex(sig_int)[2:].zfill(256)

    def issue_production_attestation(
        self,
        *,
        issuer_id: str,
        execution_origin: str,
        requirement_id: str,
        frozen_contract_digest: str,
        witness_id: str,
        witness_digest: str,
        source_commit_id: str,
        candidate_tree_digest: str,
        base_outcome: WitnessOutcome,
        candidate_outcome: WitnessOutcome,
        counterfactual_outcome: WitnessOutcome | None = None,
        transition: Any,
        verdict: PreliminaryVerdict,
        provenance: EvidenceProvenance,
        created_at_utc: str | None = None,
        execution_command: Sequence[str] | str,
        base_sandbox_id: str,
        candidate_sandbox_id: str,
        counterfactual_sandbox_id: str | None = None,
        base_exit_code: int | None = None,
        candidate_exit_code: int | None = None,
        counterfactual_exit_code: int | None = None,
        base_termination_status: TerminationStatus | str | None = None,
        candidate_termination_status: TerminationStatus | str | None = None,
        counterfactual_termination_status: TerminationStatus | str | None = None,
        base_result_digest: str = "",
        candidate_result_digest: str = "",
        counterfactual_result_digest: str | None = None,
        base_stdout_digest: str = "",
        base_stderr_digest: str = "",
        candidate_stdout_digest: str = "",
        candidate_stderr_digest: str = "",
        counterfactual_stdout_digest: str | None = None,
        counterfactual_stderr_digest: str | None = None,
        base_tree_digest: str = "",
        counterfactual_tree_digest: str | None = None,
    ) -> VerifierExecutionAttestation:
        """Issue an authentic, cryptographically bound VerifierExecutionAttestation."""
        if provenance not in (
            EvidenceProvenance.LOCAL_EXECUTION,
            EvidenceProvenance.LIVE_NEBIUS,
            EvidenceProvenance.RECORDED_LIVE,
        ):
            raise UntrustedWitnessAuthorityError(
                "issue_production_attestation requires production provenance, "
                f"got {provenance.value}"
            )
        if issuer_id not in self.authorized_issuers:
            raise UntrustedWitnessAuthorityError(
                f"issuer_id {issuer_id!r} is not an authorized verifier authority issuer"
            )

        expected_origin = (
            VerifierExecutionOrigin.LOCAL_CONTAINER_ISOLATED_RUNTIME.value
            if provenance == EvidenceProvenance.LOCAL_EXECUTION
            else VerifierExecutionOrigin.NEBIUS_TOKEN_FACTORY_SANDBOX.value
        )
        if execution_origin != expected_origin:
            raise UntrustedWitnessAuthorityError(
                f"execution_origin {execution_origin!r} does not match "
                f"expected {expected_origin!r} for provenance {provenance.value}"
            )

        timestamp = created_at_utc or datetime.now(timezone.utc).isoformat()
        cmd_str = (
            " ".join(str(c) for c in execution_command)
            if isinstance(execution_command, (list, tuple))
            else str(execution_command or "").strip()
        )
        payload = build_canonical_execution_attestation_payload(
            requirement_id=requirement_id,
            frozen_contract_digest=frozen_contract_digest,
            witness_id=witness_id,
            witness_digest=witness_digest,
            source_commit_id=source_commit_id,
            candidate_tree_digest=candidate_tree_digest,
            base_outcome=base_outcome,
            candidate_outcome=candidate_outcome,
            counterfactual_outcome=counterfactual_outcome,
            transition=transition,
            verdict=verdict,
            provenance=provenance,
            created_at_utc=timestamp,
            issuer_id=issuer_id,
            execution_origin=execution_origin,
            execution_command=cmd_str,
            base_sandbox_id=base_sandbox_id,
            candidate_sandbox_id=candidate_sandbox_id,
            counterfactual_sandbox_id=counterfactual_sandbox_id,
            base_exit_code=base_exit_code,
            candidate_exit_code=candidate_exit_code,
            counterfactual_exit_code=counterfactual_exit_code,
            base_termination_status=base_termination_status,
            candidate_termination_status=candidate_termination_status,
            counterfactual_termination_status=counterfactual_termination_status,
            base_result_digest=base_result_digest,
            candidate_result_digest=candidate_result_digest,
            counterfactual_result_digest=counterfactual_result_digest,
            base_stdout_digest=base_stdout_digest,
            base_stderr_digest=base_stderr_digest,
            candidate_stdout_digest=candidate_stdout_digest,
            candidate_stderr_digest=candidate_stderr_digest,
            counterfactual_stdout_digest=counterfactual_stdout_digest,
            counterfactual_stderr_digest=counterfactual_stderr_digest,
            base_tree_digest=base_tree_digest,
            counterfactual_tree_digest=counterfactual_tree_digest,
        )
        att_digest = compute_attestation_digest(payload)
        sig = self.sign_attestation_digest(att_digest)

        return VerifierExecutionAttestation(
            requirement_id=requirement_id,
            frozen_contract_digest=frozen_contract_digest,
            witness_id=witness_id,
            witness_digest=witness_digest,
            source_commit_id=source_commit_id,
            candidate_tree_digest=candidate_tree_digest,
            base_outcome=base_outcome,
            candidate_outcome=candidate_outcome,
            counterfactual_outcome=counterfactual_outcome,
            transition=transition,
            verdict=verdict,
            provenance=provenance,
            attestation_digest=att_digest,
            vault_signature=sig,
            created_at_utc=timestamp,
            is_authoritative=True,
            issuer_id=issuer_id,
            execution_origin=execution_origin,
            execution_command=cmd_str,
            base_sandbox_id=base_sandbox_id,
            candidate_sandbox_id=candidate_sandbox_id,
            counterfactual_sandbox_id=counterfactual_sandbox_id,
            base_exit_code=base_exit_code,
            candidate_exit_code=candidate_exit_code,
            counterfactual_exit_code=counterfactual_exit_code,
            base_termination_status=(
                base_termination_status.value
                if base_termination_status is not None and hasattr(base_termination_status, "value")
                else (str(base_termination_status) if base_termination_status else None)
            ),
            candidate_termination_status=(
                candidate_termination_status.value
                if candidate_termination_status is not None
                and hasattr(candidate_termination_status, "value")
                else (str(candidate_termination_status) if candidate_termination_status else None)
            ),
            counterfactual_termination_status=(
                counterfactual_termination_status.value
                if counterfactual_termination_status is not None
                and hasattr(counterfactual_termination_status, "value")
                else (
                    str(counterfactual_termination_status)
                    if counterfactual_termination_status
                    else None
                )
            ),
            base_result_digest=base_result_digest,
            candidate_result_digest=candidate_result_digest,
            counterfactual_result_digest=counterfactual_result_digest,
            base_stdout_digest=base_stdout_digest,
            base_stderr_digest=base_stderr_digest,
            candidate_stdout_digest=candidate_stdout_digest,
            candidate_stderr_digest=candidate_stderr_digest,
            counterfactual_stdout_digest=counterfactual_stdout_digest,
            counterfactual_stderr_digest=counterfactual_stderr_digest,
            base_tree_digest=base_tree_digest,
            counterfactual_tree_digest=counterfactual_tree_digest,
        )


@dataclass(frozen=True, slots=True)
class VerifierAuthorityRoot:
    """Authority root maintaining independent, unprivileged verification keys.

    Zero signing authority: cannot issue or sign production attestations.
    Uses pinned public verification key to validate authentic verifier attestations.
    """

    modulus: int = PINNED_VERIFIER_MODULUS
    exponent: int = PINNED_VERIFIER_EXPONENT
    authorized_issuers: frozenset[str] = AUTHORIZED_ISSUER_IDS

    def verify_production_attestation(
        self,
        attestation: VerifierExecutionAttestation,
        receipt: LocalCausalReceipt | SemanticVerificationReceipt | None = None,
        expected_requirement_id: str | None = None,
        expected_contract_digest: str | None = None,
        expected_provenance: EvidenceProvenance | None = None,
    ) -> bool:
        """Independently verify an attestation against this authority root."""
        if attestation is None or not isinstance(attestation, VerifierExecutionAttestation):
            return False

        if not attestation.is_authoritative:
            return False

        # Reject fixture attestations through production verifier authority
        if attestation.provenance not in (
            EvidenceProvenance.LOCAL_EXECUTION,
            EvidenceProvenance.LIVE_NEBIUS,
            EvidenceProvenance.RECORDED_LIVE,
        ):
            return False

        if expected_provenance is not None and attestation.provenance != expected_provenance:
            return False

        # 1. Issuer check: Must be an authenticated issuer ID
        if not attestation.issuer_id or attestation.issuer_id not in self.authorized_issuers:
            return False

        # 2. Execution origin check
        expected_origin = (
            VerifierExecutionOrigin.LOCAL_CONTAINER_ISOLATED_RUNTIME.value
            if attestation.provenance == EvidenceProvenance.LOCAL_EXECUTION
            else VerifierExecutionOrigin.NEBIUS_TOKEN_FACTORY_SANDBOX.value
        )
        if attestation.execution_origin != expected_origin:
            return False

        # 3. Mandatory factual checks (sandbox isolation, commands, result digests)
        if not attestation.base_sandbox_id or not attestation.candidate_sandbox_id:
            return False
        if attestation.base_sandbox_id == attestation.candidate_sandbox_id:
            return False
        if not attestation.execution_command or not attestation.execution_command.strip():
            return False
        if not attestation.base_result_digest or not attestation.candidate_result_digest:
            return False

        # 4. Contextual binding checks
        if (
            expected_requirement_id is not None
            and attestation.requirement_id != expected_requirement_id
        ):
            return False
        if (
            expected_contract_digest is not None
            and attestation.frozen_contract_digest.lower() != expected_contract_digest.lower()
        ):
            return False

        # 5. Cryptographic signature verification against authority root
        payload = build_canonical_execution_attestation_payload(
            requirement_id=attestation.requirement_id,
            frozen_contract_digest=attestation.frozen_contract_digest,
            witness_id=attestation.witness_id,
            witness_digest=attestation.witness_digest,
            source_commit_id=attestation.source_commit_id,
            candidate_tree_digest=attestation.candidate_tree_digest,
            base_outcome=attestation.base_outcome,
            candidate_outcome=attestation.candidate_outcome,
            counterfactual_outcome=attestation.counterfactual_outcome,
            transition=attestation.transition,
            verdict=attestation.verdict,
            provenance=attestation.provenance,
            created_at_utc=attestation.created_at_utc,
            issuer_id=attestation.issuer_id,
            execution_origin=attestation.execution_origin,
            execution_command=attestation.execution_command,
            base_sandbox_id=attestation.base_sandbox_id,
            candidate_sandbox_id=attestation.candidate_sandbox_id,
            counterfactual_sandbox_id=attestation.counterfactual_sandbox_id,
            base_exit_code=attestation.base_exit_code,
            candidate_exit_code=attestation.candidate_exit_code,
            counterfactual_exit_code=attestation.counterfactual_exit_code,
            base_termination_status=attestation.base_termination_status,
            candidate_termination_status=attestation.candidate_termination_status,
            counterfactual_termination_status=attestation.counterfactual_termination_status,
            base_result_digest=attestation.base_result_digest,
            candidate_result_digest=attestation.candidate_result_digest,
            counterfactual_result_digest=attestation.counterfactual_result_digest,
            base_stdout_digest=attestation.base_stdout_digest,
            base_stderr_digest=attestation.base_stderr_digest,
            candidate_stdout_digest=attestation.candidate_stdout_digest,
            candidate_stderr_digest=attestation.candidate_stderr_digest,
            counterfactual_stdout_digest=attestation.counterfactual_stdout_digest,
            counterfactual_stderr_digest=attestation.counterfactual_stderr_digest,
            base_tree_digest=attestation.base_tree_digest,
            counterfactual_tree_digest=attestation.counterfactual_tree_digest,
        )
        expected_att_digest = compute_attestation_digest(payload)
        if attestation.attestation_digest != expected_att_digest:
            return False

        try:
            sig_int = int(attestation.vault_signature, 16)
            digest_bytes = hashlib.sha256(expected_att_digest.encode("utf-8")).digest()
            expected_m_int = int.from_bytes(digest_bytes, "big")
            recovered_m_int = pow(sig_int, self.exponent, self.modulus)
            if recovered_m_int != expected_m_int:
                return False
        except Exception:
            return False

        # 6. Cross-check against receipt if provided
        if receipt is not None:
            if receipt.requirement_id != attestation.requirement_id:
                return False
            if receipt.frozen_contract_digest.lower() != attestation.frozen_contract_digest.lower():
                return False
            if receipt.witness_id != attestation.witness_id:
                return False
            if receipt.witness_digest.lower() != attestation.witness_digest.lower():
                return False
            if receipt.provenance != attestation.provenance:
                return False
            if receipt.verdict != attestation.verdict:
                return False

            trans_str = (
                receipt.transition.value
                if hasattr(receipt.transition, "value")
                else str(receipt.transition)
            )
            att_trans_str = (
                attestation.transition.value
                if hasattr(attestation.transition, "value")
                else str(attestation.transition)
            )
            if trans_str != att_trans_str:
                return False

            # Verify base execution facts
            b_exec = getattr(receipt, "base_execution", None)
            if b_exec is not None:
                if b_exec.outcome != attestation.base_outcome:
                    return False
                if b_exec.source_commit_id.lower() != attestation.source_commit_id.lower():
                    return False
                if b_exec.sandbox_id != attestation.base_sandbox_id:
                    return False
                if b_exec.exit_code != attestation.base_exit_code:
                    return False
                if b_exec.result_digest.lower() != attestation.base_result_digest.lower():
                    return False
                b_term = (
                    b_exec.termination_status.value
                    if hasattr(b_exec.termination_status, "value")
                    else str(b_exec.termination_status)
                )
                if b_term != attestation.base_termination_status:
                    return False

            # Verify candidate execution facts
            c_exec = getattr(receipt, "candidate_execution", None)
            if c_exec is not None:
                if c_exec.outcome != attestation.candidate_outcome:
                    return False
                if c_exec.tree_digest.lower() != attestation.candidate_tree_digest.lower():
                    return False
                if c_exec.sandbox_id != attestation.candidate_sandbox_id:
                    return False
                if c_exec.exit_code != attestation.candidate_exit_code:
                    return False
                if c_exec.result_digest.lower() != attestation.candidate_result_digest.lower():
                    return False
                c_term = (
                    c_exec.termination_status.value
                    if hasattr(c_exec.termination_status, "value")
                    else str(c_exec.termination_status)
                )
                if c_term != attestation.candidate_termination_status:
                    return False

            # Verify counterfactual execution facts if present
            cf_exec = getattr(receipt, "counterfactual_execution", None)
            if cf_exec is not None and attestation.counterfactual_outcome is not None:
                if cf_exec.outcome != attestation.counterfactual_outcome:
                    return False
                if cf_exec.sandbox_id != attestation.counterfactual_sandbox_id:
                    return False
                if cf_exec.exit_code != attestation.counterfactual_exit_code:
                    return False
                if (
                    cf_exec.result_digest.lower()
                    != (attestation.counterfactual_result_digest or "").lower()
                ):
                    return False

        return True


_GLOBAL_AUTHORITY_ROOT = VerifierAuthorityRoot()


def get_default_verifier_authority_root() -> VerifierAuthorityRoot:
    """Return the canonical verifier authority root for independent verification."""
    return _GLOBAL_AUTHORITY_ROOT


def verify_trusted_production_evidence(
    *,
    receipt: LocalCausalReceipt | SemanticVerificationReceipt | None = None,
    attestation: VerifierExecutionAttestation | None = None,
    expected_requirement_id: str | None = None,
    expected_contract_digest: str | None = None,
    expected_provenance: EvidenceProvenance | None = None,
    verifier_authority: Any | None = None,
) -> bool:
    """Independently verify production execution evidence before accepting VERIFIED coverage.

    Called by compute_causal_coverage and TrustedWitnessVault.verify_execution_authority.
    """
    effective_att = attestation
    if effective_att is None and receipt is not None:
        effective_att = getattr(receipt, "attestation", None)

    if effective_att is None or not isinstance(effective_att, VerifierExecutionAttestation):
        return False

    root = (
        verifier_authority
        if isinstance(verifier_authority, VerifierAuthorityRoot)
        else get_default_verifier_authority_root()
    )
    return root.verify_production_attestation(
        attestation=effective_att,
        receipt=receipt,
        expected_requirement_id=expected_requirement_id,
        expected_contract_digest=expected_contract_digest,
        expected_provenance=expected_provenance,
    )


class TrustedVerifierWorker:
    """Separately controlled Verifier Execution Boundary for production causal verification.

    Initiates and directly observes isolated sandbox materialization, command execution,
    result collection, and cryptographic attestation.
    """

    def __init__(
        self,
        *,
        signer: _PrivilegedVerifierSigner | None = None,
    ) -> None:
        self._signer = signer or _PrivilegedVerifierSigner.from_environment()

    @property
    def authority_root(self) -> VerifierAuthorityRoot:
        if self._signer is not None:
            return VerifierAuthorityRoot(
                modulus=self._signer.modulus,
                exponent=self._signer.exponent,
                authorized_issuers=self._signer.authorized_issuers,
            )
        return get_default_verifier_authority_root()

    def execute_causal_pair(
        self,
        *,
        context_envelope: VerifierContextEnvelope,
        sealed_record: SealedWitnessRecord,
        witness_lock: ImmutableWitnessLock,
        execution_command: Sequence[str] | str,
        provenance: EvidenceProvenance,
        sandbox_manager: VerifierSandboxManager,
        sandbox_adapter: Any,
        materializer: Any,
        vault: TrustedWitnessVault,
    ) -> LocalCausalReceipt:
        """Execute identical witness across BASE and CANDIDATE in isolated sandboxes.

        Fails closed with VerifierExecutionBlockedError if required isolation is absent.
        """
        # 1. Pinned input validation
        if not isinstance(context_envelope, VerifierContextEnvelope):
            raise TypeError("context_envelope must be VerifierContextEnvelope")
        if not isinstance(sealed_record, SealedWitnessRecord):
            raise TypeError("sealed_record must be SealedWitnessRecord")
        if not isinstance(witness_lock, ImmutableWitnessLock):
            raise TypeError("witness_lock must be ImmutableWitnessLock")

        vault.verify_witness_integrity(sealed_record)
        verify_witness_lock_chain(
            lock=witness_lock,
            frozen_contract=context_envelope.frozen_contract,
            base_record=sealed_record,
            candidate_record=sealed_record,
        )

        if witness_lock.frozen_contract_digest != context_envelope.frozen_contract.contract_digest:
            raise WitnessIntegrityError("witness_lock contract digest mismatch")
        if witness_lock.source_commit_id != context_envelope.source_identity.resolved_commit_id:
            raise WitnessIntegrityError("witness_lock source commit mismatch")

        # 2. Runtime prerequisite checks
        if self._signer is None:
            raise VerifierExecutionBlockedError(
                "Trusted verifier signing authority is not available; "
                "missing trusted signer yields explicit BLOCKED/NOT_RUN."
            )

        from basebreak.causal.engine import (
            CausalExecutionEngine,
            is_genuine_local_sandbox_runtime,
            is_genuine_nebius_sandbox_adapter,
        )

        if provenance == EvidenceProvenance.LOCAL_EXECUTION:
            if not is_genuine_local_sandbox_runtime():
                raise VerifierExecutionBlockedError(
                    "LOCAL_EXECUTION requested but isolated local container runtime is "
                    "unavailable; missing isolation yields explicit BLOCKED/NOT_RUN."
                )
            if CausalExecutionEngine._is_mock_or_simulated(sandbox_adapter, materializer):
                raise VerifierExecutionBlockedError(
                    "LOCAL_EXECUTION requires genuine sandbox adapter; "
                    "mock/simulated adapter rejected."
                )
            issuer_id = AUTHORIZED_LOCAL_ISSUER_ID
            origin = VerifierExecutionOrigin.LOCAL_CONTAINER_ISOLATED_RUNTIME.value
        elif provenance == EvidenceProvenance.LIVE_NEBIUS:
            if not is_genuine_nebius_sandbox_adapter(sandbox_adapter):
                raise VerifierExecutionBlockedError(
                    "LIVE_NEBIUS requested but genuine Nebius sandbox adapter or credentials "
                    "are unavailable; missing credentials yields explicit BLOCKED/NOT_RUN."
                )
            if CausalExecutionEngine._is_mock_or_simulated(sandbox_adapter, materializer):
                raise VerifierExecutionBlockedError(
                    "LIVE_NEBIUS requires genuine sandbox adapter; mock/simulated adapter rejected."
                )
            issuer_id = AUTHORIZED_NEBIUS_ISSUER_ID
            origin = VerifierExecutionOrigin.NEBIUS_TOKEN_FACTORY_SANDBOX.value
        else:
            raise VerifierExecutionBlockedError(
                "TrustedVerifierWorker cannot execute non-production provenance: "
                f"{provenance.value}"
            )

        # 3. Fresh isolated sandbox executions for BASE and CANDIDATE
        # Execute BASE world
        base_session = sandbox_manager.create_isolated_verifier_sandbox(
            context_envelope=context_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=sandbox_adapter,
            materializer=materializer,
            provenance=provenance,
        )
        try:
            self._deploy_witness_artifacts(
                sandbox_adapter=sandbox_adapter,
                session=base_session,
                sealed_record=sealed_record,
            )
            base_exit, base_term, base_out, base_err, base_dur = self._execute_command_in_sandbox(
                sandbox_adapter=sandbox_adapter,
                session=base_session,
                command=execution_command,
                timeout_seconds=context_envelope.execution_policy.timeout_seconds,
            )
            base_norm = normalize_witness_execution(
                witness_id=sealed_record.witness_id,
                witness_digest=sealed_record.seal_digest,
                frozen_contract_digest=sealed_record.frozen_contract_digest,
                requirement_id=sealed_record.requirement_id,
                sandbox_identity=base_session.sandbox_identity,
                source_commit_id=base_session.materialized_commit_id,
                world=ExecutionWorld.BASE,
                status=base_term,
                exit_code=base_exit,
                stdout_raw=base_out,
                stderr_raw=base_err,
                duration_seconds=base_dur,
                provenance=provenance,
                max_output_bytes=context_envelope.execution_policy.max_output_bytes,
            )
            base_code_vac = analyze_artifact_code_vacuity(sealed_record.artifacts)
            base_vac = analyze_runtime_execution_vacuity(base_norm, base_code_vac)
        finally:
            sandbox_manager._teardown_sandbox(sandbox_adapter, base_session.sandbox_identity)

        # Execute CANDIDATE world in a freshly created sandbox
        cand_session = sandbox_manager.create_isolated_verifier_sandbox(
            context_envelope=context_envelope,
            world=ExecutionWorld.CANDIDATE,
            sandbox_adapter=sandbox_adapter,
            materializer=materializer,
            candidate_tree_digest=context_envelope.candidate_tree_digest,
            provenance=provenance,
        )
        try:
            self._deploy_witness_artifacts(
                sandbox_adapter=sandbox_adapter,
                session=cand_session,
                sealed_record=sealed_record,
            )
            cand_exit, cand_term, cand_out, cand_err, cand_dur = self._execute_command_in_sandbox(
                sandbox_adapter=sandbox_adapter,
                session=cand_session,
                command=execution_command,
                timeout_seconds=context_envelope.execution_policy.timeout_seconds,
            )
            cand_norm = normalize_witness_execution(
                witness_id=sealed_record.witness_id,
                witness_digest=sealed_record.seal_digest,
                frozen_contract_digest=sealed_record.frozen_contract_digest,
                requirement_id=sealed_record.requirement_id,
                sandbox_identity=cand_session.sandbox_identity,
                source_commit_id=cand_session.materialized_commit_id,
                world=ExecutionWorld.CANDIDATE,
                status=cand_term,
                exit_code=cand_exit,
                stdout_raw=cand_out,
                stderr_raw=cand_err,
                duration_seconds=cand_dur,
                provenance=provenance,
                max_output_bytes=context_envelope.execution_policy.max_output_bytes,
            )
            cand_code_vac = analyze_artifact_code_vacuity(sealed_record.artifacts)
            cand_vac = analyze_runtime_execution_vacuity(cand_norm, cand_code_vac)
        finally:
            sandbox_manager._teardown_sandbox(sandbox_adapter, cand_session.sandbox_identity)

        # 4. Integrity and cryptographic binding verification
        integrity_failure: str | None = None
        if base_norm.witness_digest != sealed_record.seal_digest:
            integrity_failure = "BASE witness digest mismatch"
        elif cand_norm.witness_digest != sealed_record.seal_digest:
            integrity_failure = "CANDIDATE witness digest mismatch"
        elif base_session.sandbox_identity.sandbox_id == cand_session.sandbox_identity.sandbox_id:
            integrity_failure = "BASE and CANDIDATE reused the same sandbox identity"
        elif (
            base_session.materialized_tree_digest.lower()
            == cand_session.materialized_tree_digest.lower()
        ):
            integrity_failure = (
                "Candidate tree digest is identical to base tree digest (empty patch)"
            )

        reconciliation = reconcile_causal_transition(
            base_outcome=base_norm.outcome,
            candidate_outcome=cand_norm.outcome,
            base_vacuity=base_vac,
            candidate_vacuity=cand_vac,
            integrity_failure_reason=integrity_failure,
        )

        base_fact = WorldExecutionFact.from_normalized_result(
            base_norm, tree_digest=base_session.materialized_tree_digest
        )
        cand_fact = WorldExecutionFact.from_normalized_result(
            cand_norm, tree_digest=cand_session.materialized_tree_digest
        )

        # 5. Issue authentic VerifierExecutionAttestation from signer
        attestation = self._signer.issue_production_attestation(
            issuer_id=issuer_id,
            execution_origin=origin,
            requirement_id=sealed_record.requirement_id,
            frozen_contract_digest=sealed_record.frozen_contract_digest,
            witness_id=sealed_record.witness_id,
            witness_digest=sealed_record.seal_digest,
            source_commit_id=context_envelope.source_identity.resolved_commit_id,
            candidate_tree_digest=cand_session.materialized_tree_digest,
            base_outcome=base_norm.outcome,
            candidate_outcome=cand_norm.outcome,
            transition=reconciliation.transition,
            verdict=reconciliation.verdict,
            provenance=provenance,
            execution_command=execution_command,
            base_sandbox_id=base_session.sandbox_identity.sandbox_id,
            candidate_sandbox_id=cand_session.sandbox_identity.sandbox_id,
            base_exit_code=base_exit,
            candidate_exit_code=cand_exit,
            base_termination_status=base_term,
            candidate_termination_status=cand_term,
            base_result_digest=base_norm.result_digest,
            candidate_result_digest=cand_norm.result_digest,
            base_stdout_digest=base_norm.stdout_digest,
            base_stderr_digest=base_norm.stderr_digest,
            candidate_stdout_digest=cand_norm.stdout_digest,
            candidate_stderr_digest=cand_norm.stderr_digest,
            base_tree_digest=base_session.materialized_tree_digest,
        )

        # 6. Emits verifiable LocalCausalReceipt
        return create_causal_receipt(
            requirement_id=sealed_record.requirement_id,
            frozen_contract_digest=sealed_record.frozen_contract_digest,
            witness_id=sealed_record.witness_id,
            witness_digest=sealed_record.seal_digest,
            lock_digest=witness_lock.lock_digest,
            base_execution=base_fact,
            candidate_execution=cand_fact,
            transition=reconciliation.transition,
            verdict=reconciliation.verdict,
            provenance=provenance,
            narrative=reconciliation.rationale,
            attestation=attestation,
        )

    def execute_causal_triplet(
        self,
        *,
        context_envelope: VerifierContextEnvelope,
        sealed_record: SealedWitnessRecord,
        witness_lock: ImmutableWitnessLock,
        counterfactual_plan: CounterfactualDeltaPlan,
        execution_command: Sequence[str] | str,
        provenance: EvidenceProvenance,
        sandbox_manager: VerifierSandboxManager,
        sandbox_adapter: Any,
        materializer: Any,
        vault: TrustedWitnessVault,
    ) -> LocalCausalReceipt:
        """Execute identical witness across BASE, CANDIDATE, and COUNTERFACTUAL worlds.

        Fails closed with VerifierExecutionBlockedError if required isolation is absent.
        """
        # 1. Pinned input validation
        if not isinstance(context_envelope, VerifierContextEnvelope):
            raise TypeError("context_envelope must be VerifierContextEnvelope")
        if not isinstance(sealed_record, SealedWitnessRecord):
            raise TypeError("sealed_record must be SealedWitnessRecord")
        if not isinstance(witness_lock, ImmutableWitnessLock):
            raise TypeError("witness_lock must be ImmutableWitnessLock")
        if not isinstance(counterfactual_plan, CounterfactualDeltaPlan):
            raise TypeError("counterfactual_plan must be CounterfactualDeltaPlan")

        vault.verify_witness_integrity(sealed_record)
        verify_witness_lock_chain(
            lock=witness_lock,
            frozen_contract=context_envelope.frozen_contract,
            base_record=sealed_record,
            candidate_record=sealed_record,
        )

        if witness_lock.frozen_contract_digest != context_envelope.frozen_contract.contract_digest:
            raise WitnessIntegrityError("witness_lock contract digest mismatch")
        if witness_lock.source_commit_id != context_envelope.source_identity.resolved_commit_id:
            raise WitnessIntegrityError("witness_lock source commit mismatch")

        if (
            counterfactual_plan.frozen_contract_digest
            != context_envelope.frozen_contract.contract_digest
        ):
            raise WitnessIntegrityError(
                "counterfactual_plan frozen_contract_digest does not match context envelope"
            )
        if counterfactual_plan.sealed_witness_digest != sealed_record.seal_digest:
            raise WitnessIntegrityError(
                "counterfactual_plan sealed_witness_digest does not match sealed record"
            )
        if (
            counterfactual_plan.source_commit_id
            != context_envelope.source_identity.resolved_commit_id
        ):
            raise WitnessIntegrityError(
                "counterfactual_plan source_commit_id does not match context envelope"
            )

        # 2. Runtime prerequisite checks
        if self._signer is None:
            raise VerifierExecutionBlockedError(
                "Trusted verifier signing authority is not available; "
                "missing trusted signer yields explicit BLOCKED/NOT_RUN."
            )

        from basebreak.causal.engine import (
            CausalExecutionEngine,
            is_genuine_local_sandbox_runtime,
            is_genuine_nebius_sandbox_adapter,
        )

        if provenance == EvidenceProvenance.LOCAL_EXECUTION:
            if not is_genuine_local_sandbox_runtime():
                raise VerifierExecutionBlockedError(
                    "LOCAL_EXECUTION requested but isolated local container runtime is "
                    "unavailable; missing isolation yields explicit BLOCKED/NOT_RUN."
                )
            if CausalExecutionEngine._is_mock_or_simulated(sandbox_adapter, materializer):
                raise VerifierExecutionBlockedError(
                    "LOCAL_EXECUTION requires genuine sandbox adapter; "
                    "mock/simulated adapter rejected."
                )
            issuer_id = AUTHORIZED_LOCAL_ISSUER_ID
            origin = VerifierExecutionOrigin.LOCAL_CONTAINER_ISOLATED_RUNTIME.value
        elif provenance == EvidenceProvenance.LIVE_NEBIUS:
            if not is_genuine_nebius_sandbox_adapter(sandbox_adapter):
                raise VerifierExecutionBlockedError(
                    "LIVE_NEBIUS requested but genuine Nebius sandbox adapter or credentials "
                    "are unavailable; missing credentials yields explicit BLOCKED/NOT_RUN."
                )
            if CausalExecutionEngine._is_mock_or_simulated(sandbox_adapter, materializer):
                raise VerifierExecutionBlockedError(
                    "LIVE_NEBIUS requires genuine sandbox adapter; mock/simulated adapter rejected."
                )
            issuer_id = AUTHORIZED_NEBIUS_ISSUER_ID
            origin = VerifierExecutionOrigin.NEBIUS_TOKEN_FACTORY_SANDBOX.value
        else:
            raise VerifierExecutionBlockedError(
                "TrustedVerifierWorker cannot execute non-production provenance: "
                f"{provenance.value}"
            )

        # 3. Fresh isolated sandbox executions for BASE, CANDIDATE, and COUNTERFACTUAL
        # Execute BASE world
        base_session = sandbox_manager.create_isolated_verifier_sandbox(
            context_envelope=context_envelope,
            world=ExecutionWorld.BASE,
            sandbox_adapter=sandbox_adapter,
            materializer=materializer,
            provenance=provenance,
        )
        try:
            self._deploy_witness_artifacts(
                sandbox_adapter=sandbox_adapter,
                session=base_session,
                sealed_record=sealed_record,
            )
            base_exit, base_term, base_out, base_err, base_dur = self._execute_command_in_sandbox(
                sandbox_adapter=sandbox_adapter,
                session=base_session,
                command=execution_command,
                timeout_seconds=context_envelope.execution_policy.timeout_seconds,
            )
            base_norm = normalize_witness_execution(
                witness_id=sealed_record.witness_id,
                witness_digest=sealed_record.seal_digest,
                frozen_contract_digest=sealed_record.frozen_contract_digest,
                requirement_id=sealed_record.requirement_id,
                sandbox_identity=base_session.sandbox_identity,
                source_commit_id=base_session.materialized_commit_id,
                world=ExecutionWorld.BASE,
                status=base_term,
                exit_code=base_exit,
                stdout_raw=base_out,
                stderr_raw=base_err,
                duration_seconds=base_dur,
                provenance=provenance,
                max_output_bytes=context_envelope.execution_policy.max_output_bytes,
            )
            base_code_vac = analyze_artifact_code_vacuity(sealed_record.artifacts)
            base_vac = analyze_runtime_execution_vacuity(base_norm, base_code_vac)
        finally:
            sandbox_manager._teardown_sandbox(sandbox_adapter, base_session.sandbox_identity)

        # Execute CANDIDATE world in a freshly created sandbox
        cand_session = sandbox_manager.create_isolated_verifier_sandbox(
            context_envelope=context_envelope,
            world=ExecutionWorld.CANDIDATE,
            sandbox_adapter=sandbox_adapter,
            materializer=materializer,
            candidate_tree_digest=context_envelope.candidate_tree_digest,
            provenance=provenance,
        )
        try:
            self._deploy_witness_artifacts(
                sandbox_adapter=sandbox_adapter,
                session=cand_session,
                sealed_record=sealed_record,
            )
            cand_exit, cand_term, cand_out, cand_err, cand_dur = self._execute_command_in_sandbox(
                sandbox_adapter=sandbox_adapter,
                session=cand_session,
                command=execution_command,
                timeout_seconds=context_envelope.execution_policy.timeout_seconds,
            )
            cand_norm = normalize_witness_execution(
                witness_id=sealed_record.witness_id,
                witness_digest=sealed_record.seal_digest,
                frozen_contract_digest=sealed_record.frozen_contract_digest,
                requirement_id=sealed_record.requirement_id,
                sandbox_identity=cand_session.sandbox_identity,
                source_commit_id=cand_session.materialized_commit_id,
                world=ExecutionWorld.CANDIDATE,
                status=cand_term,
                exit_code=cand_exit,
                stdout_raw=cand_out,
                stderr_raw=cand_err,
                duration_seconds=cand_dur,
                provenance=provenance,
                max_output_bytes=context_envelope.execution_policy.max_output_bytes,
            )
            cand_code_vac = analyze_artifact_code_vacuity(sealed_record.artifacts)
            cand_vac = analyze_runtime_execution_vacuity(cand_norm, cand_code_vac)
        finally:
            sandbox_manager._teardown_sandbox(sandbox_adapter, cand_session.sandbox_identity)

        # Execute COUNTERFACTUAL world in a fresh isolated sandbox
        cf_session = None
        cf_norm = None
        cf_vac = None
        invalid_cf_reason: str | None = None
        try:
            cf_session = sandbox_manager.create_isolated_verifier_sandbox(
                context_envelope=context_envelope,
                world=ExecutionWorld.COUNTERFACTUAL,
                sandbox_adapter=sandbox_adapter,
                materializer=materializer,
                counterfactual_plan=counterfactual_plan,
                provenance=provenance,
            )
            try:
                self._deploy_witness_artifacts(
                    sandbox_adapter=sandbox_adapter,
                    session=cf_session,
                    sealed_record=sealed_record,
                )
                cf_exit, cf_term, cf_out, cf_err, cf_dur = self._execute_command_in_sandbox(
                    sandbox_adapter=sandbox_adapter,
                    session=cf_session,
                    command=execution_command,
                    timeout_seconds=context_envelope.execution_policy.timeout_seconds,
                )
                cf_norm = normalize_witness_execution(
                    witness_id=sealed_record.witness_id,
                    witness_digest=sealed_record.seal_digest,
                    frozen_contract_digest=sealed_record.frozen_contract_digest,
                    requirement_id=sealed_record.requirement_id,
                    sandbox_identity=cf_session.sandbox_identity,
                    source_commit_id=cf_session.materialized_commit_id,
                    world=ExecutionWorld.COUNTERFACTUAL,
                    status=cf_term,
                    exit_code=cf_exit,
                    stdout_raw=cf_out,
                    stderr_raw=cf_err,
                    duration_seconds=cf_dur,
                    provenance=provenance,
                    max_output_bytes=context_envelope.execution_policy.max_output_bytes,
                )
                cf_code_vac = analyze_artifact_code_vacuity(sealed_record.artifacts)
                cf_vac = analyze_runtime_execution_vacuity(cf_norm, cf_code_vac)
            finally:
                sandbox_manager._teardown_sandbox(sandbox_adapter, cf_session.sandbox_identity)
        except (
            CounterfactualMaterializationError,
            VerifierMaterializationError,
            VerifierTreeDigestMismatchError,
        ) as exc:
            invalid_cf_reason = f"Counterfactual materialization failed: {exc}"

        # 4. Integrity and cryptographic binding verification
        integrity_failure: str | None = None
        if base_norm.witness_digest != sealed_record.seal_digest:
            integrity_failure = "BASE witness digest mismatch"
        elif cand_norm.witness_digest != sealed_record.seal_digest:
            integrity_failure = "CANDIDATE witness digest mismatch"
        elif cf_norm is not None and cf_norm.witness_digest != sealed_record.seal_digest:
            integrity_failure = "COUNTERFACTUAL witness digest mismatch"
        elif (
            base_session.materialized_tree_digest.lower()
            == cand_session.materialized_tree_digest.lower()
        ):
            integrity_failure = (
                "Candidate tree digest is identical to base tree digest (empty patch)"
            )

        if cf_session is not None and invalid_cf_reason is None:
            if (
                cf_session.materialized_tree_digest.lower()
                == cand_session.materialized_tree_digest.lower()
            ):
                invalid_cf_reason = (
                    "Counterfactual tree is identical to candidate tree "
                    "(subtraction had zero effect)"
                )

        cf_outcome = cf_norm.outcome if cf_norm is not None else WitnessOutcome.ERROR
        reconciliation = reconcile_causal_triplet(
            base_outcome=base_norm.outcome,
            candidate_outcome=cand_norm.outcome,
            counterfactual_outcome=cf_outcome,
            base_vacuity=base_vac,
            candidate_vacuity=cand_vac,
            counterfactual_vacuity=cf_vac,
            integrity_failure_reason=integrity_failure,
            invalid_counterfactual_reason=invalid_cf_reason,
        )

        base_fact = WorldExecutionFact.from_normalized_result(
            base_norm, tree_digest=base_session.materialized_tree_digest
        )
        cand_fact = WorldExecutionFact.from_normalized_result(
            cand_norm, tree_digest=cand_session.materialized_tree_digest
        )
        cf_fact = (
            WorldExecutionFact.from_normalized_result(
                cf_norm, tree_digest=cf_session.materialized_tree_digest
            )
            if cf_session is not None and cf_norm is not None
            else None
        )

        # 5. Issue authentic VerifierExecutionAttestation from signer
        attestation = self._signer.issue_production_attestation(
            issuer_id=issuer_id,
            execution_origin=origin,
            requirement_id=sealed_record.requirement_id,
            frozen_contract_digest=sealed_record.frozen_contract_digest,
            witness_id=sealed_record.witness_id,
            witness_digest=sealed_record.seal_digest,
            source_commit_id=context_envelope.source_identity.resolved_commit_id,
            candidate_tree_digest=cand_session.materialized_tree_digest,
            base_outcome=base_norm.outcome,
            candidate_outcome=cand_norm.outcome,
            counterfactual_outcome=cf_outcome if cf_session is not None else None,
            transition=reconciliation.transition,
            verdict=reconciliation.verdict,
            provenance=provenance,
            execution_command=execution_command,
            base_sandbox_id=base_session.sandbox_identity.sandbox_id,
            candidate_sandbox_id=cand_session.sandbox_identity.sandbox_id,
            counterfactual_sandbox_id=(
                cf_session.sandbox_identity.sandbox_id if cf_session is not None else None
            ),
            base_exit_code=base_exit,
            candidate_exit_code=cand_exit,
            counterfactual_exit_code=cf_exit if cf_session is not None else None,
            base_termination_status=base_term,
            candidate_termination_status=cand_term,
            counterfactual_termination_status=cf_term if cf_session is not None else None,
            base_result_digest=base_norm.result_digest,
            candidate_result_digest=cand_norm.result_digest,
            counterfactual_result_digest=cf_norm.result_digest if cf_norm is not None else None,
            base_stdout_digest=base_norm.stdout_digest,
            base_stderr_digest=base_norm.stderr_digest,
            candidate_stdout_digest=cand_norm.stdout_digest,
            candidate_stderr_digest=cand_norm.stderr_digest,
            counterfactual_stdout_digest=cf_norm.stdout_digest if cf_norm is not None else None,
            counterfactual_stderr_digest=cf_norm.stderr_digest if cf_norm is not None else None,
            base_tree_digest=base_session.materialized_tree_digest,
            counterfactual_tree_digest=(
                cf_session.materialized_tree_digest if cf_session is not None else None
            ),
        )

        # 6. Emits verifiable LocalCausalReceipt
        return create_causal_triplet_receipt(
            requirement_id=sealed_record.requirement_id,
            frozen_contract_digest=sealed_record.frozen_contract_digest,
            witness_id=sealed_record.witness_id,
            witness_digest=sealed_record.seal_digest,
            lock_digest=witness_lock.lock_digest,
            base_execution=base_fact,
            candidate_execution=cand_fact,
            counterfactual_execution=cf_fact,
            counterfactual_id=counterfactual_plan.counterfactual_id,
            delta_digest=counterfactual_plan.subtracted_delta_digest,
            transition=reconciliation.transition,
            verdict=reconciliation.verdict,
            provenance=provenance,
            narrative=reconciliation.rationale,
            attestation=attestation,
        )

    @staticmethod
    def _deploy_witness_artifacts(
        *,
        sandbox_adapter: Any,
        session: VerifierSandboxSession,
        sealed_record: SealedWitnessRecord,
    ) -> None:
        import base64
        import posixpath
        import shlex

        clean_ws = session.workspace_path.rstrip("/")
        lines = ["set -e", f"cd {shlex.quote(clean_ws)}"]
        for art in sealed_record.artifacts:
            art_posix = art.path.replace("\\", "/").lstrip("/")
            full_path = f"{clean_ws}/{art_posix}"
            parent_dir = posixpath.dirname(full_path)
            b64_content = base64.b64encode(art.content.encode("utf-8")).decode("ascii")
            lines.append(f"mkdir -p {shlex.quote(parent_dir)}")
            lines.append(
                f'printf "%s" {shlex.quote(b64_content)} | base64 -d > {shlex.quote(full_path)}'
            )
        script = "\n".join(lines) + "\n"
        res = sandbox_adapter.execute_command(
            session.sandbox_identity, script, working_dir=session.workspace_path, timeout_seconds=60
        )
        exit_code = getattr(res, "exit_code", None)
        if exit_code is None and hasattr(res, "result"):
            exit_code = getattr(res.result, "exit_code", None)
        if exit_code != 0:
            stderr = getattr(res, "stderr", "") or ""
            raise UntrustedWitnessAuthorityError(f"Failed to deploy witness artifacts: {stderr}")

    @staticmethod
    def _execute_command_in_sandbox(
        *,
        sandbox_adapter: Any,
        session: VerifierSandboxSession,
        command: Sequence[str] | str,
        timeout_seconds: int,
    ) -> tuple[int | None, TerminationStatus, str, str, float]:
        import shlex
        import time

        cmd_str = (
            " ".join(shlex.quote(c) for c in command)
            if isinstance(command, (list, tuple))
            else str(command)
        )
        t0 = time.perf_counter()
        try:
            res = sandbox_adapter.execute_command(
                session.sandbox_identity,
                cmd_str,
                working_dir=session.workspace_path,
                timeout_seconds=timeout_seconds,
            )
            elapsed = time.perf_counter() - t0
        except Exception as exc:
            elapsed = time.perf_counter() - t0
            exc_str = str(exc).lower()
            if "timeout" in exc_str:
                return None, TerminationStatus.TIMED_OUT, "", str(exc), elapsed
            return None, TerminationStatus.COMPLETED, "", str(exc), elapsed

        exit_code = getattr(res, "exit_code", None)
        if exit_code is None and hasattr(res, "result"):
            exit_code = getattr(res.result, "exit_code", None)

        stdout = getattr(res, "stdout", "") or ""
        stderr = getattr(res, "stderr", "") or ""

        term_status = TerminationStatus.COMPLETED
        if getattr(res, "is_timed_out", False):
            term_status = TerminationStatus.TIMED_OUT
        elif getattr(res, "is_cancelled", False):
            term_status = TerminationStatus.CANCELLED
        elif getattr(res, "is_failed_to_start", False):
            term_status = TerminationStatus.FAILED_TO_START

        duration = getattr(res, "duration_seconds", None)
        if duration is None or not isinstance(duration, (int, float)):
            duration = elapsed

        return exit_code, term_status, stdout, stderr, float(duration)
