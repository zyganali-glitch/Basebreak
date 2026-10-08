"""Deterministic SECURITY_FIX verification semantics: EXPLOITABLE -> BLOCKED.

P-13.02: SECURITY_FIX EXPLOITABLE->BLOCKED verifier.

Core Invariants:
1. Invariant truth: Under SECURITY_FIX, the ONLY positive transition is:
   BASE = EXPLOITABLE, CANDIDATE = BLOCKED (with legitimate behavior preserved)
   -> SECURITY_FIX_VERIFIED (PreliminaryVerdict.VERIFIED).
2. Anti-collapse:
   - Crashes, segfaults, unhandled exceptions, timeouts, and infrastructure errors
     must NEVER be treated as BLOCKED.
   - BASE=BLOCKED, CANDIDATE=BLOCKED -> UNVERIFIED_VULNERABILITY_NOT_REPRODUCED (INCONCLUSIVE).
   - BASE=EXPLOITABLE, CANDIDATE=EXPLOITABLE -> UNVERIFIED_EXPLOIT_PERSISTS (CONTRADICTED).
   - Exploit blocked BUT legitimate behavior broken -> UNVERIFIED_SECURITY_FIX_REGRESSION
     (CONTRADICTED).
3. Bounded exploit condition: The security witness safely demonstrates the bounded exploit
   condition without causing uncontrolled damage.
4. Preserved legitimate behavior: The candidate must block the exploit while preserving
   contract-required legitimate functionality.
5. Frozen contract authority: The contract must be frozen as ChangeClass.SECURITY_FIX;
   mismatched change-class invocation fails closed with ChangeClassMismatchError.
6. Zero model authority: Model explanations never override deterministic execution facts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from basebreak.causal.receipt import WorldExecutionFact
from basebreak.causal.reconciliation import (
    CausalTransition,
    ChangeClassMismatchError,
    ReconciliationFact,
)
from basebreak.causal.semantic_receipt import (
    SemanticVerificationReceipt,
    create_semantic_receipt,
)
from basebreak.compiler.freeze import FrozenContract
from basebreak.domain.causal import ExecutionWorld
from basebreak.domain.execution import TerminationStatus
from basebreak.domain.semantics import ChangeClass
from basebreak.domain.verdict import EvidenceProvenance, PreliminaryVerdict
from basebreak.verifier.context import VerifierContextEnvelope
from basebreak.verifier.vacuity import VacuityCheckResult
from basebreak.verifier.witness_lock import (
    ImmutableWitnessLock,
    verify_witness_lock_chain,
)
from basebreak.verifier.witness_result import NormalizedWitnessResult, WitnessOutcome
from basebreak.verifier.witness_store import SealedWitnessRecord


class SecurityState(str, Enum):
    """Deterministic observed security state of an execution world."""

    EXPLOITABLE = "EXPLOITABLE"
    BLOCKED = "BLOCKED"
    CRASH = "CRASH"
    TIMEOUT = "TIMEOUT"
    UNRELATED_EXCEPTION = "UNRELATED_EXCEPTION"
    INFRASTRUCTURE_FAILURE = "INFRASTRUCTURE_FAILURE"
    INVALID_PRECONDITION = "INVALID_PRECONDITION"


class SecurityBlockingMechanism(str, Enum):
    """Recognized mechanisms by which an exploit is cleanly and safely blocked."""

    AUTH_REJECTED = "AUTH_REJECTED"
    INPUT_VALIDATION_ERROR = "INPUT_VALIDATION_ERROR"
    SANITIZED_OUTPUT = "SANITIZED_OUTPUT"
    CAPABILITY_RESTRICTED = "CAPABILITY_RESTRICTED"
    CUSTOM_SECURITY_POLICY = "CUSTOM_SECURITY_POLICY"


_BLOCKING_PATTERNS: dict[SecurityBlockingMechanism, list[re.Pattern[str]]] = {
    SecurityBlockingMechanism.AUTH_REJECTED: [
        re.compile(r"401 Unauthorized", re.IGNORECASE),
        re.compile(r"403 Forbidden", re.IGNORECASE),
        re.compile(r"PermissionDenied", re.IGNORECASE),
        re.compile(r"AuthenticationFailed", re.IGNORECASE),
        re.compile(r"AccessDenied", re.IGNORECASE),
        re.compile(r"UnauthorizedError", re.IGNORECASE),
    ],
    SecurityBlockingMechanism.INPUT_VALIDATION_ERROR: [
        re.compile(r"400 Bad Request", re.IGNORECASE),
        re.compile(r"ValidationError", re.IGNORECASE),
        re.compile(r"SecurityValidationError", re.IGNORECASE),
        re.compile(r"InvalidInputError", re.IGNORECASE),
        re.compile(r"illegal argument", re.IGNORECASE),
        re.compile(r"dangerous character detected", re.IGNORECASE),
    ],
    SecurityBlockingMechanism.SANITIZED_OUTPUT: [
        re.compile(r"EXPLOIT_PAYLOAD_SANITIZED", re.IGNORECASE),
        re.compile(r"HTML_ESCAPED", re.IGNORECASE),
        re.compile(r"SANITIZED", re.IGNORECASE),
    ],
    SecurityBlockingMechanism.CAPABILITY_RESTRICTED: [
        re.compile(r"PathTraversalBlocked", re.IGNORECASE),
        re.compile(r"path traversal detected", re.IGNORECASE),
        re.compile(r"directory traversal forbidden", re.IGNORECASE),
        re.compile(r"privilege escalation prevented", re.IGNORECASE),
    ],
    SecurityBlockingMechanism.CUSTOM_SECURITY_POLICY: [
        re.compile(r"SECURITY_BLOCKED", re.IGNORECASE),
        re.compile(r"EXPLOIT_REJECTED", re.IGNORECASE),
        re.compile(r"SECURITY_POLICY_VIOLATION", re.IGNORECASE),
    ],
}

_CRASH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"segmentation fault", re.IGNORECASE),
    re.compile(r"core dumped", re.IGNORECASE),
    re.compile(r"fatal error", re.IGNORECASE),
    re.compile(r"SIGSEGV", re.IGNORECASE),
    re.compile(r"SIGABRT", re.IGNORECASE),
    re.compile(r"SIGILL", re.IGNORECASE),
    re.compile(r"StackOverflow", re.IGNORECASE),
]

_UNRELATED_EXCEPTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ZeroDivisionError", re.IGNORECASE),
    re.compile(r"IndexError: list index out of range", re.IGNORECASE),
    re.compile(r"KeyError:", re.IGNORECASE),
    re.compile(r"TypeError:.*missing.*positional argument", re.IGNORECASE),
    re.compile(r"SyntaxError:", re.IGNORECASE),
]


@dataclass(frozen=True, slots=True)
class SecurityObservation:
    """Immutable, bounded observation of security behavior under an exploit witness."""

    world: ExecutionWorld
    state: SecurityState
    blocking_mechanism: SecurityBlockingMechanism | None
    evidence_detail: str
    exit_code: int | None
    stdout_digest: str
    stderr_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.world, ExecutionWorld):
            raise TypeError(f"world must be ExecutionWorld, got {type(self.world).__name__}")
        if not isinstance(self.state, SecurityState):
            raise TypeError(f"state must be SecurityState, got {type(self.state).__name__}")
        if self.state == SecurityState.BLOCKED and self.blocking_mechanism is None:
            raise ValueError("blocking_mechanism must be specified when state is BLOCKED")
        if not isinstance(self.evidence_detail, str) or not self.evidence_detail.strip():
            raise ValueError("evidence_detail must be a non-empty string")


def detect_security_state(
    *,
    world: ExecutionWorld,
    result: NormalizedWitnessResult,
    expected_blocking_mechanism: SecurityBlockingMechanism | None = None,
    exploit_success_pattern: str | None = None,
    blocking_indicator_pattern: str | None = None,
) -> SecurityObservation:
    """Deterministically detect security state from normalized witness execution facts.

    CRITICAL RULES:
    1. Do not treat crash, timeout, unrelated exception, or sandbox/network failure
       as BLOCKED.
    2. Exit code 139 / fatal signal / unhandled traceback is CRASH or UNRELATED_EXCEPTION.
    3. BLOCKED requires explicit, bounded mechanical blocking evidence.
    """
    if not isinstance(world, ExecutionWorld):
        raise TypeError(f"world must be ExecutionWorld, got {type(world).__name__}")
    if not isinstance(result, NormalizedWitnessResult):
        raise TypeError(f"result must be NormalizedWitnessResult, got {type(result).__name__}")

    # 1. Timeout check
    if (
        result.termination_status == TerminationStatus.TIMED_OUT
        or result.outcome == WitnessOutcome.TIMEOUT
    ):
        return SecurityObservation(
            world=world,
            state=SecurityState.TIMEOUT,
            blocking_mechanism=None,
            evidence_detail="Witness execution timed out; timeouts never count as BLOCKED",
            exit_code=result.exit_code,
            stdout_digest=result.stdout_digest,
            stderr_digest=result.stderr_digest,
        )

    # 2. Precondition check
    if result.outcome == WitnessOutcome.INVALID_PRECONDITION:
        return SecurityObservation(
            world=world,
            state=SecurityState.INVALID_PRECONDITION,
            blocking_mechanism=None,
            evidence_detail="Execution precondition invalid",
            exit_code=result.exit_code,
            stdout_digest=result.stdout_digest,
            stderr_digest=result.stderr_digest,
        )

    # 3. Infrastructure / cancelled check
    if result.termination_status in (
        TerminationStatus.CANCELLED,
        TerminationStatus.FAILED_TO_START,
    ):
        return SecurityObservation(
            world=world,
            state=SecurityState.INFRASTRUCTURE_FAILURE,
            blocking_mechanism=None,
            evidence_detail=f"Execution terminated with {result.termination_status.value}",
            exit_code=result.exit_code,
            stdout_digest=result.stdout_digest,
            stderr_digest=result.stderr_digest,
        )

    combined_output = f"{result.stdout_clean}\n{result.stderr_clean}"

    # 4. Crash check: fatal signal or crash indicators
    if result.exit_code is not None and (result.exit_code < 0 or result.exit_code >= 128):
        # Exit codes 139 (SIGSEGV), 134 (SIGABRT), etc.
        return SecurityObservation(
            world=world,
            state=SecurityState.CRASH,
            blocking_mechanism=None,
            evidence_detail=(
                f"Process crashed with fatal exit code {result.exit_code}; "
                f"crashes never count as BLOCKED"
            ),
            exit_code=result.exit_code,
            stdout_digest=result.stdout_digest,
            stderr_digest=result.stderr_digest,
        )

    for c_pat in _CRASH_PATTERNS:
        if c_pat.search(combined_output):
            return SecurityObservation(
                world=world,
                state=SecurityState.CRASH,
                blocking_mechanism=None,
                evidence_detail=(
                    f"Process crashed ({c_pat.pattern}); crashes never count as BLOCKED"
                ),
                exit_code=result.exit_code,
                stdout_digest=result.stdout_digest,
                stderr_digest=result.stderr_digest,
            )

    # 5. Unrelated exception check: unhandled exceptions that are not security rejections
    for u_pat in _UNRELATED_EXCEPTION_PATTERNS:
        if u_pat.search(combined_output):
            return SecurityObservation(
                world=world,
                state=SecurityState.UNRELATED_EXCEPTION,
                blocking_mechanism=None,
                evidence_detail=(
                    f"Execution failed with unrelated exception ({u_pat.pattern}); "
                    f"unrelated exceptions never count as BLOCKED"
                ),
                exit_code=result.exit_code,
                stdout_digest=result.stdout_digest,
                stderr_digest=result.stderr_digest,
            )

    # 6. Check for clean BLOCKED evidence
    if expected_blocking_mechanism is not None:
        matched_blocking = False
        matched_detail = ""

        if blocking_indicator_pattern is not None:
            pat = re.compile(blocking_indicator_pattern, re.IGNORECASE)
            m = pat.search(combined_output)
            if m:
                matched_blocking = True
                matched_line = next(
                    (line.strip() for line in combined_output.splitlines() if pat.search(line)),
                    m.group(0).strip(),
                )
                matched_detail = f"Matched custom blocking pattern '{pat.pattern}': {matched_line}"

        if not matched_blocking and expected_blocking_mechanism in _BLOCKING_PATTERNS:
            for pat in _BLOCKING_PATTERNS[expected_blocking_mechanism]:
                m = pat.search(combined_output)
                if m:
                    matched_blocking = True
                    matched_line = next(
                        (line.strip() for line in combined_output.splitlines() if pat.search(line)),
                        m.group(0).strip(),
                    )
                    matched_detail = f"Matched pattern '{pat.pattern}': {matched_line}"
                    break

        if matched_blocking:
            return SecurityObservation(
                world=world,
                state=SecurityState.BLOCKED,
                blocking_mechanism=expected_blocking_mechanism,
                evidence_detail=(
                    f"Exploit mechanically BLOCKED via {expected_blocking_mechanism.value}: "
                    f"{matched_detail}"
                ),
                exit_code=result.exit_code,
                stdout_digest=result.stdout_digest,
                stderr_digest=result.stderr_digest,
            )

    # 7. Check for EXPLOITABLE evidence
    # Default: if test succeeded (outcome PASS, exit 0) or matched exploit success pattern
    if exploit_success_pattern is not None:
        pat = re.compile(exploit_success_pattern, re.IGNORECASE)
        m = pat.search(combined_output)
        if m:
            matched_line = next(
                (line.strip() for line in combined_output.splitlines() if pat.search(line)),
                m.group(0).strip(),
            )
            return SecurityObservation(
                world=world,
                state=SecurityState.EXPLOITABLE,
                blocking_mechanism=None,
                evidence_detail=f"Exploit succeeded: {matched_line}",
                exit_code=result.exit_code,
                stdout_digest=result.stdout_digest,
                stderr_digest=result.stderr_digest,
            )

    # Standard security witness convention:
    # If the exploit script exits 0, the vulnerability was successfully exploited!
    if result.outcome == WitnessOutcome.PASS and result.exit_code == 0:
        return SecurityObservation(
            world=world,
            state=SecurityState.EXPLOITABLE,
            blocking_mechanism=None,
            evidence_detail=(
                "Exploit witness completed successfully (exit code 0); system is EXPLOITABLE"
            ),
            exit_code=result.exit_code,
            stdout_digest=result.stdout_digest,
            stderr_digest=result.stderr_digest,
        )

    # If failure occurred but did not match recognized blocking mechanism:
    # Fail closed to UNRELATED_EXCEPTION, never BLOCKED!
    return SecurityObservation(
        world=world,
        state=SecurityState.UNRELATED_EXCEPTION,
        blocking_mechanism=None,
        evidence_detail=(
            f"Execution failed with exit code {result.exit_code} without matching defined "
            f"blocking mechanism; fails closed to UNRELATED_EXCEPTION"
        ),
        exit_code=result.exit_code,
        stdout_digest=result.stdout_digest,
        stderr_digest=result.stderr_digest,
    )


def reconcile_security_transition(
    *,
    base_observation: SecurityObservation,
    candidate_observation: SecurityObservation,
    legitimate_preserved: bool = True,
    frozen_contract: FrozenContract | None = None,
    base_vacuity: VacuityCheckResult | None = None,
    candidate_vacuity: VacuityCheckResult | None = None,
    integrity_failure_reason: str | None = None,
) -> ReconciliationFact:
    """Deterministically reconcile BASE and CANDIDATE security observations.

    Enforces:
    - Contract change_class must be ChangeClass.SECURITY_FIX.
    - BASE=EXPLOITABLE and CANDIDATE=BLOCKED (with legitimate_preserved=True)
      is the ONLY positive transition -> SECURITY_FIX_VERIFIED.
    - Crash, timeout, unrelated exception, or broken legitimate behavior
      resolves to non-verified states.
    """
    if not isinstance(base_observation, SecurityObservation):
        raise TypeError(
            f"base_observation must be SecurityObservation, got {type(base_observation).__name__}"
        )
    if not isinstance(candidate_observation, SecurityObservation):
        cand_type = type(candidate_observation).__name__
        raise TypeError(f"candidate_observation must be SecurityObservation, got {cand_type}")
    if not isinstance(legitimate_preserved, bool):
        raise TypeError("legitimate_preserved must be a boolean")

    # 0. Frozen contract change class check
    if frozen_contract is not None:
        if not isinstance(frozen_contract, FrozenContract):
            raise TypeError(
                f"frozen_contract must be FrozenContract, got {type(frozen_contract).__name__}"
            )
        if frozen_contract.change_class != ChangeClass.SECURITY_FIX:
            raise ChangeClassMismatchError(
                f"Contract change_class is {frozen_contract.change_class.value}, "
                f"expected ChangeClass.SECURITY_FIX for security fix verification"
            )

    # 1. Cryptographic binding / integrity failure
    if integrity_failure_reason is not None and str(integrity_failure_reason).strip():
        reason = str(integrity_failure_reason).strip()
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_TAMPERING_OR_INTEGRITY_FAILURE,
            verdict=PreliminaryVerdict.CONTRADICTED,
            is_causally_verified=False,
            rationale=f"Cryptographic binding or integrity check failed: {reason}",
        )

    # 2. Vacuity checks
    if base_vacuity is not None and base_vacuity.is_vacuous:
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_VACUOUS,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=f"Witness on BASE world is vacuous: {base_vacuity.details}",
        )
    if candidate_vacuity is not None and candidate_vacuity.is_vacuous:
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_VACUOUS,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=f"Witness on CANDIDATE world is vacuous: {candidate_vacuity.details}",
        )

    # 3. Precondition failures
    if (
        base_observation.state == SecurityState.INVALID_PRECONDITION
        or candidate_observation.state == SecurityState.INVALID_PRECONDITION
    ):
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_INVALID_PRECONDITION,
            verdict=PreliminaryVerdict.BLOCKED,
            is_causally_verified=False,
            rationale="Security execution precondition invalid",
        )

    # 4. Timeout outcomes
    if (
        base_observation.state == SecurityState.TIMEOUT
        or candidate_observation.state == SecurityState.TIMEOUT
    ):
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_TIMEOUT,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                f"Security execution timed out (BASE: {base_observation.state.value}, "
                f"CANDIDATE: {candidate_observation.state.value}); timeouts never count as BLOCKED"
            ),
        )

    # 5. Crash outcomes
    if (
        base_observation.state == SecurityState.CRASH
        or candidate_observation.state == SecurityState.CRASH
    ):
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_CRASH_OR_UNHANDLED_EXCEPTION,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                f"Process crashed during security verification "
                f"(BASE: {base_observation.state.value}, "
                f"CANDIDATE: {candidate_observation.state.value}); "
                f"crashes never count as BLOCKED"
            ),
        )

    # 6. Unrelated exceptions
    if (
        base_observation.state == SecurityState.UNRELATED_EXCEPTION
        or candidate_observation.state == SecurityState.UNRELATED_EXCEPTION
    ):
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_CRASH_OR_UNHANDLED_EXCEPTION,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                f"Execution threw unrelated exception "
                f"(BASE: {base_observation.state.value}, "
                f"CANDIDATE: {candidate_observation.state.value}); "
                f"unrelated exceptions never count as BLOCKED"
            ),
        )

    # 7. Infrastructure failures
    if (
        base_observation.state == SecurityState.INFRASTRUCTURE_FAILURE
        or candidate_observation.state == SecurityState.INFRASTRUCTURE_FAILURE
    ):
        return ReconciliationFact(
            transition=CausalTransition.NON_VERIFIED_EXECUTION_ERROR,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale="Security execution encountered sandbox or infrastructure failure",
        )

    # 8. Behavioral transitions
    # 8a. BASE=BLOCKED -> Vulnerability not reproduced
    if base_observation.state == SecurityState.BLOCKED:
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_VULNERABILITY_NOT_REPRODUCED,
            verdict=PreliminaryVerdict.INCONCLUSIVE,
            is_causally_verified=False,
            rationale=(
                "Vulnerability was already BLOCKED on BASE; exploit not reproduced on baseline."
            ),
        )

    # 8b. CANDIDATE=EXPLOITABLE -> Exploit persists
    if candidate_observation.state == SecurityState.EXPLOITABLE:
        return ReconciliationFact(
            transition=CausalTransition.UNVERIFIED_EXPLOIT_PERSISTS,
            verdict=PreliminaryVerdict.CONTRADICTED,
            is_causally_verified=False,
            rationale="CANDIDATE remains EXPLOITABLE under witness; security fix failed.",
        )

    # 8c. BASE=EXPLOITABLE and CANDIDATE=BLOCKED
    if (
        base_observation.state == SecurityState.EXPLOITABLE
        and candidate_observation.state == SecurityState.BLOCKED
    ):
        if not legitimate_preserved:
            return ReconciliationFact(
                transition=CausalTransition.UNVERIFIED_SECURITY_FIX_REGRESSION,
                verdict=PreliminaryVerdict.CONTRADICTED,
                is_causally_verified=False,
                rationale=(
                    "Exploit was blocked on CANDIDATE, but required legitimate functionality "
                    "was broken (security fix regression)."
                ),
            )

        mech = (
            candidate_observation.blocking_mechanism.value
            if candidate_observation.blocking_mechanism
            else "UNKNOWN"
        )
        return ReconciliationFact(
            transition=CausalTransition.SECURITY_FIX_VERIFIED,
            verdict=PreliminaryVerdict.VERIFIED,
            is_causally_verified=True,
            rationale=(
                f"Security fix verified: BASE was EXPLOITABLE; "
                f"CANDIDATE cleanly BLOCKED the exploit via {mech} "
                f"while preserving legitimate behavior."
            ),
        )

    # Fallback fail closed
    return ReconciliationFact(
        transition=CausalTransition.NON_VERIFIED_EXECUTION_ERROR,
        verdict=PreliminaryVerdict.INCONCLUSIVE,
        is_causally_verified=False,
        rationale=(
            f"Unhandled security state combination: BASE={base_observation.state.value}, "
            f"CANDIDATE={candidate_observation.state.value}"
        ),
    )


def verify_security_fix(
    *,
    context_envelope: VerifierContextEnvelope,
    sealed_record: SealedWitnessRecord,
    witness_lock: ImmutableWitnessLock,
    base_result: NormalizedWitnessResult,
    candidate_result: NormalizedWitnessResult,
    base_tree_digest: str,
    candidate_tree_digest: str,
    expected_blocking_mechanism: SecurityBlockingMechanism,
    exploit_success_pattern: str | None = None,
    blocking_indicator_pattern: str | None = None,
    candidate_legitimate_result: NormalizedWitnessResult | None = None,
    base_vacuity: VacuityCheckResult | None = None,
    candidate_vacuity: VacuityCheckResult | None = None,
    provenance: EvidenceProvenance = EvidenceProvenance.LOCAL_EXECUTION,
) -> SemanticVerificationReceipt:
    """Coordinate deterministic SECURITY_FIX verification and generate tamper-proof receipt."""
    # Step 1: Validate contract change_class
    if context_envelope.frozen_contract.change_class != ChangeClass.SECURITY_FIX:
        raise ChangeClassMismatchError(
            f"Contract change_class is {context_envelope.frozen_contract.change_class.value}, "
            f"expected ChangeClass.SECURITY_FIX"
        )

    # Step 2: Validate witness lock chain of custody
    verify_witness_lock_chain(
        lock=witness_lock,
        frozen_contract=context_envelope.frozen_contract,
        base_record=sealed_record,
        candidate_record=sealed_record,
    )

    # Step 3: Integrity checks
    integrity_failure_reason: str | None = None

    if base_result.sandbox_id == candidate_result.sandbox_id:
        integrity_failure_reason = "BASE and CANDIDATE reused the same sandbox identity"

    if base_tree_digest.lower() == candidate_tree_digest.lower():
        integrity_failure_reason = (
            "Candidate tree digest is identical to base tree digest (empty patch)"
        )

    # Step 4: Detect security states
    base_obs = detect_security_state(
        world=ExecutionWorld.BASE,
        result=base_result,
        expected_blocking_mechanism=expected_blocking_mechanism,
        exploit_success_pattern=exploit_success_pattern,
        blocking_indicator_pattern=blocking_indicator_pattern,
    )
    cand_obs = detect_security_state(
        world=ExecutionWorld.CANDIDATE,
        result=candidate_result,
        expected_blocking_mechanism=expected_blocking_mechanism,
        exploit_success_pattern=exploit_success_pattern,
        blocking_indicator_pattern=blocking_indicator_pattern,
    )

    # Step 5: Check legitimate behavior preservation if supplied
    legitimate_preserved = True
    legit_detail = "None specified"
    if candidate_legitimate_result is not None:
        if (
            candidate_legitimate_result.outcome != WitnessOutcome.PASS
            or candidate_legitimate_result.exit_code != 0
        ):
            legitimate_preserved = False
            legit_detail = (
                f"Legitimate check failed: outcome={candidate_legitimate_result.outcome.value}, "
                f"exit_code={candidate_legitimate_result.exit_code}"
            )
        else:
            legit_detail = "Legitimate functionality preserved (PASS, exit 0)"

    # Step 6: Reconcile transition
    reconciliation = reconcile_security_transition(
        base_observation=base_obs,
        candidate_observation=cand_obs,
        legitimate_preserved=legitimate_preserved,
        frozen_contract=context_envelope.frozen_contract,
        base_vacuity=base_vacuity,
        candidate_vacuity=candidate_vacuity,
        integrity_failure_reason=integrity_failure_reason,
    )

    # Step 7: Create execution facts
    base_exec = WorldExecutionFact.from_normalized_result(
        base_result,
        tree_digest=base_tree_digest,
    )
    candidate_exec = WorldExecutionFact.from_normalized_result(
        candidate_result,
        tree_digest=candidate_tree_digest,
    )

    class_payload: dict[str, Any] = {
        "base_state": base_obs.state.value,
        "base_evidence_detail": base_obs.evidence_detail,
        "blocking_mechanism": expected_blocking_mechanism.value,
        "candidate_state": cand_obs.state.value,
        "candidate_evidence_detail": cand_obs.evidence_detail,
        "legitimate_behavior_preserved": legitimate_preserved,
        "legitimate_detail": legit_detail,
    }

    # Step 8: Build and return authentic receipt
    return create_semantic_receipt(
        change_class=ChangeClass.SECURITY_FIX,
        requirement_id=sealed_record.requirement_id,
        frozen_contract_digest=context_envelope.frozen_contract.contract_digest,
        witness_id=sealed_record.witness_id,
        witness_digest=sealed_record.seal_digest,
        lock_digest=witness_lock.lock_digest,
        source_commit_id=context_envelope.source_identity.resolved_commit_id,
        candidate_tree_digest=candidate_tree_digest,
        base_execution=base_exec,
        candidate_execution=candidate_exec,
        class_specific_payload=class_payload,
        transition=reconciliation.transition,
        verdict=reconciliation.verdict,
        is_causally_verified=reconciliation.is_causally_verified,
        provenance=provenance,
        narrative=reconciliation.rationale,
    )
