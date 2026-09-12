# Evidence & Verdict Contract

## Provenance
Exactly:
- FIXTURE
- LOCAL_EXECUTION
- LIVE_NEBIUS
- RECORDED_LIVE

Provenance answers WHERE/HOW evidence was produced.
Verdict answers WHAT the check concluded.
They are separate dimensions.

## Primitive deterministic facts
Examples:
- repository URL and base SHA
- candidate tree/commit/patch digest
- sandbox/run ID
- model identifier returned/used by runtime
- command argv/working directory
- start/end timestamps
- exit code
- timeout/cancellation
- stdout/stderr digest and bounded sanitized excerpt
- witness ID/digest
- file/artifact digests
- protected-surface diff
- external-grounding source references

## Verdict vocabulary
Initial design target:
- VERIFIED
- PARTIALLY_VERIFIED
- CONTRADICTED
- INCONCLUSIVE
- NOT_RUN
- BLOCKED

Do not finalize public enum before the dedicated domain-contract phase.

## Causal requirement rule
For behavioral changes, a causal witness must bind:
- requirement ID
- witness digest
- trusted base hash
- exact candidate hash
- base outcome
- candidate outcome
- counterfactual outcome if required
- provenance
- runtime/sandbox identity
- evidence digests

## Causal Coverage
May only be computed from explicitly eligible behavioral requirements.
Never use LLM confidence as coverage.

## Receipts
A receipt is a deterministic envelope of evidence references, not a model narrative.
Narrative explanations may be attached but cannot change deterministic fields.
