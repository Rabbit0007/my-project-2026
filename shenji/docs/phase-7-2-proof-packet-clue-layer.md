# Phase 7.2: ProofPacket as Graph Pheromone / Clue Layer

## Scope

Phase 7.2 hardens the boundary around ProofPacket repository content:

```text
ProofPacket is a graph pheromone / clue.
ProofPacket is not a finding.
ProofPacket is not a capability.
ProofPacket is not a scanner template.
ProofPacket is not executable code.
ProofPacket is not the exploration driver.
```

The main lifecycle remains:

```text
Observation
→ Hypothesis
→ ValidationIntent
→ Runner
→ Evidence
→ Capability / NegativeFact / UnverifiedRisk
```

ProofPacket content can only assist hypothesis formation, ranking, and candidate selection.

## Graph Clue Semantics

Added blackboard node / edge vocabulary:

- `proof_packet_hint`
- `known_vuln_clue`
- `safe_probe_candidate`
- `suggests`
- `suggests_validation`

Runtime ProofPacket candidates are added as clue-only graph material and linked toward `known_vuln_candidate` hypotheses. They do not validate hypotheses and cannot produce capabilities or findings.

## Pheromone Permission Model

`AIPheromoneHint` now carries explicit permission flags:

- `CanCreateFinding=false`
- `CanCreateCapability=false`
- `CanValidateHypothesis=false`
- `CanFormHypothesis=true`
- `CanRankIntent=true`
- `CanSelectCandidate=true`
- `RequiresSafeProbeValidation=true`

ProofPacket / fingerprint / CVE label / PoC label metadata remains auxiliary.

## Candidate-Only Search Output

`proof_packet_search` emits candidate metadata with:

- `candidate_only=true`
- `is_pheromone=true`
- `is_clue=true`
- `can_create_finding=false`
- `can_create_capability=false`
- `can_validate_hypothesis=false`
- `requires_normalization=true`
- `requires_safeprobe_validation=true`
- `match_score`
- `match_reason`
- `matched_fields`

It does not create Findings, Capabilities, or validated Hypotheses.

## Metadata-Only Validation Guard

`proof_packet_search` and `proof_packet_normalize` are metadata-only stages.

They are blocked from:

- validating Hypotheses directly;
- creating Capabilities;
- creating Findings.

Only `safe_packet_validate` can produce validation evidence that may lead to capability acquisition.

## Repository Failure Isolation

`RepoSourceManager.SyncConfiguredRepositories` treats per-repository sync failures as non-blocking:

- sync failure emits `repo_source_sync_failed_non_blocking`;
- existing local `AIProofPacketIndex` records remain usable;
- current task execution is not failed by repository sync errors;
- runtime `proof_packet_search` queries the local index only and does not clone or download GitHub content.

## Audit Events

Phase 7.2 adds or hardens:

- `proof_packet_clue_created`
- `proof_packet.metadata_finding_blocked`
- `proof_packet.metadata_capability_blocked`
- `proof_packet.metadata_hypothesis_validation_blocked`
- `repo_source_sync_failed_non_blocking`

All ProofPacket audit metadata is marked as clue/candidate-only and requires SafeProbe validation.

Sensitive audit keys are redacted:

- Authorization
- Cookie
- Token
- Secret
- Password
- Private-Key
- Set-Cookie

## Safety Boundary

SafeProbe validation remains required and unchanged:

```text
ProofPacket clue
→ proof_packet_normalize
→ SafeProbe
→ safe_packet_validate
→ Runner evidence
→ Hypothesis lifecycle
```

No GitHub scripts, binaries, nuclei templates, command-line exploits, or arbitrary PoC files are executed.

## Acceptance Summary

Phase 7.2 keeps ProofPacket useful but humble:

```text
It is a clue, not a conclusion.
It can suggest a path, not prove one.
It can rank candidates, not validate them.
SafeProbe evidence remains mandatory.
```
