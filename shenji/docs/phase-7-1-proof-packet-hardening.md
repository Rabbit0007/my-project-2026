# Phase 7.1: ProofPacket Repository Sync and SafeProbe Hardening

## Scope

Phase 7.1 hardens the Phase 7 ProofPacket side-probe path:

```text
GitHub ProofPacket repository
→ RepoSourceManager sync
→ ProofPacketIndex
→ proof_packet_search
→ proof_packet_normalize
→ SafeProbe
→ safe_packet_validate
→ Runner non-destructive execution
→ Evidence
→ Hypothesis lifecycle
→ Capability / NegativeFact / UnverifiedRisk
```

It does not add scanner-style template execution, arbitrary PoC script execution, GitHub script execution, a new workflow engine, a new Intent table, or new Runner behavior.

## RepoSourceManager

Implemented at:

```text
backend/internal/service/proof_packet_repo_source_manager.go
```

Responsibilities:

- read `Config.ProofPacketRepositories`;
- initialize repository metadata records;
- support manual/configured sync;
- clone or pull repositories using Git only;
- skip disabled repositories;
- traverse text files only;
- compute `source_repo`, `source_branch`, `source_commit`, `file_path`, and `file_hash`;
- call ProofPacket parsers;
- isolate parser failures per file;
- emit repository and indexing audit events.

Repository metadata is stored in:

```text
backend/internal/model/proof_packet.go
AIProofPacketRepository
```

## ProofPacketIndex

`AIProofPacketIndex` now includes:

- source name / repo / branch / commit;
- file path / file hash;
- title / summary;
- product / vendor / component / version / fingerprint fields;
- CVE / CNVD / CNNVD optional labels;
- safety fields;
- request templates;
- parser type / parse status / parse error;
- enabled flag;
- indexed timestamp.

CVE IDs are optional metadata and not the primary key. Identity is based on:

```text
proof_packet_id
source_repo
source_commit
file_path
file_hash
```

## Parser Adapters

Implemented adapter interface:

```go
type ProofPacketParser interface {
    Name() string
    Match(path string, content []byte) bool
    Parse(ctx context.Context, src ProofPacketSource, content []byte) ([]model.AIProofPacketIndex, error)
}
```

Implemented parsers:

- raw HTTP request;
- Markdown request extraction;
- curl snippet extraction;
- JSON request descriptor;
- YAML / nuclei-like placeholder parser that records `parse_error` without execution.

Unsupported or unsafe formats are recorded as failed index records instead of aborting the entire repository index.

## SafeProbe Hardening

SafeProbe remains the only structure allowed to enter validation.

`ValidateSafeProbeSafety` / `ValidateSafeProbe` rejects:

- `destructive=true`;
- `writes_target=true`;
- `requires_callback=true`;
- `requires_oob=true`;
- method outside `GET` / `POST`;
- request count above the local cap;
- unsafe shell fragments;
- webshell / reverse shell patterns;
- credential file write patterns;
- destructive SQL fragments;
- Java exec patterns.

Raw repository content is never sent directly to Runner.

## Lifecycle Guardrails

- `proof_packet_search` is capability-neutral.
- `proof_packet_normalize` is capability-neutral.
- `safe_packet_validate` may carry expected capability.
- Only `safe_packet_validate` with `verified=true` can enter capability acquisition.
- `verified=false + clear_negative` maps to refutation / NegativeFact.
- `verified=false + timeout | auth_required | blocked | network_error | inconclusive` maps to inconclusive / UnverifiedRisk.
- Phase 7 metadata and validation evidence is blocked from direct Finding creation.

## Budget and Dedup

Side probes still use:

- local cap: default `3`;
- `ExplorationBudgetManager.AllowIntentGenerationFor`.

Dedup helpers include:

```text
task_id
target_ref
fingerprint_product
fingerprint_version
proof_packet_id
source_repo
source_commit
file_hash
hypothesis_type = known_vuln_candidate
```

## Audit Events

Implemented audit events include:

- `proof_packet_repository_sync_started`;
- `proof_packet_repository_synced`;
- `proof_packet_repository_sync_failed`;
- `proof_packet_index_started`;
- `proof_packet_indexed`;
- `proof_packet_index_failed`;
- `proof_packet_search_generated`;
- `proof_packet_search_completed`;
- `proof_packet_normalize_generated`;
- `proof_packet_normalized`;
- `proof_packet_rejected`;
- `safe_packet_validate_generated`;
- `safe_packet_validate_executed`;
- `safe_packet_validate_blocked`;
- `safe_packet_validate_verified`;
- `safe_packet_validate_refuted`;
- `safe_packet_validate_inconclusive`;
- `proof_packet.finding_blocked`;
- `proof_packet.capability_blocked`.

Audit metadata is sanitized for sensitive keys such as Authorization, Cookie, token, secret, password, and private key references.

## Remaining Limitations

- YAML / nuclei-like parsing is intentionally a TODO adapter that records `parse_error`; it does not execute or translate templates yet.
- Repo sync currently uses Git clone/pull and local indexing; scheduling cadence is left to the worker/bootstrap layer.
- SafeProbe validation reuses the existing safe HTTP validation path; no new Runner behavior was introduced.
