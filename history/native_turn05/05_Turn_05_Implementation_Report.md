# Turn 5 — Implementation report and candidate release

**Project:** Google Drive Distributed Object Substrate & Atomic Chunk Dropzone Orchestrator  
**Commission:** Gemini Operator Lab / Leon / Open Research / Sovereign Systems  
**Date:** 23 September 2026  
**Code release:** `drive-cas/0.5.0`  
**Wire:** `gdoe-cas/1`, `ascii-json-1`  
**CLI:** `gdoe-cli/2`  
**Release disposition:** IMPLEMENTED_CANDIDATE; production qualification NOT_GRANTED  
**Engine SHA-256:** `4c1700151602c9f10a7ac23785f346292bee7251efe915d07ab72f63fe73d065`  
**Harness SHA-256:** `6f7aa2a4edc1ba5085b092ad8621c8cf53370cc5addccd6d7635e9b1eabc9a80`

## 1. What was delivered and what was not

This release contains working Python, not another architecture proposal. `drive_cas.py` implements all five requested data-plane verbs, the four named classes, strict typed Merkle verification, immutable self-contained publication, a private SQLite authority, protected private reconstructions, retained exports, explicit administration and an executable unittest harness.

**It is not a complete implementation of every frozen Turn 4 runtime contract, and it is not production-ready or production-qualified.** The specific implementation gaps in section 8 remain engineering work, not merely host tests waiting to be checked off. In particular, qualified receipt activation, the complete per-block durable scheduler and several recovery/lifecycle services are not present. This is a usable, inspectable qualification candidate with a tested core; the source does not disguise those gaps with successful production receipts.

Observed on the exact delivered sources: **54 unittest methods passed, zero failures, zero errors, zero skips, in 18 fresh-process batches of three methods.** The methods include subcases and cover selected obligations across 16 original suite labels. This is neither 54 original acceptance suites nor a pass of all 32 Turn 4 suites. A single uninterrupted full-harness run is **not demonstrated**: longer grouped development runs hit execution-environment deadlines and the underlying wait was not conclusively isolated. Section 6 preserves this limitation.

The implementation, test execution and artifact assembly ran in a Linux x86-64 container. No Apple Silicon, native Google FileProvider, real cellular, two-device replication or power-loss qualification was performed. The root filesystem was overlayfs with `fsync=volatile`; successful flush calls here are not durability evidence.

### 1.1 Source-chain precision

The supplied Turn 4 specification is 90,677 bytes. Its whole-file SHA-256 is `c2127e7a6c5546be7fa5bf8b624aef8f81c2c163cbb14361d1c4dcc1fe8ac023`. The commission's `97a46f3bfd99ab0ac19c5d44063bac330d7f6703f19f686ec9bd776a418af7e3` is its explicitly scoped **specification-body** hash, not the whole-file digest. Both are legitimate but distinct integrity domains.

The Turn 4 acceptance matrix is 51,969 bytes, SHA-256 `0231d9915073b4eee043e234905a91cbf969250212e2252c8d71b9b0282961b8`. Turn 2 defines the retained CAS fields; Turn 3 supplies A01–A07; Turn 4 freezes the broader runtime that this candidate only partially implements. No historical planning artifact has been rewritten.

### 1.2 Explicit current-instruction overrides

| Topic | Earlier contract | Implemented Turn 5 behavior |
|---|---|---|
| Writer default | 16 MiB; 4 MiB permitted | **4 MiB** (`4194304` bytes); both wire layouts remain readable when authorized |
| `get` positional operand | Logical file content hash H | **Submission-manifest root R**; no namespace guessing |
| Prune target option | `--max-size` | **`--max-size-gb`**, decimal GB |
| Entry point | `tools/drive-engine.py` | **`drive_cas.py`**; existing lab wrapper is not edited |
| Verification mutation | Private retained evidence permitted | Fresh `verify` changes neither source nor authority DB; it uses ephemeral private capture and bounded job diagnostics |

The first four are explicit current-request changes. The stricter read-only verification means it does not mint a successful retained-snapshot qualified receipt. The CLI uses version 2 so old consumers cannot silently reinterpret H as R. A root representing several files or an empty dataset is valid CAS content but is not a single-file `get` operand; that operation refuses to guess a file.

## 2. Codebase and class ownership

| File | Exact bytes | Lines | Purpose |
|---|---:|---:|---|
| `drive_cas.py` | 111891 | 2051 | All runtime and explicit administrative APIs |
| `test_drive_cas.py` | 36464 | 716 | Independent byte/history checks and fault fixtures |
| `README.md` | See manifest | See file | Enrollment, command reference, execution and limits |
| `validation/test_results.json` | See manifest | Machine-readable | Exact-source batch aggregation, every method outcome and scope |

All imports were statically inventoried as Python standard-library modules. No package installation, dynamic source download, REST client, Google SDK, network lock service, Web UI automation, FUSE, `fileproviderctl`, OpenAI call or other LLM call is used. The actual imports are:

`__future__, argparse, contextlib, ctypes, datetime, errno, fcntl, functools, hashlib, io, json, os, pathlib, platform, random, re, selectors, shutil, signal, sqlite3, stat, subprocess, sys, tempfile, time, typing, uuid`

The list in the commission is interpreted as examples of standard-library modules, not a prohibition on `subprocess`, `fcntl`, `ctypes` and other standard-library facilities already required by the approved architecture. These additional modules are necessary for real process isolation and native no-clobber operations.

| Class/service | Implemented responsibility | Explicit exclusion |
|---|---|---|
| `CASChunkManager` | Non-EOF short-read-safe fixed splitting; raw blocks; 4096-entry pages; ordered file maps; datasets; manifest and marker construction; duplicate blocks inside a candidate share one object | No cross-root physical block pool or shared Drive pool writer |
| `MerkleVerifier` | Exact root and marker; canonical decoding; typed decreasing graph; path rules; reference lengths; page and block packing; occurrence/unique totals; whole-file reconstruction; private destination readback; actual self-contained inventory | Never calls admission; never follows native Docs references or extracts archives |
| `DropzoneAdmissionBroker` | Immutable O/K/R binding; exact snapshot-to-task check; durable Q order; current approval/fence; one decision per K; atomic acceptance, retention pin and receipt outbox | No cloud election; no qualified receipt tier; no cross-host failover |
| `LocalCacheEvictor` | Registered private generations; last-use/G ordering; pin recheck; RETIRING before deletion; unique generation paths; protected-floor reporting | No provider eviction, cloud deletion, automatic pin expiry or arbitrary scratch cleanup |
| `AuthorityRegistry` | Explicit local transactions; stable guard; current DB/history/guard binding; durable operations/invocations/reservations/pins/audit | No cache-derived reconstruction of missing authority; no automatic old-backup recovery |
| `WorkerSupervisor` | Direct child interpreter; bounded control/log capture; isolated unique job paths; timeout and exit checks; inherited slot locks | Not a same-user hostile-code sandbox; full long-run liveness not qualified |
| `AtomicPublisher` | Native same-filesystem no-replace file/directory installation and exact existing-tree verification | No replace, hard-link trick, direct-final streaming or copy fallback |
| `Clock` | Mac continuous clock/timebase/boot UUID; Linux BOOTTIME/boot UUID for fixture execution | No guessed wall-clock distributed order or automatic old-boot grant renewal |
| `DriveEngine` | Five-verb orchestration, operation replay, private captures, root resolution, exports, explicit receipt-outbox iteration | Does not install a daemon, discover credentials or modify the lab dispatcher |

### 2.1 Concrete private/transport separation

Enrollment requires an already existing exchange directory and an explicitly chosen private root outside synchronization. It creates runtime intake subdirectories deliberately, never a missing account-root lookalike. Configuration pins root and authority identities and the engine source digest. Data commands do not bootstrap or replace missing authority state.

Source files and imported content use descriptor-relative no-follow traversal. Imported symlinks, special files and unexpected hard links are refused. Logical artifact names follow the frozen ASCII path policy; Unicode native parent paths remain allowed. The imported task contract supplies exact paths, roles, media types, byte limits and empty-artifact permission. Producer names and adjacent checksums are not authorization.

The scope is cooperative local control plus hostile transport bytes. A malicious process able to rewrite the local configuration, engine, database or private generations with equivalent privileges is outside this boundary. Read-only file modes and application pins are not a new OS security principal.

### 2.2 Immutable publication and actual atomicity

Mac uses `renameatx_np` with `RENAME_EXCL` through `ctypes`. Linux uses `renameat2` with `RENAME_NOREPLACE`. The unsupported branch fails closed. File and directory no-clobber semantics were exercised on the recorded Linux fixture filesystem; Mac and FileProvider behavior were not.

The source tree is prepared privately, copied into unique same-filesystem transport staging, fully checked, then installed without replacement. A colliding existing tree is verified for exact identity/content, not overwritten or merged. No distributed mutex is inferred from the native syscall.

**The engine does not prevent Google from syncing a partial staging file.** The inherited specification expressly says temporary names are not a synchronization exclusion mechanism. Its safety property is instead that a partial, missing, malformed or mismatching candidate cannot obtain a clean verification/admission result. Root hashes and markers are not remote transaction boundaries.

### 2.3 Verification, deduplication and consumption

The parser hashes captured bytes, rejects noncanonical encoding and unknown fields, validates every typed edge, preserves order/repetition, checks lengths to EOF including trailing bytes, recomputes totals and the whole-file digest, then rereads retained output. A missing self-contained member cannot be hidden by an unrelated private cache hit.

Within a self-contained submission equal raw blocks occupy one object, while ordered references retain their logical occurrences. Existing exact submission trees and private snapshots can be reused under their protection. Independently available equal-key samples are compared rather than treating a filename as proof. Global cross-root/private or cloud physical deduplication is not implemented; the report does not claim it.

Accepted retrieval uses retained private bytes. Fresh source verification may fail after transport changes while a historical acceptance remains valid about its earlier captured bytes. Conversely, detected private corruption blocks current `get` and new admission; a historical receipt does not certify perpetual health.

## 3. SQLite DDL — exact runtime definition

The following is the literal `DDL` constant extracted from the delivered `drive_cas.py`, not proposed SQL. Runtime migrations are not supplied in this release. The tables are private authority state; none belongs in CloudStorage.

```sql
CREATE TABLE store_info (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), store_id TEXT NOT NULL UNIQUE,
 authority_id TEXT NOT NULL, history_id TEXT NOT NULL, authority_epoch INTEGER NOT NULL CHECK(authority_epoch>0),
 health TEXT NOT NULL CHECK(health IN ('HEALTHY','RECOVERY_REQUIRED','INCIDENT')),
 qualification TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE tasks (
 k TEXT PRIMARY KEY, store_id TEXT NOT NULL, campaign TEXT NOT NULL, task_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0), contract BLOB NOT NULL, contract_hash TEXT NOT NULL,
 intake TEXT NOT NULL UNIQUE, intake_dev INTEGER NOT NULL, intake_ino INTEGER NOT NULL,
 selection TEXT NOT NULL CHECK(selection IN ('EXACT_ROOT','ANY_VALID_ENROLLED')),
 status TEXT NOT NULL CHECK(status IN ('OPEN','CLOSED','ACCEPTED')),
 fence INTEGER NOT NULL CHECK(fence>0), approval_boot TEXT NOT NULL,
 approval_until_ns INTEGER NOT NULL, approval_utc TEXT NOT NULL,
 UNIQUE(store_id,campaign,task_id,revision)
);
CREATE TABLE approved_roots (k TEXT NOT NULL REFERENCES tasks(k), root TEXT NOT NULL,
 PRIMARY KEY(k,root));
CREATE TABLE operations (
 o TEXT PRIMARY KEY, verb TEXT NOT NULL, intent BLOB NOT NULL, intent_hash TEXT NOT NULL,
 state TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
 active_ns INTEGER NOT NULL DEFAULT 0, result BLOB, error BLOB, created_at TEXT NOT NULL, checkpoint BLOB,
 active_boot TEXT, active_started INTEGER, next_attempt_ns INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE reservations (o TEXT PRIMARY KEY REFERENCES operations(o), bytes INTEGER NOT NULL CHECK(bytes>=0));
CREATE TABLE invocations (
 j TEXT PRIMARY KEY, o TEXT REFERENCES operations(o), generation INTEGER NOT NULL,
 phase TEXT NOT NULL, state TEXT NOT NULL, pid INTEGER, output_path TEXT NOT NULL,
 started_at TEXT NOT NULL, ended_at TEXT, exit_code INTEGER,
 UNIQUE(o,generation)
);
CREATE TABLE generations (
 g TEXT PRIMARY KEY, root TEXT, path TEXT NOT NULL UNIQUE,
 kind TEXT NOT NULL CHECK(kind IN ('SNAPSHOT','EXPORT')),
 size_bytes INTEGER NOT NULL CHECK(size_bytes>=0), evidence BLOB,
 state TEXT NOT NULL CHECK(state IN ('AVAILABLE','RETIRING','ABSENT','CORRUPT')),
 last_use INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX generations_root ON generations(root,state);
CREATE TABLE pins (
 g TEXT NOT NULL REFERENCES generations(g), owner TEXT NOT NULL, kind TEXT NOT NULL,
 created_at TEXT NOT NULL, PRIMARY KEY(g,owner,kind)
);
CREATE TABLE requests (
 q INTEGER PRIMARY KEY AUTOINCREMENT, o TEXT NOT NULL UNIQUE REFERENCES operations(o),
 k TEXT NOT NULL REFERENCES tasks(k), root TEXT NOT NULL,
 g TEXT NOT NULL REFERENCES generations(g), fence INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('QUEUED','BLOCKED','REJECTED','DECIDED','UNKNOWN')),
 reason TEXT, created_at TEXT NOT NULL
);
CREATE TABLE acceptances (
 a INTEGER PRIMARY KEY AUTOINCREMENT, k TEXT NOT NULL UNIQUE REFERENCES tasks(k),
 root TEXT NOT NULL, o TEXT NOT NULL UNIQUE REFERENCES operations(o),
 q INTEGER NOT NULL UNIQUE REFERENCES requests(q), g TEXT NOT NULL REFERENCES generations(g),
 verification BLOB NOT NULL, receipt BLOB NOT NULL, receipt_hash TEXT NOT NULL UNIQUE,
 created_at TEXT NOT NULL
);
CREATE TABLE receipt_outbox (
 receipt_hash TEXT PRIMARY KEY REFERENCES acceptances(receipt_hash), bytes BLOB NOT NULL,
 intake TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE publications (
 o TEXT PRIMARY KEY REFERENCES operations(o), destination TEXT NOT NULL UNIQUE,
 root TEXT NOT NULL, g TEXT NOT NULL REFERENCES generations(g), state TEXT NOT NULL
);
CREATE TABLE exports (
 o TEXT PRIMARY KEY REFERENCES operations(o), root TEXT NOT NULL,
 source_g TEXT NOT NULL REFERENCES generations(g), output_g TEXT REFERENCES generations(g),
 destination TEXT NOT NULL UNIQUE, state TEXT NOT NULL
);
CREATE TABLE audit (
 ordinal INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, detail BLOB NOT NULL,
 at_utc TEXT NOT NULL
);
```

### 3.1 Transaction invariants

`tasks` is unique over store/campaign/task/revision; `acceptances.k` is unique and does not include an authority epoch. Request sequence Q and acceptance sequence A have separate tables/identities. A later epoch does not authorize a second value for the same task revision.

Every connection uses the selected explicit transaction mode. Required pragma values are set/read back. Conditional writes use the private stable guard followed by a bounded `BEGIN IMMEDIATE` transaction. Payload hashing, worker waits and provider I/O are outside that transaction. SQLite is a local boundary only; it does not commit a filesystem and a remote replica atomically. [S01, S02]

Before allocating Q, the broker independently checks the operation verb/intent, requested K/R, the captured manifest's K/contract, current approval, generation state and an existing protection pin. Queue advancement records blocked obsolete requests before advancing, but stops at an earlier UNKNOWN. One decision transaction inserts the acceptance, exact candidate receipt, retained acceptance pin, request/task changes and receipt outbox together.

Prepared snapshot protection exists before that transaction; no prune gap is introduced. Existing candidate acceptance replay returns its original bytes. A different root gets a conflict. A compatible new O for the same accepted K/R is an alias of the old decision, not another receipt.

Output publication similarly records the handed-off export and operation completion together. An unrelated occupied destination stays a conflict on replay, even when matching bytes happen to be present. A possible owned publication with a lost response is reconciled by the same reservation.

### 3.2 Recovery and lifetime costs

The database identity and history UUID detect missing/replaced authority in the tested cases. They cannot detect an unnoticed in-place rollback of the entire trusted state. `enter_recovery` records a stop; a complete restore reconciler/migration service is absent. Never delete the DB to reset a running store.

Reader/export pins do not expire with a work deadline. `release_export` is explicit end-of-use administration. Preparation and acceptance pins remain separate and this release has no automatic last-copy release. This conservative retention can consume substantial disk; `prune` must return a protected-floor hold rather than invent a release.

Unregistered interrupted scratch and job diagnostics are outside prune's accounted target and are not automatically reclaimed. Operators must first establish ownership closure and retained-source obligations before any separate maintenance. The release does not offer an unsafe wildcard-cleanup command.

## 4. Worker containment and offline operation

All runtime provider accesses are performed in subprocess jobs: path probing, inventory, acquisition, copying, flushes, publication and reconciliation. Read-only verification uses a nonrecording supervisor; source and authority bytes are tested unchanged. Private ephemeral job files and destination captures are local side effects, so “without mutation” is specifically source/canonical-state nonmutation, not literally no disk writes.

Two private stable slot locks are inherited by direct children. The caller closes its descriptor without issuing a shared `LOCK_UN`; a live timed-out child therefore continues holding its slot. No authority guard or live SQLite connection is passed. This limits replacement work without relying on a PID-only guess that a blocked child died. Worker messages/results, evidence bytes and logs are bounded. Successful registration requires a proper result, successful direct child exit and closed/private destination verification.

No CloudStorage `mmap` is used. Synthetic SIGBUS affects only an owned isolated child in the harness. Normal FileProvider eviction behavior was not observed. Process containment cannot protect against a kernel failure or make uninterruptible I/O obey a hard deadline. Python subprocess documentation is the narrow basis for exit/timeout behavior, not a proof of target liveness. [S03]

Mac controller, lock-wait and worker deadlines use continuous time and a boot epoch. Linux fixtures use BOOTTIME. New approval requires both its UTC and continuous bounds; old decisions can be read without reviving expired permission. Actual sleep/reboot behavior of the Mac adapter remains untested.

Provider-stage retry count and active-time accounting are persisted. An offline invocation does not dispatch provider jobs; a prepared private source can remain held. The implementation uses whole-job acquisition/publication stages, not the complete per-block resumable scheduler from Turn 4. New retry windows require explicit administration. An outbox remains durable state but no background daemon is installed; progress requires a live invocation or a deliberate call from the existing controller.

## 5. Public surface and actual result contracts

```text
python3.13 drive_cas.py [common options] put FILE [--dropzone INTAKE_PARENT]
python3.13 drive_cas.py [common options] get ROOT_HASH [--output DEST]
python3.13 drive_cas.py [common options] commit SUBMISSION_LEAF
python3.13 drive_cas.py [common options] verify SUBMISSION_LEAF
python3.13 drive_cas.py [common options] prune [--max-size-gb DECIMAL_GB] [--dry-run]
```

Common options: `--config`, `--operation-id`, `--wait-ms`, `--offline`, `--status-only` before the verb. Strict argument parsing rejects abbreviations and duplicates. `verify` does not support operation/status identity because it deliberately does not record an authority operation. `--help` and `--version` need no enrolled store. README contains complete examples and exit meanings.

Only `commit` admits. `put` publishes a proposal; `get` hands off complete private bytes; `verify` makes a fresh bounded observation; `prune` acts on eligible registered private generations. All command results carry `qualification: NOT_GRANTED`. CLI2 is a implemented candidate envelope, not an assertion that every old CLI1 field remains identical.

`candidate_verification_evidence` and `candidate_acceptance_receipt` are deliberately distinct from the frozen production-qualified successful receipt types. They are unsigned, hash-bound records. Merely running this candidate on a Mac will not create a production-qualified receipt. A separately reviewed implementation/activation path would be required after the full qualification evidence exists.

Explicit administration is a Python API, not hidden data-plane bootstrap: `enroll_store`, `enroll_task`, `approve_candidate`, `release_export`, `open_retry_window`, and `enter_recovery`. Enrollment records a candidate and a trusted contract; it cannot declare the implementation production-qualified. README's disposable demo uses a temporary local exchange, not the user's real Drive.

## 6. Actual executable results and evidence limits

### 6.1 Final exact-source campaign

| Measure | Observation |
|---|---|
| Test method count | 54 |
| Execution organization | 18 fresh-process batches of 3 methods |
| Passed / failed / errors / skips | 54 / 0 / 0 / 0 |
| Matching engine/harness digest in every batch | Yes; programmatically checked |
| Duplicate/missing test method IDs | None; compared with discovered harness methods |
| Original suite labels with some executed coverage | 16 |
| Summed method execution time | 226.385521 seconds; not end-to-end wall time or a throughput benchmark |
| Python | 3.13.5, GCC 14.2.0 |
| SQLite | 3.46.1 |
| Machine / OS | x86_64; Linux 6.18.44; glibc 2.41 |
| Filesystem | overlayfs with `fsync=volatile` |
| Syntax compilation / stdlib import inventory | Passed |
| Apple Silicon/FileProvider/cellular/power loss | Not executed |
| Full uninterrupted single-process harness | Not demonstrated |
| Production qualification | NOT_GRANTED |

`validation/batch_00.json` through `batch_17.json` retain each exact test ID, suite annotation, result, time and source/environment binding. The accompanying logs preserve unittest output. `validation/test_results.json` is the checked aggregation. Batch method order is a round-robin partition of the harness's discovered methods; no failing methods were omitted to produce a passing total.

### 6.2 Longer-run limitation and retained development history

Longer grouped development runs exceeded execution-container time limits while waiting around a child-operation path. Diagnostic observations included completed job evidence with the caller still awaiting completion/pipe state. A supervisor patch now polls direct child termination independently of inherited pipe EOF and stops requiring EOF after a child has exited, but this did **not** establish the root cause or prove full long-run liveness. Subsequent final-source tests were executed in the bounded fresh batches above.

This is a remaining investigation/soak obligation. It would be inaccurate to say the complete test harness passed in one run, that the wait was definitely only external infrastructure, or that this patch conclusively fixed it. The long-run issue is one reason this is not a production-ready release. Historical timeout logs are labeled development evidence and are not mixed into final-build PASS counts.

### 6.3 Observer independence and retained artifacts

The tests inspect exact bytes, independent fixture expectations, raw metadata and SQLite history rather than asking the engine verifier to certify itself. At least two deliberate negative controls check that the external oracle detects overwrite and order/repetition loss. This is limited negative-control coverage, not the full planned mutation-testing program. Both implementation and oracle may use the standard-library SHA-256 primitive; that is not cryptographic implementation diversity.

The harness includes a real two-local-process SQLite admission race. That is **not two-device synchronization**. Direct child SIGBUS is an injected fault, not spontaneous FileProvider behavior. Successful kernel renames are local namespace observations, not Drive upload completion. Reloading a database on volatile overlay storage does not qualify process-crash durability or power-loss survival.

Temporary fixtures are removed after tests. The release retains logs, method outcomes, source digests and summaries, **not the full per-case filesystem/DB snapshots and named-barrier evidence prescribed for a production qualification campaign**. The later full acceptance harness needs that evidence retention and independent review.

## 7. Coverage mapping

Every count below denotes passing unittest methods with bounded subcases. “Partial” means the entire original suite, all its negative controls and its target applicability have not been qualified. Selected requested seven suites are implemented through these real methods; the full frozen 32-suite matrix is not.

| Original suite | Methods passed | Implemented scope | Full-suite qualification |
|---|---:|---|---|
| AT-02 | 5 | Empty file/dataset, exact encoding and independent contract permission | Partial; NOT_GRANTED |
| AT-03 | 3 | 4/16 MiB boundaries and non-EOF short reads | Partial; NOT_GRANTED |
| AT-04 | 2 | Strict JSON subset, depth, unknown fields | Partial; NOT_GRANTED |
| AT-06 | 5 | EOF/trailing byte/whole digest and declared length | Partial; NOT_GRANTED |
| AT-07 | 4 | Order/repetition and trusted root binding | Partial; NOT_GRANTED |
| AT-08 | 2 | Symlink/special-file confinement subcases only | Partial; NOT_GRANTED |
| AT-09 | 2 | Missing block and read-only verification subcases | Partial; NOT_GRANTED |
| AT-14 | 3 | Injected child failure; no live FileProvider SIGBUS claim | Partial; NOT_GRANTED |
| AT-15 | 6 | Native local rename on recorded host; FileProvider remains unqualified | Partial; NOT_GRANTED |
| AT-18 | 7 | Real local SQLite ordering, conflict and process race | Partial; NOT_GRANTED |
| AT-19 | 3 | Stable intent and exact receipt replay subcases | Partial; NOT_GRANTED |
| AT-22 | 5 | Before/after capture tampering, private output readback | Partial; NOT_GRANTED |
| AT-24 | 1 | Explicit export lifetime and generation-specific reclamation | Partial; NOT_GRANTED |
| AT-25 | 1 | Private-only prune, exact decimal target, protected floor | Partial; NOT_GRANTED |
| AT-28 | 2 | Missing/replaced authority refuses initialization | Partial; NOT_GRANTED |
| AT-32 | 3 | Five verbs, machine output and no hidden admission subcases | Partial; NOT_GRANTED |

Coverage counts are not additive claims of independent bug families. Some tests share fixtures and more than one invariant. Remaining suite IDs without a separately annotated method have no claimed suite execution in this report, even when part of their intended behavior exists in code.

### 7.1 Exact method inventory

| Method | Suite | Final result |
|---|---|---|
| `test_blocked_first_request_has_recorded_disposition` | AT-18 | PASS |
| `test_boundary_packing_both_profiles` | AT-03 | PASS |
| `test_broker_rejects_root_different_from_operation_intent` | AT-18 | PASS |
| `test_changed_order_with_old_whole_digest_rejected` | AT-07 | PASS |
| `test_cli_all_five_verbs_and_zero_hidden_acceptance` | AT-32 | PASS |
| `test_cli_rejects_abbreviations_duplicate_flags_and_old_hash_namespace` | AT-32 | PASS |
| `test_correct_leaves_wrong_whole_digest_rejected` | AT-06 | PASS |
| `test_cross_task_cached_root_cannot_satisfy_other_contract` | AT-18 | PASS |
| `test_depth_is_rejected_before_unbounded_parser` | AT-04 | PASS |
| `test_destination_readback_is_required` | AT-22 | PASS |
| `test_dry_run_no_deletion_and_decimal_units` | AT-25 | PASS |
| `test_durable_request_order_survives_registry_reopen` | AT-18 | PASS |
| `test_early_eof_rejected` | AT-06 | PASS |
| `test_empty_artifact_requires_independent_permission` | AT-02 | PASS |
| `test_empty_dataset_allow_and_forbid` | AT-02 | PASS |
| `test_empty_dataset_can_be_admitted_under_its_own_contract` | AT-02 | PASS |
| `test_empty_file_has_zero_blocks_and_known_hash` | AT-02 | PASS |
| `test_exact_receipt_replay_after_source_deletion` | AT-19 | PASS |
| `test_export_is_pinned_until_explicit_release` | AT-24 | PASS |
| `test_fully_rehashed_alternate_cannot_replace_approved_root` | AT-07 | PASS |
| `test_get_explicitly_approved_external_root_without_admission` | AT-22 | PASS |
| `test_get_replay_checks_current_output` | AT-22 | PASS |
| `test_inconsistent_reference_size_rejected` | AT-06 | PASS |
| `test_isolated_child_sigbus_does_not_kill_parent` | AT-14 | PASS |
| `test_logical_case_and_ancestor_collisions` | AT-08 | PASS |
| `test_missing_authority_not_automatically_recreated` | AT-28 | PASS |
| `test_missing_block_never_admitted_even_with_marker` | AT-09 | PASS |
| `test_native_no_clobber_file_and_directory_probe` | AT-15 | PASS |
| `test_native_occupied_destination_preserves_both_files` | AT-15 | PASS |
| `test_negative_control_oracle_catches_overwrite` | AT-15 | PASS |
| `test_negative_control_oracle_catches_sorted_or_dropped_references` | AT-07 | PASS |
| `test_occupied_explicit_output_even_matching_bytes_is_refused` | AT-15 | PASS |
| `test_offline_get_uses_private_bytes_but_verify_holds` | AT-32 | PASS |
| `test_one_root_per_task_and_epoch_never_reopens_it` | AT-18 | PASS |
| `test_original_root_rejects_modified_manifest` | AT-07 | PASS |
| `test_private_corruption_blocks_get_and_admission` | AT-22 | PASS |
| `test_readonly_status_does_not_rehydrate_or_mutate` | AT-19 | PASS |
| `test_real_two_process_admission_race` | AT-18 | PASS |
| `test_repeated_blocks_deduplicate_storage_not_occurrences` | AT-03 | PASS |
| `test_replaced_valid_database_requires_recovery` | AT-28 | PASS |
| `test_same_length_bit_tamper_rejected` | AT-06 | PASS |
| `test_same_operation_put_is_identical_replay` | AT-15 | PASS |
| `test_same_operation_rejects_altered_intent` | AT-19 | PASS |
| `test_short_reads_do_not_end_chunk` | AT-03 | PASS |
| `test_slot_cap_is_shared_between_controllers` | AT-14 | PASS |
| `test_strict_json_rejects_ambiguous_encodings` | AT-04 | PASS |
| `test_symlink_block_never_followed` | AT-08 | PASS |
| `test_trailing_byte_rejected_not_valid_prefix` | AT-06 | PASS |
| `test_transport_tamper_does_not_change_private_consumption` | AT-22 | PASS |
| `test_unknown_earlier_request_blocks_later` | AT-18 | PASS |
| `test_unsupported_native_symbol_fails_closed` | AT-15 | PASS |
| `test_verify_does_not_mutate_source_or_database` | AT-09 | PASS |
| `test_worker_timeout_releases_no_unverified_output` | AT-14 | PASS |
| `test_zero_byte_block_reference_is_invalid` | AT-02 | PASS |

## 8. Conformance and remaining engineering

This table is intentionally operational: it separates completed mechanisms from omissions that cannot be resolved by merely relabeling test output.

| Area | Current implementation | Remaining work / prohibited stronger claim |
|---|---|---|
| Five requested commands and four named classes | Real executable paths, tested local cycle | Not the complete frozen runtime feature set |
| CAS wire | Typed T2 self-contained layout retained; 4 MiB default | Optional shared-pool profile rejected; no silent fake pool support |
| Receipt wire / qualified activation | Explicit candidate receipt types and NOT_GRANTED | Production-qualified T2 receipt generation and independently controlled activation are not implemented |
| CLI compatibility | CLI2 root-get/new prune option; strict parser | Old CLI1 envelope and H-only API are not claimed compatible |
| Read-only verify | No source or authority row mutation, ephemeral private acquisition | Does not persist a qualified retained verification receipt; operation/status options intentionally refused |
| Worker messaging | Bounded private JSON job/evidence files plus bounded stdout result | Not exact Turn4 length-prefixed IPC framing |
| Worker counts | Two inherited global kernel slots | Not complete per-role scheduler or separate persistent unreaped-helper reconciliation service |
| Hydration/retry | Isolated whole jobs with persisted stage budgets and immutable prepared source | Full per-block resumable job scheduling/progress is absent; large jobs can remain held |
| Private physical dedup | Within each candidate and exact-root snapshot reuse | Cross-root block-generation registry/pool is not implemented |
| Shared cloud CAS | Disabled | No shared-pool import/reservation implementation or cloud dedup savings claim |
| Cache database | Authority-backed indexed snapshot records | Separate disposable `cache.sqlite3` is not shipped |
| Retention | Export/acceptance/preparation pins and unique private generations | No general last-copy release or abandoned-scratch reconciler; maintenance costs remain visible |
| Prune accounting | Registered generations and managed exports only | Not a complete all-private-disk garbage collector or exact physical SSD-space meter |
| Administration | Explicit candidate enrollment/approval/release/hold APIs | Full authenticated controller integration, production qualification administration and migration protocol are absent |
| Recovery | Missing/replaced authority holds; original receipts retained | Not a complete lossless restore coordinator; invisible whole-trust-base rollback remains out of scope |
| Resource reservations | Conservative registered operation reservations; nonrecording verification free-space checks | Full scheduler-wide handling of every scratch/log reservation and recovery corner needs further work |
| Long-run worker liveness | All final short batches pass | Uninterrupted full-run and saturation problem is not closed |
| Original acceptance harness | 54 real methods, selected subcases, limited negative controls | Entire 32 suites, all 44 inherited obligations, raw forensic evidence and live target qualification remain outstanding |
| Mac adapter | Actual ctypes implementation included | Not executed/qualified on Apple Silicon or FileProvider here |
| Durability | Correctly requested local settings, no stronger claim | Volatile test root cannot establish process-crash or power-loss durability |

The excluded mechanisms from planning remain excluded: Web UI automation, token copying, networked lock daemon, synced mutex, `fileproviderctl`, native Workspace export, cloud garbage collection, provider eviction through deletion, FUSE interception, arbitrary same-user hostile isolation, signatures and unconditional collision detection. These are not promised future modules that a success result secretly assumes.

## 9. Defects found and corrected during this build

**Cross-task cached-root admission:** an earlier candidate could reuse a cached snapshot through a different enrolled intake. The final broker independently compares manifest K and contract hash with the requested task before allocating Q. A dedicated regression checks the rejected cross-task case and zero acceptances.

**Broker operation-intent substitution:** the final broker verifies verb and O-bound K/R rather than relying on its caller to have supplied a matching root. The altered-root regression checks zero Q allocations.

**Occupied output on replay:** an unrelated occupied explicit output cannot become owned merely because a retry finds matching bytes. The final output path distinguishes a known refusal from an unresolved owned publication and retains conflict behavior.

**Export completion gap:** output generation registration/export completion and operation result persistence are tied in the same registry mutation so a completed result does not become a free-standing unprotected handoff.

**Changed source on put retry:** the prepared private checkpoint and root survive as the immutable operation source. A replay does not recapture a changed live pathname as the original intent. Interrupted pre-checkpoint capture remains unresolved instead of manufacturing the lost bytes.

**Worker wait and clock review:** direct child exit is polled independently of pipe EOF; deadlines now use the platform continuous/BOOTTIME clock instead of assuming a generic monotonic clock includes sleep. Final batch digests bind these changes. The longer-run wait still lacks a conclusive root-cause determination and remains explicitly open.

These findings are recorded because a passing happy path alone would not have exposed them. They do not establish absence of further defects.

## 10. Execution and next qualification boundary

The README supplies a disposable enrollment and full-cycle demonstration. Start with a fresh temporary candidate store and the test harness, not an existing production authority. The shipped full harness command is:

```sh
python3.13 test_drive_cas.py --report apple_silicon_results.json
```

That runs synthetic/local tests on the selected host; it does not automatically perform the live network/provider experiments from the original matrix. Bounded batch controls are available and their complete-coverage rule is documented. A successful target rerun would add evidence, not repair the engineering gaps in section 8 or grant a durability label automatically.

Native FileProvider testing, real cellular fault controls and independent-device ingress need explicitly approved disposable fixtures. No instruction in this delivery authorizes killing Drive desktop, deleting user files, filling the system disk or modifying a real authority's history.

## 11. Primary sources and provenance

The architecture basis is the supplied T2/T3/T4 artifact chain; its decisions are attributed there, not silently replaced by internet summaries. The following primary documentation was consulted for narrow implementation facts. None is a test of this code or the target Mac:

- **S01 — Python 3.13 sqlite3:** https://docs.python.org/3.13/library/sqlite3.html — explicit transaction modes and autocommit behavior.
- **S02 — SQLite PRAGMA:** https://www.sqlite.org/pragma.html — effective journal/synchronous/fullfsync/foreign-key/mmap settings. Settings are not durability observations.
- **S03 — Python subprocess:** https://docs.python.org/3/library/subprocess.html — direct child execution, descriptor passing, output, timeout and signal status; no hard kernel-cancellation guarantee.
- **S04 — Apple XNU rename manual:** https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/man/man2/rename.2 — native no-clobber rename contract; actual filesystem support must be tested.
- **S05 — Linux rename manual:** https://man7.org/linux/man-pages/man2/rename.2.html — RENAME_NOREPLACE and filesystem support limits for the Linux fixture adapter.

Review date is 23 September 2026. No current account quota, Google upload speed, native Linux Drive client or discovered private lab dispatcher is asserted.

## 12. Packaging and delivery receipt scope

The archive contains the engine, harness, README, this report, final validation JSON/logs and clearly separated development observations. `MANIFEST.sha256` covers every other archived file, including the validation summaries. The ZIP's detached `.zip.sha256` is outside the ZIP. There is no self-hash cycle or signature claim.

Delivery readback, when separately reported in chat, means the connected Drive tool returned the same bytes for the named artifact at that observation. It does not prove the native CloudStorage mount has synchronized. The connector is an artifact-delivery tool, not a runtime dependency of `drive_cas.py`.

**Final build disposition:** real five-verb implementation and selected executable acceptance cases delivered; 54 exact-source method passes in bounded fresh batches; complete Turn4 conformance and production qualification not granted.
