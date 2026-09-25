# Turn 5 — Python implementation, selected acceptance harness and delivery report

**Project:** Google Drive Distributed Object Substrate & Atomic Chunk Dropzone Orchestrator  
**Commission:** Gemini Operator Lab / Leon / Open Research / Sovereign Systems  
**Date:** 23 September 2026  
**Code version:** `0.5.0-rc1`  
**CAS wire:** `gdoe-cas/1`, `ascii-json-1`  
**Local interfaces:** `gdoe-cli/2`, `gdoe-worker/2`  
**Release disposition:** RUNNABLE IMPLEMENTATION CANDIDATE — FULL TURN 4 CONFORMANCE NOT CLAIMED; PRODUCTION QUALIFICATION NOT GRANTED  
**Engine SHA-256:** `5a6c036f147bcd0877b0b75e2349b30a3ade0c8af49500c3738ed0e4d6e31da9`  
**Test source SHA-256:** `a95b32b2c607ad86206df6bf5b601d04713eadc61070fa95004bf12aa1d4912a`  
**Integrity:** The bundle's `MANIFEST.sha256` identifies the final complete report and all other members. The archive checksum is detached. These are unkeyed integrity checks, not signatures.

## 1. What was built and what was actually established

This delivery contains executable Python, not another planning specification. All five requested verbs execute through the supplied `drive_cas.py`, with standard-library hashing, strict typed Merkle verification, isolated filesystem jobs, a local SQLite admission broker, protected private generations, no-clobber publication, and pin-aware reclamation. The selected acceptance cases are executable in `test_drive_cas.py`.

The final run executed **66 test methods: 66 passed, no failures, no errors and no skips**. The source and test hashes were recorded before and after the run and did not change. A separate runner constructed **eight deliberately defective temporary source copies**; each designated test detected its intended defect. A subprocess workflow exercised put, verify, commit, get, prune dry-run, and real prune, and compared reconstructed bytes to the independently retained source.

These are **Linux x86-64 observations**, not Apple Silicon, APFS, Google FileProvider, cellular, two-device, or power-loss qualification. They also do not mean all 32 original acceptance suites have been fully implemented. The seven specifically requested suites have selected implemented cases; the remaining tests exercise additional boundaries. Several material parts of the full Turn 4 freeze remain incomplete, as enumerated in §10 and `CONFORMANCE.md`. This package must not be described as a completely matching, production-ready implementation merely because its selected tests pass.

The default explicit enrollment helper creates `LAB_CANDIDATE` stores. Their receipt kinds and acceptance states are visibly unqualified. Production mode requires separately approved evidence bound to the exact code, configuration and runtime; the selected harness does not create such an approval. Filling an approval record with invented PASS values cannot resolve the incomplete implementation or qualify the host.

### 1.1 Recorded final execution

| Item | Observed value |
|---|---|
| Python | 3.13.5 |
| SQLite runtime | 3.46.1 |
| Platform / architecture | linux / x86_64 |
| Kernel release | 6.18.44 |
| Started, UTC | 2026-09-23T19:20:13.833656+00:00 |
| Finished, UTC | 2026-09-23T19:23:04.708636+00:00 |
| Test-run elapsed time | 170.874971 seconds; a measurement of this run, not a future estimate |
| Test methods | 66; some methods contain multiple subcases |
| Failures / errors / skips | 0 / 0 / 0 |
| Deliberately defective controls | 8 / 8 detected |
| Five-verb subprocess workflow | Six command invocations including dry-run and actual prune; independent output comparison succeeded |
| Actual Google Drive runtime I/O | None; test fixtures used owned temporary local directories |
| Production qualification | NOT_GRANTED |

The final authoritative run records are `evidence/final_run_02/results.json` and `unittest.log`. The final negative-control record is `evidence/negative_controls_02/results.json`. Earlier runs, when included under development evidence, have their own source hashes and are not substituted for the final run.

### 1.2 Input identity and explicit precedence changes

The audited Turn 4 document's **whole-file** digest is `c2127e7a6c5546be7fa5bf8b624aef8f81c2c163cbb14361d1c4dcc1fe8ac023`. The current commission quotes `97a46f3bfd99ab0ac19c5d44063bac330d7f6703f19f686ec9bd776a418af7e3`, which is the correctly labeled **specification-body** digest in that document's header. They are distinct scopes, not conflicting versions. The acceptance-matrix whole-file digest is `0231d9915073b4eee043e234905a91cbf969250212e2252c8d71b9b0282961b8`.

The current implementation request explicitly changes the default writer from 16 MiB to 4 MiB, asks get to use a root hash rather than Turn 4's H-only operand, and changes the prune option spelling to `--max-size-gb`. It also asks for verification without mutation. This build implements those latest forms and records its local interface changes as version 2 rather than silently claiming v1 compatibility. The CAS metadata format remains unchanged.

| Domain | Turn 5 interpretation |
|---|---|
| B, writer block size | 4,194,304 bytes; `fixed-4m-v1` |
| Reader profiles | Both `fixed-4m-v1` and `fixed-16m-v1` |
| R | SHA-256 of the exact submission `manifest.json` bytes; get's only hash namespace |
| H | SHA-256 of reconstructed logical bytes; still returned and checked, not guessed as R |
| K | Store / campaign / task / task revision; authority epoch is not part of uniqueness |
| Read-only verify | No persistent source/authority/pin mutation; a current observed-closure diagnostic, not a retained qualified receipt |
| Prune option | `--max-size-gb`; exact decimal GB conversion; old spelling is rejected |
| Public entrypoint | `drive_cas.py`; no remote edit of the existing `./lab` dispatcher was performed |

## 2. Package and execution boundaries

`drive_cas.py` is self-contained. Its imported modules are Python standard-library modules; the static import inventory is retained in `evidence/dependency_inventory.json`. The native no-clobber and clock adapters use `ctypes` to call operating-system interfaces. This adds a platform requirement, not a pip dependency. The child runner invokes the same Python executable and exact script directly, without a shell or downloaded code.

The complete delivery adds executable helpers for explicit lab enrollment, test recording, negative controls, and a disposable CLI example. They import the bundled engine and do not install packages. Tests and examples affect only newly created owned temporary fixtures unless the operator deliberately enrolls a different already-existing exchange root. There is no credential, bearer token, network endpoint, or assumption about Fortress's Linux Drive ingress in the code.

| File | Purpose |
|---|---|
| `drive_cas.py` | Five-verb engine, strict wire codec, native adapters, registry, broker, verifier, lifetime manager |
| `test_drive_cas.py` | 66 executable test methods for selected obligations and additional guards |
| `run_validation.py` | Records test log, per-method verdicts, environment and before/after source hashes |
| `run_negative_controls.py` | Compiles deliberately defective temporary copies and requires designated assertion failures |
| `enroll_example.py` | Explicit administrative setup/approval/release helper; LAB_CANDIDATE creation only |
| `example_workflow.py` | Disposable end-to-end CLI demonstration and independent byte check |
| `schema.sql` | Exact DDL extracted from the engine's `DDL` literal; not a separate migration implementation |
| `README.md` | Execution guide, exact CLI meanings, enrollment and replay examples |
| `CONFORMANCE.md` | Implemented scope, current-instruction changes and material full-freeze gaps |
| `NATIVE_QUALIFICATION.md` | Target-only requirements still unexecuted |
| `evidence/` | Final results, negative controls, subprocess workflow, dependency/schema checks and development findings |
| `MANIFEST.sha256` | Checksums for every other release member |

The release ZIP is a packaging artifact. It is not a transaction across Google Drive replicas. Its detached checksum binds the ZIP after creation; neither the archive nor its manifest tries to contain its own ordinary full-file hash.

## 3. Concrete architecture and class ownership

### 3.1 Trust and roots

The exchange tree transports untrusted candidates. The private root owns the authoritative database, current task contracts and approvals, operation identities, immutable generations, pins and acceptance history. Engine consumers receive verified private bytes, not a mutable Drive pathname opened after an unrelated verification.

Enrollment binds the private root and database identities, stable guard inode, exchange root, intake/chunks directories, source roots and export roots. Runtime data commands do not initialize a missing authority. A copied sentinel does not replace root continuity. A test specifically replaces the outer exchange directory while retaining the original nested intake inode; that is still rejected.

The local trusted program, configuration, database and private storage form the trusted computing base. This does not sandbox an arbitrary malicious process with the same operating-system privileges. Public agent strings remain provenance claims rather than authentication.

### 3.2 Required classes

| Class | Implemented responsibility | Does not do |
|---|---|---|
| `CASChunkManager` | Builds fixed-block self-contained candidates, node references and exact totals from captured sources | Canonical task acceptance; shared-pool import or protected physical cross-generation deduplication |
| `MerkleVerifier` | Strict root/node/marker checks, ordered full reconstruction, length and whole-file digest, destination readback, membership and independent contract | Automatic admission, source repair, pointer execution, remote upload certification |
| `DropzoneAdmissionBroker` | Registers durable eligible Q requests, checks K uniqueness/current approval/fence, advances the queue, stores one decision and exact receipt | Cloud mutexes, cross-host authority election, network-order-independent winner selection |
| `LocalCacheEvictor` | Plans deterministic private reclamation, serializes pin checks with RETIRING, deletes the unique private generation, accounts for held floor | Cloud deletion, forced pin release, provider eviction or arbitrary recursive user-folder cleanup |

`DriveEngine` connects those components to the five public operations. `AuthorityRegistry` owns explicit transaction boundaries and typed records. `SafeTree` provides descriptor-relative no-follow traversal. `WorkerSupervisor` executes fixed job kinds with bounded frames and retained kernel-held slots. `AtomicPublisher` wraps no-clobber native installation. `ClockPolicy` supplies a boot-bound continuous-clock observation.

The implementation deliberately keeps these classes in one importable file. The module's API contains explicit administrative enrollment, approval, recovery and end-of-use actions; they are not an implicit sixth data-plane command and do not derive authority from a candidate.

### 3.3 What is atomic

The publisher prepares closed bytes, copies and checks them in an attempt-owned destination-filesystem stage, and installs the final file or directory through the no-clobber adapter. Darwin uses `renameatx_np` with `RENAME_EXCL`; the independently identified Linux local-test backend uses `renameat2` with `RENAME_NOREPLACE`. Unsupported capability returns an error, not exists-check plus replacement. [P1]

An existing final candidate must pass exact expected identity and byte-tree comparison before an identical retry can succeed. A mismatch is not overwritten or merged. A staging suffix or leading dot is not assumed to prevent Google from synchronizing the stage: partial transport observations remain inadmissible. This preserves Turn 2 §5 and Turn 3's explicit exclusion of remote transactional guarantees.

For explicit get outputs, a matching checksum alone cannot establish ownership. The export stores a pre-rename staged-inode proof in private operation-owned scratch. A lost rename response can be reconciled against that original proof; an unrelated occupied file remains OUTPUT_EXISTS even if it contains the same bytes.

Admission is a separate SQLite transaction. It records the unique K decision, retained snapshot protection, exact receipt bytes and receipt-outbox item together. There is no filesystem-plus-SQLite distributed transaction. A crash before the decision may leave a protected orphan; a crash after it may leave pending receipt export. Neither creates another accepted root.

## 4. Data plane and integrity checks

### 4.1 Typed content representation

A raw block contains only its data-fork bytes. Its path is derived from its complete SHA-256 digest. Each chunk-page node contains an ordered array of at most 4,096 references. A file map names ordered pages, exact length, exact block-reference count, fixed-layout profile and H. A dataset names ordered artifact paths/roles/media types and file maps. The root manifest binds dataset identity to store, campaign, task revision, contract digest, producer attempt and recomputed totals.

The empty file has zero pages and zero blocks, with the empty-stream SHA-256. A dataset containing no artifacts is a valid wire structure only when the independently enrolled task permits it. The public single-file put/get conveniences do not mistake an empty dataset for an empty file.

`ascii-json-1` is checked against the exact captured bytes. Duplicate keys, unknown fields, noncanonical whitespace/escaping, floats, booleans in integer positions, excessive depth/size, and invalid typed edges are rejected. Parsing and reserializing an invalid record is not a repair path.

A short read is not EOF. Packing continues until the block is full or real EOF is observed. Exact multiples do not produce a phantom empty tail. Readers enforce the fixed profile's expected page lengths, block lengths and final remainder. Repeated references remain repeated logical bytes; unique-object totals are separate.

### 4.2 Verifier sequence and expected-root trust

Verification captures the marker and exact root, checks R and its agreed length/attempt, validates the independently enrolled task contract, then walks only the allowed decreasing node types. Each metadata reference is checked against both byte length and digest. A repeated digest cannot carry inconsistent declared lengths elsewhere in the graph.

Each raw block is read through EOF checks, including an extra-byte check beyond the expected length; a valid prefix followed by a suffix does not pass. Logical reconstruction follows the references' original order. H is computed from reconstructed bytes, not a hash of hexadecimal leaf hashes. The retained destination is separately read back before its generation is eligible.

For self-contained delivery, expected members must actually be obtained from that delivery. A privately cached equivalent cannot hide a missing submitted member. Unexpected observed payload members prevent a clean structural verdict. These are observations of the finite local traversal, not a universal time-invariant snapshot of Google's namespace.

An entirely rehashed alternate graph is not automatically authorized. Exact-root approval or an explicitly enrolled candidate-selection policy is required at the task boundary. A producer-supplied adjacent checksum or claimed identity cannot replace the local root policy. A zero-byte file may be correctly encoded and still violate its task's empty-file rule.

### 4.3 Hash collisions and stored tampering

Changed captured bytes normally fail the expected length or SHA-256. A genuine equal-length collision is not unconditionally detectable by re-running the same hash. When two independently available equal-key samples differ byte-for-byte, the reuse path rejects the contradiction and preserves the existing representation rather than overwriting it. The artificial equal-key fixture tests that control flow; it does not claim to construct a real cryptographic collision.

Known private mismatch blocks current consumption. A historical acceptance remains a historical record; get must not use it as permission to skip current destination checks. Conversely, a later source-only edit cannot replace an already verified private generation. Tests change and remove the transport representation, then compare the actual delivered output to the original independently retained bytes.

## 5. Worker, FileProvider and operation lifetime

All normal exchange-tree access is performed by fixed-function children. That includes root identity checks, stat, enumeration, open, reads, writes, flush and rename. The controller does not probe provider files merely to display progress, and it never maps provider content. Actual Darwin dataless flags, where available, are observations recorded before acquisition, not success predicates. No synthetic flag is changed or stripped. [P2]

The supervisor directly starts the enrolled interpreter with the known script and an internal worker mode. It drains framed stdout and stderr through selectors, rejects oversized or mismatched result frames, and checks child exit before using a result. It attempts termination at a deadline and stops waiting within its bounded reap policy. A user-space timeout is not a guarantee that a blocked kernel operation was canceled. [P3]

Two acquisition slots and one publication slot are private, stable kernel-locked files. Their descriptors and the per-operation execution guard are deliberately inherited by the child, while the authority guard and live SQLite connection are not. A surviving child continues holding its slot even after parent exit. This prevents an endless replacement-worker sequence and operation-path reuse without claiming perfect remote failure detection. It is a conservative candidate scheduling profile, not complete implementation of every Turn 4 invocation/scheduler field.

Each construction path belongs to a unique invocation or generation. A completed put capture whose registry acknowledgment was lost may be recovered from that owned closed generation. An uncertain or incomplete capture is held, not silently replaced by a new capture from a changed source pathname under the same O. Some unresolved constructions therefore retain disk until explicit review; comprehensive orphan reconciliation is still a conformance gap.

A managed generation can have construction, preparation, reader, source-retention, export or acceptance-retention pins. Pins are in the authoritative database. Work-lease or approval expiry does not end consumer lifetime. An unmanaged get export remains protected until explicit end-of-use acknowledgment. Prune does not guess end of life from inactivity or PID appearance.

The candidate's ordinary-read route can trigger OS hydration. It cannot export native Google documents transparently, guarantee the provider's network volume, or prevent an unrelated program from blocking when it opens Drive directly. Optional provider eviction, clone, REST and remote-witness controls remain disabled.

## 6. Local authority, request ordering and recovery

Task identity K is unique across retained authority history. A local epoch increase does not create a new slot for the same task. Eligible requests receive Q sequence numbers after their verified protected evidence and approval are checked. Decision sequence A is separate. The broker handles Q in stored order, records a blocked earlier request before moving on, and does not bypass an earlier UNKNOWN transaction outcome.

At admission it rechecks the current task, root, fence, boot-bound grant, approval version/deadline, generation pins, incidents and qualification scope. Both same-O replay and same-K/R aliasing return the exact stored original receipt rather than creating a second timestamp or operation identity. Different intent under O is a conflict; a different root under accepted K is TASK_ALREADY_ACCEPTED.

The registry uses explicit low-level autocommit and SQL BEGIN IMMEDIATE / COMMIT / ROLLBACK, plus a separate stable local flock guard in the same acquisition order. No hash, provider call, subprocess wait or long reconstruction occurs inside that authority transaction. DELETE journal, synchronous EXTRA, foreign keys and disabled database mmap are read back. The connection requests fullfsync, but this candidate does not separately read back that PRAGMA or qualify its target effect; that check remains part of native-profile completion. These settings do not certify power-loss behavior. [P4, P5]

An explicit recovery state blocks admission after known restore or lost/untrusted history. The code does not automatically create an empty replacement authority, select a newest-looking cloud backup, or elect another host. Undetectable rollback of the entire trusted configuration and database together is outside this local trust model; the documented recovery guard is not represented as an external anti-rollback service.

Receipt export is a bounded, separately invoked `service_pending` action. It writes exact already-committed evidence and records local publication. It does not produce a second acceptance or a remote witness. There is no installed background daemon. Further progress after a hold requires a replay or an actual existing lab-controller iteration.

## 7. Actual SQLite schema

The following is extracted directly from the tested module's `DDL` literal. The byte-identical SQL is also supplied as `schema.sql`. It executed successfully in an isolated in-memory SQLite 3.46.1 database: 15 application tables, integrity result `ok`, and no foreign-key-check findings. That check validates schema creation, not journal durability, migration safety or historical correctness.

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE tasks (
 task_key TEXT PRIMARY KEY, contract TEXT NOT NULL, contract_sha256 TEXT NOT NULL,
 selection_policy TEXT NOT NULL CHECK(selection_policy IN ('EXACT_ROOT','ENROLLED_CANDIDATE')),
 lifecycle TEXT NOT NULL DEFAULT 'OPEN' CHECK(lifecycle IN ('OPEN','CLOSED','ACCEPTED')),
 fence INTEGER NOT NULL DEFAULT 1 CHECK(fence>0));
CREATE TABLE bindings (
 binding_id TEXT PRIMARY KEY, task_key TEXT NOT NULL REFERENCES tasks(task_key),
 path TEXT NOT NULL UNIQUE, identity_json TEXT NOT NULL, chunks_identity_json TEXT NOT NULL);
CREATE TABLE approvals (
 task_key TEXT NOT NULL REFERENCES tasks(task_key), root TEXT NOT NULL,
 version INTEGER NOT NULL CHECK(version>0), boot TEXT NOT NULL,
 deadline_ns INTEGER NOT NULL, expires_utc TEXT NOT NULL,
 PRIMARY KEY(task_key,root));
CREATE TABLE operations (
 operation_id TEXT PRIMARY KEY, command TEXT NOT NULL, intent TEXT NOT NULL,
 intent_sha256 TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'PENDING',
 phase TEXT NOT NULL DEFAULT 'NEW', generation INTEGER NOT NULL DEFAULT 0,
 attempts INTEGER NOT NULL DEFAULT 0, window_boot TEXT NOT NULL,
 window_start_ns INTEGER NOT NULL, root TEXT, generation_id TEXT,
 attempt_id TEXT NOT NULL, created_at_utc TEXT NOT NULL,
 result_json TEXT, error_json TEXT);
CREATE TABLE generations (
 generation_id TEXT PRIMARY KEY, relative_path TEXT NOT NULL UNIQUE,
 owner_operation TEXT NOT NULL REFERENCES operations(operation_id),
 root TEXT, state TEXT NOT NULL CHECK(state IN ('WRITING','AVAILABLE','CORRUPT','RETIRING','ABSENT')),
 accounted_bytes INTEGER NOT NULL DEFAULT 0 CHECK(accounted_bytes>=0),
 ordinal INTEGER NOT NULL UNIQUE);
CREATE TABLE pins (
 generation_id TEXT NOT NULL REFERENCES generations(generation_id),
 owner TEXT NOT NULL, kind TEXT NOT NULL,
 PRIMARY KEY(generation_id,owner,kind));
CREATE TABLE snapshots (
 generation_id TEXT PRIMARY KEY REFERENCES generations(generation_id),
 root TEXT NOT NULL, task_key TEXT NOT NULL REFERENCES tasks(task_key),
 summary_json TEXT NOT NULL, verification_json TEXT NOT NULL);
CREATE INDEX snapshots_root ON snapshots(root);
CREATE TABLE admission_requests (
 request_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 operation_id TEXT NOT NULL UNIQUE REFERENCES operations(operation_id),
 task_key TEXT NOT NULL REFERENCES tasks(task_key), root TEXT NOT NULL,
 generation_id TEXT NOT NULL REFERENCES snapshots(generation_id),
 fence INTEGER NOT NULL, approval_root TEXT NOT NULL, approval_version INTEGER NOT NULL,
 grant_boot TEXT NOT NULL, grant_deadline_ns INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('QUEUED','BLOCKED','REJECTED','DECIDED','UNKNOWN')),
 reason TEXT);
CREATE TABLE acceptances (
 decision_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 task_key TEXT NOT NULL UNIQUE REFERENCES tasks(task_key), root TEXT NOT NULL,
 operation_id TEXT NOT NULL UNIQUE REFERENCES operations(operation_id),
 generation_id TEXT NOT NULL REFERENCES snapshots(generation_id),
 request_sequence INTEGER NOT NULL REFERENCES admission_requests(request_sequence),
 receipt_bytes BLOB NOT NULL, receipt_sha256 TEXT NOT NULL UNIQUE,
 verification_bytes BLOB NOT NULL, qualified INTEGER NOT NULL CHECK(qualified IN (0,1)));
CREATE TABLE receipt_outbox (
 receipt_sha256 TEXT PRIMARY KEY REFERENCES acceptances(receipt_sha256),
 receipt_bytes BLOB NOT NULL, binding_id TEXT NOT NULL REFERENCES bindings(binding_id),
 state TEXT NOT NULL DEFAULT 'PENDING', attempts INTEGER NOT NULL DEFAULT 0);
CREATE TABLE exports (
 operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
 generation_id TEXT NOT NULL REFERENCES generations(generation_id),
 path TEXT NOT NULL, managed INTEGER NOT NULL, released INTEGER NOT NULL DEFAULT 0);
CREATE TABLE incidents (
 incident_id TEXT PRIMARY KEY, reason TEXT NOT NULL, root TEXT,
 generation_id TEXT, detail_json TEXT NOT NULL, created_at_utc TEXT NOT NULL);
CREATE TABLE qualifications (
 qualification_id TEXT PRIMARY KEY, record_json TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE audit (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL,
 detail_json TEXT NOT NULL, at_utc TEXT NOT NULL);
```

### 7.1 Relationships that matter

`tasks.task_key` is the application-serialized K. `acceptances.task_key UNIQUE` enforces at most one row in the current retained authority database. The claim across time additionally requires the nonrollback/recovery assumptions; a uniqueness constraint in a restored old file cannot recover missing history.

`admission_requests.request_sequence` and `acceptances.decision_sequence` are separate AUTOINCREMENT sequences. A request has a protected snapshot, original operation, stored root and current authority context. `acceptances` stores both receipt byte strings rather than regenerating a narrative at lookup time. `receipt_outbox` references the committed receipt digest.

`generations.relative_path UNIQUE` prevents path reuse. Pins refer to the exact generation, not just a digest. Snapshot summaries and original verification records attach to those generations. Generation ordinals give deterministic local prune order without relying on cloud timestamps.

`operations` preserves the original intent and digest, completion state, captured root/generation, attempt ID, creation timestamp and dispatch/window counters. Not every frozen invocation phase is represented as its own relation in this candidate; §10 lists that gap rather than attributing nonexistent history to the DDL.

Many wire/type/authorization predicates are enforced by application validation rather than DDL CHECK clauses. Direct same-privilege database edits can bypass those checks and exceed this threat model. `schema.sql` is for audit and controlled schema inspection; users must not run it against an existing authority as a reset procedure. Enrollment is explicit and missing-state recovery is fail closed.

## 8. CLI and administrative handoff

The README is the full execution guide. The public grammar is:

```text
python3.13 drive_cas.py [--config PATH] [--operation-id UUID]
    [--wait-ms N] [--offline] [--status-only] COMMAND ...

put FILE [--dropzone ENROLLED_INTAKE_PARENT]
get SUBMISSION_ROOT_SHA256 [--output DESTINATION]
commit EXACT_SUBMISSION_LEAF
verify EXACT_SUBMISSION_LEAF
prune [--max-size-gb DECIMAL_GB] [--dry-run]
```

Common options occur before the verb. Duplicates, abbreviations and unknown options fail. The JSON output separates command goal, goal_met, exit category, operation identity, result and explicit remote-evidence status. The condensed v2 envelope is a documented migration from, not a complete implementation of, every v1 status field. Verify has no persistent stored operation, so `--status-only verify` is rejected explicitly.

Put requires an enrolled single-artifact task and captures its source before sealing a new self-contained candidate. Successful put is local publication, not admission. Get resolves a registered own-prepared or accepted R and only one logical file, reconstructs/checks it privately, then returns an explicit retained export or publishes under an approved unsynchronized destination root. It never falls back to interpreting H or globally scanning Drive. Commit alone requests authority admission. Verify is a fresh read-only diagnostic. Prune deletes only eligible engine-owned private generations.

The helper creates LAB_CANDIDATE mode only; its confirmation of unsynchronized private placement is an operator prerequisite, not an automatic universal sync-root detector. Exact approval of a produced R is separate from put. The helper can explicitly release an unmanaged export after use, release a resolved unaccepted preparation, or open a new retry window with a recorded reason. None silently releases an accepted snapshot.

The installed `./lab` wrapper was not changed. It should eventually call the enrolled Python executable and `drive_cas.py` with an argument array. Do not splice operands into a shell command or infer that this delivery has deployed itself onto Leon's machine.

## 9. Executed coverage and adversarial evidence

### 9.1 Seven requested obligations

Counts below are test methods, not counts of original complete suites. PASS refers only to the tests executed on this recorded host.

| Original suite | Executed methods | Concrete exercised checks | Remaining scope limit |
|---|---:|---|---|
| AT-02 | 4 | Empty file permitted/forbidden, allowed/forbidden empty datasets, illegal stored zero-byte BlockRef | No claim of all deployment contract combinations |
| AT-03 | 3 | Both 4/16 MiB boundary arithmetic, B−1/B/B+1/2B, repeated non-EOF short reads, no empty tail | No target throughput claim |
| AT-06 | 6 | Early EOF, suffix beyond expected prefix, same-length tamper, wrong whole-file hash, exact read without expected hash, recomputed totals | Cross-reference inconsistent length is an additional method elsewhere |
| AT-07 | 4 | Reference order, legitimate repetition, fully rehashed unauthorized alternate root, noncanonical/root bytes not repaired | Expected fixture bytes/policy remain independent of producer claims |
| AT-15 | 3 | Native local file/directory no-clobber, occupied destination, explicitly unsupported backend without fallback | Linux syscall observations only; Darwin/FileProvider and all cross-volume cases not qualified |
| AT-18 | 5 | Durable Q order across reopen, earlier UNKNOWN blocks bypass, epoch cannot reopen K, stale fence, two real competing processes | Two local processes are not two independent devices |
| AT-22 | 5 | Destination tamper before readback, persistent-state-free verify, later private corruption, source tamper/loss, source change after good capture | Same-privilege hostile mutation after final check remains outside protection |
| Additional groups | 36 | Publication replay, retained pins, explicit export ownership, root/role/enrollment guards, restored-history barrier, dispatch timeout, injected SIGBUS, actual postdecision SIGKILL, offline gate, receipt export and CLI | Selected narrower subcases, not all remaining original suites |
| **Total** | **66** | **66 PASS; 0 failures/errors/skips** | **No complete 32-suite or production qualification claim** |

The test oracle uses deterministic expected bytes, independent integer packing counts, explicit known digest values where appropriate, raw output comparisons and direct read-only SQLite observations. It does not ask the production MerkleVerifier to declare its own result correct. The standard-library SHA-256 implementation is still a shared platform primitive; two uses of it are not independent cryptographic algorithms.

### 9.2 Defective-control executions

| Deliberate defect | Designated failing test | Observed result |
|---|---|---|
| `SHORT_READ_IS_EOF` | `TestAT03.test_short_reads_are_not_eof` | DETECTED |
| `NO_EXACT_LENGTH_CHECK` | `TestAT06.test_read_exact_without_hash_is_still_exact` | DETECTED |
| `PERMISSIVE_CANONICAL_ENCODING` | `TestRecoveryAndContainment.test_raw_canonical_only_guard` | DETECTED |
| `RENAME_OVERWRITES` | `TestAT15.test_file_no_clobber_native` | DETECTED |
| `STALE_FENCE_ACCEPTED` | `TestAT18.test_stale_fence_blocks_request` | DETECTED |
| `NO_DESTINATION_READBACK` | `TestAT22.test_destination_tamper_before_readback_detected` | DETECTED |
| `UNOWNED_EQUAL_OUTPUT_REUSED` | `TestRecoveryAndContainment.test_unrelated_equal_output_stays_unowned_on_retry` | DETECTED |
| `MERKLE_EDGE_ORDER_IGNORED` | `TestAT07.test_reordered_leaves_rehashed_metadata_wrong_reconstruction` | DETECTED |

The runner first checks that each mutation site is unique and compiles the modified temporary copy. It then requires the named test to fail by an assertion, without import/syntax errors. The negative result cannot be counted as detection merely because a process returned nonzero. Raw logs and modified-source digests are retained, while mutation recipes in the runner allow reproduction. The delivered engine was not modified by that process.

### 9.3 Actual process and failure observations

The two-process race started two genuine Python CLI processes against one local registry. Exactly one root was accepted for K. The loser returned the required task-conflict category after the classification fix recorded below. This is local arbitration evidence, not replication or distributed-mutex evidence.

The postdecision crash test uses a named test-only callback after the decision transaction commits, terminates only the owned child with SIGKILL, reopens the registry and verifies exact receipt replay plus retention/outbox state. The SIGBUS test sends an actual synthetic signal to an owned child and observes that the parent remains alive; it is not evidence that FileProvider evicted an active mapping. A separate controlled sleeping child tests bounded waiting and unregistered late output. None tests a kernel panic or a permanently uninterruptible disk operation.

The CLI workflow uses a 4,194,560-byte deterministic input, obtains a root from put, explicitly approves it, runs verify/commit/get, compares the returned output to the original, then exercises prune planning and protected-floor refusal. Its raw argv/JSON/exit observations are retained in `evidence/cli_workflow.json`. No model tokens or remote API requests occur in these test workflows.

### 9.4 Development findings, not erased failures

An earlier long suite invocation was interrupted by its execution wrapper after 200 seconds; it is retained as an incomplete development log, not a pass. A focused race run exposed loser exit category 6, TASK_NOT_OPEN, instead of category 5, TASK_ALREADY_ACCEPTED, when another process committed between the optimistic lookup and request registration. One-root safety was preserved, but the externally visible conflict contract was wrong. The broker was changed to check the existing acceptance in the request-registration transaction. The test oracle was not weakened.

Review also replaced hash-only export reconciliation with the original staged-inode proof. An independently occupied equal-content file must not become this operation's output on a second retry. Further checks protect failed-capture identity, outer-root continuity and production prune qualification. Final tests and defective controls ran against the final hash printed in this report.

## 10. Material outstanding full-freeze work

The following are implementation/conformance limitations, not merely absent Mac measurements. They must remain visible when evaluating the production request.

| Area | Present implementation | Outstanding requirement |
|---|---|---|
| Physical deduplication | Dedup/reuse inside one self-contained candidate; equal content may be duplicated in separate private generations | Protected cross-generation object index and full lifecycle/dedup protocol |
| Shared pool | Explicitly unsupported; no preacceptance promotion or cloud GC | Single-steward import, reservation/reconciliation and all shared-pool tests |
| Metadata cache | Trusted snapshot/read indexes in the authority database | Separate disposable `cache.sqlite3` and rebuildable hint behavior |
| Resource reservations | Size ceilings, per-write observed free-space reserve, pins preserved | Durable aggregate reservation ledger, pending-source quota and full AT-27 failure campaign |
| Retry/outbox scheduler | Persisted eight worker dispatches and conservative continuous window; explicit replay | Full active-time/equal-jitter scheduler, next-eligibility records and complete receipt transport operation/window model |
| Worker contract | Bounded fixed-function v2 jobs and inherited private slots | Full frozen J history, separate private-validation scheduling, complete binding-ID envelope and per-block deadlines |
| Command/status contract | Requested five forms; explicitly versioned condensed v2 status | Full v1 migration/compatibility coverage expected by an existing caller |
| Read-only verify | Fresh nonpersistent observed-closure diagnostic | Deliberately not a retained successful verification receipt; consumers must honor the changed scope |
| Large/multi-artifact workloads | Bounded typed datasets in API; one-artifact conveniences | High-count page/dataset/amplification, IPC-envelope capacity and native-scale measurements |
| Orphan lifecycle | Closed capture recovery and safe holds for ambiguity | Complete administrative owner reconciliation, abort and safe orphan retirement |
| Environment | Linux local filesystem tests; Darwin adapter source supplied | Actual Apple Silicon, APFS/FileProvider, sleep/reboot, cellular, second device and stronger durability evidence |

The source does not conceal these gaps behind successful placeholder methods. Unsupported operations refuse. Some conservative holds preserve safety while sacrificing availability. A full production release still needs the missing implementation work plus the remaining mandatory tests. See `CONFORMANCE.md` for precise boundaries, and `NATIVE_QUALIFICATION.md` for target experiments.

The built-in qualification gate binds its evidence to source/runtime/configuration and separates test-only diagnostic receipts. It is not a substitute for independent engineering review and cannot prove that a declarative external PASS record is truthful. Do not enable a production store by inventing that record or claiming the 66 methods represent all 32 suites.

## 11. Reproduction and Apple Silicon handoff

Run from the extracted bundle using the intended interpreter:

```sh
python3.13 -m unittest -v test_drive_cas
python3.13 run_validation.py evidence/apple-silicon-run-001
python3.13 run_negative_controls.py evidence/apple-silicon-negative-001
python3.13 example_workflow.py evidence/apple-silicon-cli-example.json
```

Choose new evidence paths; the validation runners preserve existing runs rather than overwrite them. These commands do not enroll the real Drive project or touch production task data. The test signal/crash fixtures act only on owned temporary children. The CLI example is a local fixture; it is not a FileProvider test merely because it runs on a Mac.

For a disposable native-mount test, follow the explicit enrollment guide in the README using an existing approved test folder and independent source copies. Record the real macOS, Python, SQLite, Drive, root/volume and native adapter versions. Establish genuine dataless conditions and actual operator-approved network interruption separately. Missing live setup means BLOCKED_ENVIRONMENT, not a mocked target PASS.

Full release qualification retains Turn 4's 32-suite matrix and independent negative oracles. Private-filesystem no-clobber success does not qualify the provider-managed volume. An injected signal is not spontaneous provider behavior; a process kill is not power loss; two processes are not two devices. Recovery from a known old database requires an explicit history barrier, not a claim that every undetectable rollback can be found locally.

## 12. Persistence and receipt scope

The intended destination remains the verified `Google_Drive_Object_Engine` folder, ID `1p9XS4zIGL9rIUvbbLSQ7XmU6oWLeTfD2`. During this turn, the available connected Google Drive actions exposed metadata/search/read functions but no upload action. An explicit upload-action discovery returned no result; the available plugin-management actions did not provide a way to add it. Consequently **this report and bundle are delivered as verified local downloadable artifacts, not falsely claimed Drive deposits**. The account was not disconnected and no conclusion about its underlying write permissions was drawn from the absent tool.

The root `MANIFEST.sha256` covers every other archived member. The ZIP checksum is in `Google_Drive_Object_Engine_Turn_05_Code_Bundle.zip.sha256`, outside the archive. Packaging verification checks archive CRC, complete unique membership and every listed SHA-256 against the sealed local files. None of those packaging checks is evidence of arrival on Leon's CloudStorage mount or of engine runtime qualification.

## 13. Sources, authority and new implementation decisions

**Normative source inputs:** Turn 2 §3/§12 defines the retained exact CAS and receipt schemas; Turn 3 A01–A07 defines the guard amendments; Turn 4 defines the wider production and 32-suite qualification contract. The current Turn 5 request authorizes implementation and the documented 4 MiB/root-get/prune/read-only-verification changes. Current code behavior and test results are evidenced by the supplied source and raw results, not inferred from those earlier prose specifications.

External maintainer documentation was used narrowly for platform semantics; it does not qualify the deployed system:

- **P1 — Apple XNU rename manual:** `https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/man/man2/rename.2`. Native no-clobber semantics and support limits, not a cross-device transaction.
- **P2 — Python stat:** `https://docs.python.org/3/library/stat.html`. SF_DATALESS is an observation flag, not upload or permanent retention evidence.
- **P3 — Python subprocess:** `https://docs.python.org/3/library/subprocess.html`. Direct process invocation, pipe handling and timeout limits; not universal kernel cancellation.
- **P4 — SQLite PRAGMA:** `https://www.sqlite.org/pragma.html`. Effective settings, synchronous behavior and readback; not a power-loss qualification result.
- **P5 — Python 3.13 sqlite3:** `https://docs.python.org/3.13/library/sqlite3.html`. Explicit transaction/autocommit behavior; local transactions do not span Drive.

**Final result:** a real, tested five-verb implementation candidate with reproducible selected evidence and explicit remaining production work. It is not a full-Turn-4-conformance certificate, an Apple Silicon result, a remote synchronization receipt, or a digital signature.
