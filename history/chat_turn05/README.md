# Google Drive Object Engine — Turn 5

**Implementation:** `drive_cas.py`, 0.5.0-rc1. **Runtime:** CPython 3.13 or later, POSIX; standard library only. **Release status:** runnable qualification candidate, not a fully conforming or production-qualified Turn 4 release. Read `CONFORMANCE.md` before integration.

The engine implements the five requested verbs and the `gdoe-cas/1` ordered, typed Merkle format. The code contains no Google credentials, SDK, network client, cloud mutex, provider-backed mmap, `fileproviderctl`, or automatic cloud deletion. The filesystem transport is the already installed native mount; local test directories are also supported in explicitly unqualified lab mode.

## 1. Run the tests first

From the extracted bundle directory, using the intended Python executable:

```sh
python3.13 -m unittest -v test_drive_cas
```

For retained per-test evidence, choose a **new** output directory:

```sh
python3.13 run_validation.py evidence/my-mac-run-001
python3.13 run_negative_controls.py evidence/my-mac-negative-001
python3.13 example_workflow.py evidence/my-mac-cli-example.json
```

No pip installation is needed. Do not use Python's `-O` optimization mode for the harness. The tests use owned temporary directories and never connect to or delete a real Drive account. Actual SIGBUS and SIGKILL injections affect only owned test children. Linux test results are not Apple Silicon or FileProvider qualification. A pass on a Mac's private temporary filesystem still does not qualify the provider-managed volume.

`run_negative_controls.py` modifies **temporary copies** of the engine. It requires the designated assertion to fail for each deliberately broken variant; a syntax error, import failure or arbitrary nonzero exit does not count as defect detection. Never deploy those copies.

## 2. CLI v2: exact interpretation

Common options appear **before** the verb:

```text
python3.13 drive_cas.py [--config PATH] [--operation-id UUID]
    [--wait-ms N] [--offline] [--status-only] VERB ...

put FILE [--dropzone ENROLLED_INTAKE_PARENT]
get SUBMISSION_ROOT_SHA256 [--output DESTINATION]
commit EXACT_SUBMISSION_LEAF
verify EXACT_SUBMISSION_LEAF
prune [--max-size-gb DECIMAL_GB] [--dry-run]
```

These are the only five data-plane verbs. `enroll_example.py` is a separate, explicitly invoked administrative helper; ordinary operations never bootstrap missing authority state.

**Turn 5 changes are intentional:** the writer uses 4,194,304-byte blocks; readers retain both 4 MiB and 16 MiB profiles. `get` takes **R, the SHA-256 of the submission's exact `manifest.json`**, not H, the original file's digest, and not a file-map or dataset digest. The root must identify exactly one logical artifact and be registered as own-prepared or accepted content. The prune spelling is `--max-size-gb`; the older `--max-size` is rejected. The machine envelope is versioned `gdoe-cli/2`, not silently labeled as the frozen v1 output.

`put` returns both `root` and `content_sha256`. Use `root` for `get`. The Merkle DAG is submission → dataset → file map → ordered chunk pages → raw blocks. The whole-file byte digest is checked in addition to the metadata roots. Empty files have zero blocks; a task must independently permit them.

One completed invocation writes one JSON record to stdout. Payload bytes are written to a file, never mixed into stdout. Help/version are metadata requests. Unknown/duplicate/abbreviated options are rejected. `--operation-id` makes retries explicit; retain that UUID. A new UUID is a new operation, not an exactly-once retry.

## 3. Enroll a disposable lab store

The helper creates a **new** local authority and a task, with `mode=LAB_CANDIDATE`. It refuses to overwrite an existing private store. Source and export roots must already exist. The private root must be outside **all** sync services; the engine rejects known Apple CloudStorage/iCloud paths, but your confirmation is still required for other sync products.

Create separate private input/output directories:

```sh
mkdir -p "$HOME/drive-cas-inputs" "$HOME/drive-cas-outputs"
```

Then explicitly select an **existing** exchange/test folder. For the lab, a disposable child of the supplied project folder is appropriate; do not enroll the entire account root or call the documentation folder itself a qualified production store.

```sh
python3.13 enroll_example.py create \
  --private-root "$HOME/Library/Application Support/SovereignDrive/drive-cas-qualification-001" \
  --exchange-root "/absolute/path/to/an/existing/Drive/test-folder" \
  --source-root "$HOME/drive-cas-inputs" \
  --export-root "$HOME/drive-cas-outputs" \
  --campaign lab-transfer \
  --task-id artifact-001 \
  --logical-name artifact.bin \
  --confirm-unsynced-private
```

The helper prints `config` and `intake`. The default config for this example is the new private root's `config.json`. Supply it explicitly; the engine does not search cloud files or the current working directory for authority configuration.

A native mount is not required for initial local functional tests: an existing ordinary local directory can be the exchange in LAB_CANDIDATE mode. That does **not** make it a Google Drive replica. Do not change mode to PRODUCTION and treat a local successful command as independent qualification.

## 4. Publish, approve, check, commit, retrieve

Place one closed input file under the enrolled source root. The public convenience `put` covers one complete single-artifact task, not an accumulating folder.

```sh
CFG="$HOME/Library/Application Support/SovereignDrive/drive-cas-qualification-001/config.json"
python3.13 drive_cas.py --config "$CFG" put "$HOME/drive-cas-inputs/model.bin"
```

The response's `result.root` is R. `result.submission_dir` is the exact leaf used below. The result is **local publication only**; remote synchronization remains `NOT_ASSERTED`.

Approve that exact R through the administrative surface:

```sh
python3.13 enroll_example.py approve --config "$CFG" --root ROOT_FROM_PUT
python3.13 drive_cas.py --config "$CFG" verify SUBMISSION_DIR_FROM_PUT
python3.13 drive_cas.py --config "$CFG" commit SUBMISSION_DIR_FROM_PUT
python3.13 drive_cas.py --config "$CFG" get ROOT_FROM_PUT \
  --output "$HOME/drive-cas-outputs/model.bin"
```

Approval is intentionally separate from a producer's adjacent manifest. Its default lifetime is one hour; `--lifetime-seconds` belongs to the administrative helper. It does not change the content intent. A task revision can accept only one root. Another result requires explicitly enrolling a successor task/revision, not deleting the first acceptance or silently reopening it.

`verify` freshly reads the declared transport closure and does not mutate source files, authority records, task decisions, or persistent pins. It uses a temporary private report which is removed once writer lifetime is closed. Its result is an **OBSERVED_CLOSURE diagnostic**, not a retained, qualified verification receipt. FileProvider itself may hydrate an ordinary read; read-only here does not mean preventing OS cache activity. `commit` separately captures/rechecks retained private bytes and transactionally pins them before admission.

In LAB_CANDIDATE mode, accepted records and receipts are explicitly named `qualification_acceptance` / `ACCEPTED_LAB_CANDIDATE`; they must not be relabeled production evidence. They still exercise actual SQLite uniqueness, request order, retention and exact receipt replay.

`get` never discovers an arbitrary root by globally scanning Drive. It uses the local registered read domain. An external candidate becomes registered for reading through accepted capture; run `commit` under an independently approved task first. A hash is not an access credential. A zero-artifact dataset can be accepted when permitted but cannot be reconstructed as one file by `get`.

## 5. Retention and pruning

With no `--output`, `get` creates an engine-owned retained export at a unique operation path. It is protected across command exit, sleep and unrelated lease expiry. Explicit output paths must be inside an enrolled **unsynchronized** export root. No output is overwritten; even identical bytes at an unrelated occupied destination remain a conflict. Replay ownership is tied to a persisted pre-rename staged-inode proof, not merely an equal checksum.

```sh
python3.13 drive_cas.py --config "$CFG" prune --max-size-gb 100 --dry-run
python3.13 drive_cas.py --config "$CFG" prune --max-size-gb 100
```

GB means decimal gigabytes, with at most three fractional digits. Pins and construction ownership override the requested target. A target below the protected floor returns `HOLD_RESOURCE` and exit 8, not forced deletion. No Drive file, provider cache entry, active reader, accepted snapshot or authority DB is deleted by this verb. Reported accounted bytes are not a promise of physically reclaimed SSD space.

An unmanaged export needs an explicit end-of-use acknowledgment:

```sh
python3.13 enroll_example.py release-export --config "$CFG" \
  --operation-id GET_OPERATION_UUID --end-of-use-reason "All consumers finished"
```

An unaccepted, resolved proposal can be deliberately abandoned with `release-prepared --root R --reason TEXT`. This does not delete its Drive submission. Accepted-source retention cannot be removed through that helper. Incomplete construction and unresolved writer ownership remain protected; general orphan-recovery/reclamation is not implemented in this candidate.

## 6. Replay, offline operation and outbox

Common options precede the verb:

```sh
python3.13 drive_cas.py --config "$CFG" --operation-id OPERATION_UUID \
  --status-only commit SUBMISSION_DIR_FROM_PUT
```

Exact accepted-operation replay returns the original receipt bytes, ID and timestamp. A different root, task binding or destination under the same O is `INTENT_CONFLICT`. Historical receipt status does not establish current cloud or private-file health.

`--offline` prohibits a fresh transport verification and new source capture. It can retrieve registered private content, reconcile a completed decision, or continue from a retained put capture without publishing. This is deliberately stricter than Turn 4's contemplated offline creation from arbitrary new local sources. It cannot stop Drive Desktop from processing a backlog already queued by other activity.

The candidate uses a persistent eight-**worker-dispatch** cap and a conservative continuous-clock window. It does not yet implement the frozen active-time/equal-jitter scheduler. No process is installed to work after a command returns. An explicitly invoked replay or existing lab-controller iteration drives remaining work. A new retry window requires:

```sh
python3.13 enroll_example.py open-retry-window --config "$CFG" \
  --operation-id OPERATION_UUID --reason "Dependencies restored; authorization reviewed"
```

Receipt export is a separate, bounded administrative/controller iteration:

```python
import drive_cas
engine = drive_cas.DriveEngine("/absolute/path/to/private/config.json")
results = engine.service_pending(maximum=1)
```

A receipt-outbox entry exists in the same SQLite transaction as the acceptance. Export success means local receipt publication, not a remote witness. Shared pool imports and direct REST transfers are disabled.

A crash after closed source capture but before registry registration is reconciled from its operation-owned private generation. Successful recovery asks for another replay of the same O. An incomplete/unrecoverable capture returns `SOURCE_CAPTURE_OUTCOME_UNKNOWN`; it does not silently recapture changed source bytes as the same operation. Preserve the held generation for explicit administrative review.

## 7. Exit categories

| Exit | Meaning |
|---:|---|
| 0 | This invocation's stated goal was established, in its reported qualification scope |
| 2 | Invalid command/argument |
| 3 | Pending, offline, finite retry hold, acquisition timeout or contention |
| 4 | Integrity, encoding, source-shape or contract rejection |
| 5 | Task, immutable-intent or destination conflict |
| 6 | Approval, role or read/write scope refusal |
| 7 | Missing enrollment or unqualified/unsupported capability |
| 8 | Resource hold / worker circuit limit |
| 9 | A possible effect or capture outcome needs reconciliation |
| 10 | Authority-history or observed hash-identity incident |
| 11 | Internal contract breach |
| 130 | Caller interrupted; reconcile the original operation |

An uncatchable kill may produce no record. Never infer "nothing happened" from absent stdout.

## 8. Integration boundaries

The lab dispatcher should invoke the enrolled Python interpreter and the absolute `drive_cas.py` path with an argument array. Do not insert operands into a shell command string. The code does not edit the existing `./lab` dispatcher or deploy itself into the user's Mac.

The private registry uses explicit immediate transactions, DELETE journaling, synchronous EXTRA, fullfsync policy, foreign keys and disabled SQLite mmap. The native publisher uses Darwin `renameatx_np(RENAME_EXCL)` or the separately identified Linux test backend `renameat2(RENAME_NOREPLACE)`. There is no check-then-replace fallback. Actual provider-volume support remains untested here.

Staging may be synchronized by Drive. The guarantee is that incomplete/mismatching observations cannot qualify for admission—not that the engine can prevent every partial staging upload. No unkeyed checksum is a digital signature.

See `05_Turn_05_Implementation_Report.md` for exact test/source hashes, actual DDL, coverage and findings. See `CONFORMANCE.md` for the remaining production blockers and `NATIVE_QUALIFICATION.md` for target-only evidence still required.
