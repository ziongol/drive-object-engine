# Drive CAS — executable candidate 0.5.0

A standard-library-only content-addressed dropzone engine for **one private local
admission authority** and an asynchronous, untrusted exchange filesystem.

**Release status:** executable qualification candidate, not a production-qualified
or fully Turn-4-conformant release. All decisions and command results explicitly
carry `qualification: NOT_GRANTED`. No passing Linux fixture upgrades a Mac,
FileProvider installation, filesystem, clock, or durability tier.

Read `05_Turn_05_Implementation_Report.md` for implemented scope, exact SQLite DDL,
measured test results, and remaining engineering/qualification work. The report's
conformance table is part of the release contract, not an optional disclaimer.

## Files

- `drive_cas.py`: all five commands, strict CAS parser/builder, authority registry,
  process supervisor, native no-replace adapter, and private lifetime management.
- `test_drive_cas.py`: executable unittest cases, independent byte/history checks,
  fault fixtures and machine-readable results. No pip packages are needed.
- `validation/`: recorded runs and their exact source/environment bindings.
- `MANIFEST.sha256`: hashes every other bundle member. It does not hash itself.

## Observed validation for this delivery

The delivered engine/harness pair passed **54 unittest methods in 18 fresh-process
batches**, with zero failures, errors or skips; all batch digests match the sealed
source pair. This covers selected subcases under 16 original suite labels, not
all 32 original suites. See `validation/test_results.json` and the individual logs.

Longer grouped development runs exceeded the execution environment's time limits;
the underlying worker wait was not conclusively isolated. **A single uninterrupted
full-harness run and supervisor soak remain unproven.** The shorter batches do not
establish that the long-run issue is fixed. This is a release blocker, not a reason
to describe the candidate as production-ready.

The observed host was Linux x86-64, Python 3.13.5, SQLite 3.46.1, on overlayfs with
`fsync=volatile`. No durability or Apple Silicon/FileProvider qualification follows
from these tests. Full production receipt activation and other runtime work remain
unimplemented, as detailed in the report.

## Requirements and first execution

Use **CPython 3.13 or newer**, on macOS or Linux. Windows is not supported.
macOS operations use `renameatx_np(RENAME_EXCL)` through `ctypes`; Linux operations
use `renameat2(RENAME_NOREPLACE)`. Unsupported primitives fail; there is no
replace/copy/link fallback. Linux tests do not qualify macOS behavior.

From the extracted bundle:

```sh
python3.13 test_drive_cas.py --report apple_silicon_results.json
```

The default harness creates and removes its own temporary fixtures. It never
opens the real lab's database or changes the user's Drive account, network,
provider settings or files. Its local native-rename fixture runs on the actual
temporary filesystem selected by the host. It does **not** automatically conduct
live FileProvider, cellular, independent-device or power-loss experiments.

Individual suites and bounded batches are available:

```sh
python3.13 test_drive_cas.py --suite AT-18 --suite AT-22 --report selected_results.json
python3.13 test_drive_cas.py --batches 18 --batch-index 0 --report batch_00.json
```

Batch indexes run from zero to `batches - 1`. A complete batch campaign requires
all indexes, the same engine/test digests, and no missing or duplicate tests.
Do not treat the selected suite IDs as claims that every original Turn 4 subcase
has been implemented or qualified.

## Explicit enrollment: no data command invents an authority

The five verbs require a previously enrolled private configuration and task.
Enrollment is an explicit Python administrative API. It is not an extra public
CLI verb, an OAuth flow, a network daemon, or a cloud-supplied configuration.

This disposable local demonstration exercises the same engine without touching
Drive. Run it from the directory containing `drive_cas.py`:

```python
from pathlib import Path
import tempfile
import drive_cas as cas

base = Path(tempfile.mkdtemp(prefix="drive-cas-demo-")).resolve()
exchange = base / "exchange"
exchange.mkdir()
outputs = base / "outputs"
outputs.mkdir()
config = base / "config.json"

cas.enroll_store(
    config, base / "private", exchange,
    export_roots=[str(outputs)],
)
cas.enroll_task(
    config,
    campaign="demo",
    task_id="artifact-001",
    artifacts=[cas.artifact_slot("artifact.bin", allow_empty=True)],
    selection="EXACT_ROOT",
)
source = base / "input.bin"
source.write_bytes(b"A retained, independently checked artifact.\n")
engine = cas.DriveEngine(config)
proposal = engine.put(str(source))
cas.approve_candidate(config, proposal["root_hash"])
verification = engine.verify(proposal["submission_dir"])
acceptance = engine.commit(proposal["submission_dir"])
retrieved = engine.get(proposal["root_hash"], output=str(outputs / "verified.bin"))
assert Path(retrieved["output_path"]).read_bytes() == source.read_bytes()
print({"config": str(config), "proposal": proposal, "acceptance": acceptance,
       "retrieved": retrieved})
```

The default free-space reserve is **max(2 GiB, 5% of private-volume capacity)**.
A resource refusal is an expected outcome on a nearly full volume. The test
harness explicitly uses smaller resource settings in disposable fixtures; do not
copy those fixture exemptions into a deployment merely to bypass a hold.

For actual Drive intake, explicitly create a dedicated runtime directory under
an already working, verified Drive mount, then enroll that existing directory.
Keep the configuration and private root outside **all** synchronization trees.
The caller must establish that deployment fact; a directory name alone cannot.
Do not point experimental enrollment at an existing authority directory.
The documentation dropzone is not implicitly a runtime authority.

Enrollment creates `chunks/` and `receipts/` inside the selected existing intake.
It never creates a missing account mount. Root inode/device identities are pinned.
Changing them requires controlled reenrollment, not a copied sentinel file.

The trusted task fixes exact logical paths, roles, media types, empty-content
permission, size bounds and optionally an independently expected content digest.
`EXACT_ROOT` requires `approve_candidate` before external verification/admission.
`ANY_VALID_ENROLLED` instead authorizes any structurally valid candidate for the
**already enrolled task contract**. It does not authenticate a producer label.
Use that broader policy deliberately, not as an unnoticed default.

## Command reference

All common options precede the verb. Paths containing spaces must be quoted.
There are no silent legacy aliases.

```text
python3.13 drive_cas.py [--config PATH] [--operation-id UUID]
                      [--wait-ms 1..900000] [--offline] [--status-only]
                      put FILE [--dropzone INTAKE_PARENT]

python3.13 drive_cas.py [common options] get ROOT_HASH [--output DEST]
python3.13 drive_cas.py [common options] commit SUBMISSION_LEAF
python3.13 drive_cas.py [common options] verify SUBMISSION_LEAF
python3.13 drive_cas.py [common options] prune [--max-size-gb DECIMAL_GB] [--dry-run]
```

The default configuration is
`~/Library/Application Support/SovereignDrive/drive-engine/config.json`.
An existing `./lab drive-engine` dispatcher can forward arguments to this script
using its explicitly selected Python executable. This bundle does not edit or
claim to have inspected the lab's actual dispatcher.

### put

Uses **4,194,304-byte blocks**. Non-EOF short reads do not terminate a block;
exact multiples do not create an empty tail. Identical blocks share one stored
block file inside a candidate, while repeated references preserve repeated bytes.
The T2 page/file-map/dataset/submission wire format remains `gdoe-cas/1`.
The reader still accepts the 16 MiB layout when the independent task permits it.

`--dropzone` selects an enrolled intake **parent**, not a final leaf.
The result's `root_hash` is the SHA-256 of exact root-manifest bytes, and the
completed candidate is published at `INTAKE/chunks/ROOT_HASH/`.
One `put` is one complete single-artifact proposal. It is not an append operation.
The Python builder can construct a complete multi-artifact or empty dataset.

Success means **local publication**, not task acceptance or remote upload.
Staging inside Drive can itself sync. Renaming a sealed tree and verifying its
entire closure prevents false consumption; it cannot prohibit Google's daemon
from observing staging files or turn sync into a remote transaction.

### get

`ROOT_HASH` means **submission-manifest R**, not logical content hash H, file-map
hash, dataset hash, or an arbitrary block key. This intentionally changes Turn 4's
H-only interface in accordance with the Turn 5 instruction. CLI protocol is
therefore `gdoe-cli/2`, not an undocumented reinterpretation of `gdoe-cli/1`.

A prepared/accepted private root is resolved from the local registry. A previously
unseen external root needs an explicit `approve_candidate` locator binding before
it can be captured. No unbounded Drive scan or cross-client lookup is performed.
`get` requires exactly one logical file; a multi-artifact/empty dataset returns
`TASK_SHAPE_UNSUPPORTED` rather than guessing an artifact.

The complete private output is checked before handoff. The normal path never
reopens a mutated Drive pathname to supply accepted file bytes. A current corrupt
private generation is marked ineligible and requires explicit reconciliation.

An explicit destination must lie inside an approved unsynchronized export root.
An unrelated existing output is refused even when its bytes match, including on
retry after that refusal. An unresolved owned publication can reconcile its exact
bytes. There is no force/overwrite option.

Without `--output`, the returned private export remains retained after command
exit. The operator explicitly acknowledges end of use:

```python
cas.release_export(config, export_operation_id, reason="The consumer has finished; no remaining use")
```

Release does not delete the output immediately; it makes that export generation
eligible for `prune`. Acceptance and preparation pins remain separate. Releasing
an export does not release the last private copy of an accepted proposal.

### commit

The operand is exactly `INTAKE/chunks/ROOT_HASH`, not a parent to scan recursively.
Only the registered local authority may submit canonical decisions. The broker
binds the operation, task K, snapshot contract and root together before allocating
Q. A snapshot from one task cannot satisfy another task merely because it is cached.

Q orders eligible requests; A records decisions. Unknown earlier requests block
advancement. Recorded obsolete requests can be blocked before later work proceeds.
A unique constraint on K excludes authority epoch and prevents a second root for
an unchanged task revision. Decisions, retained snapshot pins and exact receipt
outbox bytes commit together. Receipts are **unsigned candidate evidence**.

An explicit controller iteration exports already committed receipts:

```python
engine.service_receipt_outbox()
```

This does not install a daemon. A pending export does not undo an already committed
local decision and never becomes an invented remote witness.

### verify

Fresh full-closure observation. It writes **no source files, authority rows,
operations, acceptance decisions or pin records**. It uses isolated, ephemeral
private capture/readback and keeps bounded private job diagnostics. It is therefore
not literally a zero-I/O operation. Failed/uncertain private scratch can remain for
safe investigation. A fresh observation cannot be replaced by an older cache hit.
`--operation-id` and `--status-only` are not supported for this nonrecorded verb.

No production-qualified verification receipt is minted from scratch that is then
removed. The result describes checked bytes and a matched structural task contract;
it does not assess the content's scientific or business correctness.

### prune

`--max-size-gb` uses decimal GB: 1 GB = 1,000,000,000 bytes; up to three fractional
digits. It is not the binary MiB unit used for blocks.
The target covers **registered private generations and managed exports**, not
provider-cache allocation, logs, reservations or uncertain unregistered scratch.
No amount of disk pressure overrides a pin. A target below the protected floor
returns `HOLD_RESOURCE`, possibly after removing eligible garbage.

`--dry-run` performs no retirement or deletion. Unknown readers and accepted or
unresolved content stay protected. This implementation does not automatically
release preparation/acceptance lifetime, collect cloud objects, dehydrate provider
files, or repair a corrupted object in place.

## Replay, errors and supervision

Retain the caller's operation UUID. Same O with changed intent is a conflict.
A completed `put`/`commit` replay can return historical evidence while the original
Drive path is unavailable. A normal `get` replay rechecks its current output;
`--status-only` returns only stored evidence, without implying fresh health.

The supervisor runs direct child interpreters with bounded output and private
job files. Two stable, inherited **slot** locks cap simultaneous helpers across
controllers. They are not authority locks. A live timed-out child retains its
slot even after its caller exits. Late work uses unique paths and cannot edit
SQLite authority. No provider-backed mmap or signal-resume trick is used.

Mac deadlines use `mach_continuous_time` and a boot-session identity; Linux fixture
deadlines use `CLOCK_BOOTTIME`. Approval is checked against both boot-scoped time
and UTC. Existing accepted history is never reopened by a new epoch.

Persistent provider-stage retries have eight attempts and a 900-second active
budget, with recorded backoff. Known offline calls do not dispatch provider jobs.
A new window requires explicit `open_retry_window` administration and never
renews business approval. This release supervises **whole jobs**, not a complete
per-block resumable hydration scheduler; see the conformance report.

| Exit | Meaning |
|---:|---|
| 0 | The named command's specific goal was established; qualification remains separate |
| 2 | Invalid command grammar |
| 3 | Incomplete, contention, offline, timeout or retry hold |
| 4 | Structural, content or task-contract rejection |
| 5 | Intent, existing output or accepted-task conflict |
| 6 | Authorization/fence refusal |
| 7 | Missing or unsupported binding/capability |
| 8 | Resource or helper-circuit hold |
| 9 | Mutation outcome needs reconciliation |
| 10 | Authority/identity incident or recovery required |
| 11 | Internal defect |
| 130 | Caller interruption; absence of success is not proof that no effect occurred |

Never reset a missing/corrupt/restored authority by deleting its database.
`enter_recovery(config, reason)` records a stop barrier; it is not a lossless restore
implementation. The source digest is enrolled; changing code requires controlled
build review, not silent reuse of an old qualification claim.
