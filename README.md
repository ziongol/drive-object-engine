# Google Drive Object Engine — Distributed CAS & FileProvider Isolation Substrate

> **Engineering Provenance & Authorship**: Leonid Majbits / Gemini Operator Lab (ZION Chassis) in partnership with Frontier Systems Foundries (OpenAI GPT-6 Max).  
> **Falsification Guarantee**: Every claim is backed by reproducible raw machine receipts in `/evidence`, verified on Apple Silicon bare-metal hardware (`macOS ARM64`).

**Release:** 1.0.1. Native-signed receipt outbox, explicit activation, protected-generation retirement, and red-team fault-injection stress hardening. Zero third-party dependencies (`pip`). Verified on Darwin metal. Results and remaining native gates are in `06_Turn_06_Production_Qualification_Report.md` and `RELEASE_STATUS.json`.

## Start with the right existing store

Two different Turn 5 builds existed under the same project name. They are not interchangeable:

| Profile | Existing configuration | Retained engine | Prior suite |
|---|---|---|---|
| **NATIVE54** | `protocol: gdoe-config/2` | `drive_cas_native.py`, byte-identical to the 111,891-byte Drive build | 54 methods |
| **CHAT66** | `version: 1` | `drive_cas.py`, extended from the chat-delivered build | 66 methods |

The wrapper checks the explicit configuration format and calls the corresponding implementation. It never converts K, receipt formats, or a live authority database. `SOURCE_LINEAGES.json` gives both original hashes. For the Mac deployment described in the commission, start with **NATIVE54**. Its original source hash is `4c1700151602c9f10a7ac23785f346292bee7251efe915d07ab72f63fe73d065`.

Unpack into a private, unsynchronized code directory. Keep all runtime modules together; do not copy just the wrapper. Do **not** replace your existing `lab` program with the sample launcher. The bundled `lab` works as a standalone launcher, and the integration section below shows the existing-dispatcher entry.

## First run: disposable qualification

Use the intended installed Python 3.13-or-newer interpreter from the extracted directory:

```sh
python3.14 run_release_validation.py evidence/apple-silicon-turn06-001
```

This executes the preserved 54-test source, the 66-test alternate source, and both extension suites, each without batch slicing; at most two independent runner processes run concurrently. Then it runs the eight defective controls. Fixtures own temporary stores only. The runner records source hashes before/after, raw logs, individual results, native environment and explicit scope. An existing output directory is refused so evidence is not overwritten.

This does **not** exercise a real Google FileProvider domain, cellular network, physically independent second device, or power loss. It does run the platform-selected signature backend. On macOS that is Apple Security.framework; on Linux it is a system OpenSSL 3 test backend. Those runs are distinct observations, not interchangeable qualification.

## Install on an enrolled store

Set `CONFIG` to the existing **private** configuration pathname. It must not be a file downloaded from an untrusted producer. The following is an explicit additive migration and key enrollment, not a new-store bootstrap:

```sh
CONFIG="$HOME/Library/Application Support/SovereignDrive/drive-engine/config.json"
python3.14 tools/receipt_admin.py --config "$CONFIG" install
python3.14 tools/receipt_admin.py --config "$CONFIG" initialize-signing
python3.14 tools/drive_engine.py --config "$CONFIG" status
```

Before installation, retain a consistent backup using the existing trusted backup procedure; do not copy a live SQLite file arbitrarily or remove its journal. Coordinate the deployment with the local controller. No command here upgrades old receipts to production status. NATIVE54 installation adds `t6_*` tables and integrity/lifetime triggers; CHAT66 installation adds its corresponding receipt tables. Neither resets authority history, tasks, fences or pins.

Private signing keys are generated on that host and stored under the private root's `keys/` directory, with 0700 directory / 0600 file policy and no-follow access. They are **not** included in this archive and must not be uploaded to Drive. They are file-backed software keys, not Secure Enclave, Keychain ACL, hardware-backed or nonexportable keys.

## Lab commands

The wrapper's standard forms are:

```sh
./lab drive --config "$CONFIG" put /absolute/source/file.bin
./lab drive --config "$CONFIG" get ROOT_SHA256 --output /approved/private/output.bin
./lab drive --config "$CONFIG" verify /enrolled/intake/chunks/ROOT_SHA256
./lab drive --config "$CONFIG" status
./lab drive --config "$CONFIG" prune --max-size-gb 100 --dry-run
./lab drive --config "$CONFIG" prune --max-size-gb 100
```

`get` follows Turn 5's current **submission-root** interface, not the earlier Turn 4 content-H interface. It reconstructs the registered single artifact and returns verified private bytes. `verify` never admits. `put` never marks a task accepted. Native pointers are not exported implicitly. Prune never deletes anything in CloudStorage.

Canonical admission and receipt drainage remain **explicit** optional wrapper verbs:

```sh
./lab drive --config "$CONFIG" --operation-id UUID commit /enrolled/intake/chunks/ROOT_SHA256
./lab drive --config "$CONFIG" drain --maximum 16
./lab drive --config "$CONFIG" --offline drain
```

The strings `UUID` and `ROOT_SHA256` in this reference denote required caller values, not runnable defaults. The initial real task/source enrollment is independent of this code bundle. Existing source/build identity failures must be reviewed, not patched by rewriting a config hash.

### Integrating an existing Python lab dispatcher

Add a routing branch that imports `main` from `tools.drive_engine` and returns `main(arguments_after_drive)`. The function accepts an argument list; it does not parse an assistant prompt or evaluate shell fragments. Preserve all unrelated existing lab commands. No existing repository dispatcher was modified by this delivery.

For the scheduled local lab loop, select the profile once from the trusted configuration and use its explicit bounded service:

```python
from release_profiles import profile
_, _, receipt_module = profile(config_path)
outcomes = receipt_module.ReceiptService(config_path).drain_receipts(maximum=16)
```

This is an ordinary synchronous iteration to run outside the UI thread. It installs no daemon, HTTP server, webhook, cloud lock or automatic scheduler. The controller decides when to call it again. For NATIVE54, replace use of the old unsigned `service_receipt_outbox` in that loop; its unchanged original core still exposes the legacy exporter. Do not call both loops and expect one to configure the other.

## Receipt authenticity and trust

The **new outer envelope** is `gdoe-signed-receipt/1`, using ECDSA P-256 with SHA-256 and DER-encoded signatures. Signing covers the domain-separated exact canonical payload. The payload embeds the original acceptance and verification **bytes** in canonical base64, plus their hashes, K/R/Q/A/G, an audit event/checkpoint, build fingerprint and explicit qualification.

No public key sent inside an untrusted receipt is automatically trusted. Export the verification-only trust snapshot through the trusted local administration path:

```sh
python3.14 tools/receipt_admin.py --config "$CONFIG" public-trust > /private/approved/trust.json
python3.14 tools/verify_receipt.py --trust /private/approved/trust.json --receipt /private/downloaded/receipt.json
```

Provision that public trust snapshot or its digest through an already authenticated channel. A Drive file declaring itself a trust root is not enrollment. The verifier also supports `--expected-sha256` and `--minimum-decision-sequence`; those values must come from independent trusted context. A valid signature proves an enrolled key signed its payload, not that the file is the newest receipt or that every Google replica has received it.

The private outbox persists exact signed bytes before publication. The destination is the enrolled intake's `receipt_outbox/<envelope_sha256>.json`. A crash after rename but before recording success replays the same bytes and destination. Nonmatching occupied files are never overwritten. Staging may itself synchronize partially; only a complete verified envelope qualifies. `LOCAL_PUBLISHED` is not a cloud-upload receipt.

Each drain job has a persistent eight-dispatch budget. Exhaustion remains `HOLD_RETRY`. A new window is an explicit administrative act with a reason:

```sh
python3.14 tools/receipt_admin.py --config "$CONFIG" reopen-window JOB_SHA256 --reason "Dependency restored; approved new attempt window"
```

This new receipt service has a finite per-call/per-job dispatch bound; it is not the full Turn 4 persisted elapsed-time/equal-jitter transport scheduler. The existing lab loop must back off and respect metered-network policy. `--offline` initiates no new receipt provider work, but cannot stop work already queued in Drive by another process.

### Rotation and revocation

Drain pending jobs before planned rotation. `rotate-key` makes the prior key verification-only; sealed prior envelopes remain reusable, but a queued unsealed job bound to the old key does not silently select a different signing identity. A lost/revoked signing key cannot be bypassed with an unkeyed checksum.

```sh
python3.14 tools/receipt_admin.py --config "$CONFIG" rotate-key
python3.14 tools/receipt_admin.py --config "$CONFIG" revoke-key KEY_ID --reason "Approved revocation"
```

Distribute the resulting updated **public** trust snapshot explicitly. Revocation is conservative: a key marked revoked is rejected even for historical receipts. Offline consumers with an old trust snapshot do not learn revocations automatically. ECDSA signatures need not be unique for a message; byte identity comes from the persisted envelope and its SHA-256, not an assumption that signing twice returns the same signature.

## Qualified activation is separate from signing

Historical signing works now without relabeling candidate evidence. NATIVE54 retains `qualification: NOT_GRANTED` inside its original receipts; the outer historical label is `LAB_CANDIDATE_UNQUALIFIED`. CHAT66 likewise preserves its original labels and bytes.

`activate_receipt()` creates a **new attestation** of a freshly reverified, still-protected accepted snapshot. It does not create another acceptance for K, change the original timestamp, or edit the old receipt. It requires an independently reviewed qualification record bound to the **current full runtime fingerprint and environment**, current protected content and authorization. The record requires the 32-suite contract and four new capabilities to be explicitly qualified. The user's reported earlier 54-method run cannot automatically satisfy that gate for this newly added signing adapter.

```sh
python3.14 tools/receipt_admin.py --config "$CONFIG" environment
python3.14 tools/receipt_admin.py --config "$CONFIG" approve-qualification /private/reviewed/qualification.json
python3.14 tools/receipt_admin.py --config "$CONFIG" activate ACCEPTANCE_SHA256 --qualification-id QUALIFICATION_UUID --operation-id OPERATION_UUID
./lab drive --config "$CONFIG" drain
```

The qualification record fields are `qualification_id`, `environment`, `evidence_sha256`, `approved_by`, `mandatory_suites`, `capabilities`, `scope`. `mandatory_suites` records AT-01 through AT-32 individually; capabilities are `native_signatures`, `receipt_drainage`, `generation_lifecycle`, `wrapper`; scope is `PROCESS_CRASH_QUALIFIED`. The administration API validates the bound record and permission boundary; it does not rerun or independently prove an operator's evidence declaration. Never manufacture PASS entries from method count alone. The tests exercise positive activation with an isolated `FIXTURE_ONLY` mock, which has no production flag or configuration shortcut.

## Retirement and protected floor

`retire_generation(G, reason)` transitions only an unpinned eligible generation to `RETIRING`. A later removal targets its unique private path. Interrupted removal can reconcile an already absent path. The same registry serialization and installed triggers exclude new pins on retiring/absent generations. Active-reader, acceptance, preparation, unresolved-work and export pins are not expired by a work lease.

`protected_floor_gb` is an exact decimal string. It is accounted logical bytes of protected physical generations, not a prediction of actual APFS allocated space. Asking for a target below that floor returns a resource hold; it does not erase pins. A returned unmanaged export remains retained until an explicit end-of-use release. Provider eviction and cloud deletion are different operations and remain unavailable to prune.

## Status and recovery

Status uses private registry information only. It does not inspect a provider pathname to manufacture a sync badge. Missing, replaced or untrusted authoritative state halts the corresponding operation. No synchronized lock or second-machine SQLite copy can elect a replacement authority.

The new audit seals are tamper-evident checkpoints under the trusted local-key assumption. For the preserved native core, new base audit rows are sealed at the next extension checkpoint; the software does not claim to have signed them at their original commit. A signature/checkpoint cannot detect rollback of the entire trusted database, keys and checkpoints without an independent retained head.

## What to read next

`06_Turn_06_Production_Qualification_Report.md` records executed results, coverage, defects found/fixed and remaining gates. `SIGNATURE_PROTOCOL.md` specifies trust and exact-byte domains. `NATIVE_QUALIFICATION.md` lists the positive live capabilities still needing qualification. The historical files are immutable source evidence, not current instructions to deploy the older profile blindly.
