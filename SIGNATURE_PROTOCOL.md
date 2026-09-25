# Signed receipt protocol / 1

## Domain and algorithm

`gdoe-signed-receipt/1` uses ECDSA P-256 / SHA-256 / ASN.1 DER signatures through the native cryptographic provider. Signed input is the bytes `GDOE-SIGNED-RECEIPT-V1`, followed by a single zero byte, followed by the **exact canonical payload bytes**. No handwritten elliptic-curve implementation or private-key operation is shipped in Python arithmetic.

Key ID is SHA-256 of `GDOE-P256-PUBLIC-V1`, a single zero byte, then the 65-byte uncompressed SEC1 public point. Public trust is an independently enrolled record scoped to one store and authority. Private keys never appear in a receipt, log or archive.

The outer object has exactly: `protocol`, `algorithm`, `key_id`, `payload_b64`, `signature_b64`. JSON uses sorted keys, compact separators, ASCII-safe encoding and one final LF. Base64 must round-trip canonically with bounds. The complete encoded envelope is bounded below the 65,536-byte worker/result ceiling. The SHA-256 filename covers this entire final envelope.

## Payload fields

Exactly: `protocol`, `event_type`, `store_id`, `authority_id`, `task_key`, `submission_sha256`, `decision_sequence`, `request_sequence`, `snapshot_id`, `acceptance_b64`, `acceptance_sha256`, `verification_b64`, `verification_sha256`, `audit_event_b64`, `audit_event_sha256`, `qualification`, `activation`, `build`, `prepared_at_utc`.

Protocol is `gdoe-receipt-attestation/1`. `event_type` is HISTORICAL or ACTIVATION. Original inner receipt bytes are embedded without rewriting. Their digests, root, contract, store, authority and snapshot bindings are checked before signing and by the public verifier. K is the four-field task record; Q orders eligible requests; A identifies the original decision; G identifies the retained physical snapshot.

The audit event is the exact sealed normalized event with sequence, action, detail, time and predecessor hash. For NATIVE54 the original ACCEPTED_LOCAL row supplies k/root/q/a; for CHAT66 the ACCEPT row supplies task/root/O/Q/A. All are observations of the one local SQLite history, not consensus proofs. A native base audit event created after extension install may remain an unsealed tail until the next checkpoint. The signed envelope does not claim a signature existed before that checkpoint.

Historical qualification remains LAB_CANDIDATE_UNQUALIFIED for both candidate kinds. A preexisting legitimately qualified CHAT66 receipt retains its qualified label; this path does not synthesize it. `activation` is null for historical records.

Activation includes its new ID, qualification ID and record hash, exact fresh-evidence bytes and their SHA-256. Positive production activation requires a current-build, current-environment, externally approved PROCESS_CRASH_QUALIFIED record and a fresh retained-snapshot verification. Unit tests can supply FIXTURE_ONLY solely through local test mocks. The original acceptance is never replaced, and replay of the activation operation returns the same activation.

## Persistence and publication

The original acceptance/outbox transaction remains unchanged. The extension queues a deterministic source identity (historical receipt digest or activation ID), binds the selected key and immutable payload, creates one signature, then persists exact envelope bytes before the first provider attempt. An immutable signature field cannot be rewritten to make a retry look new.

Native publication uses an attempt-specific staged file and no-clobber final install at `receipt_outbox/<envelope hash>.json`. A lost publication response remains UNKNOWN; the same bytes and pathname are reconciled. An occupied, nonmatching target is a conflict. A directory may expose partial staging through Drive; that never certifies a complete signed envelope.

Every generation/receipt transition is guarded locally, not by synchronized cloud locks. Different authority histories cannot be merged by comparing signatures or choosing the largest epoch. One signature does not appoint a new authority.

## Security limits and verification

Verify with independently obtained trust, exact protocol/algorithm, public-key ID consistency, mathematical signature validation, canonical payload and all inner byte bindings. An optional expected envelope digest binds exact signature bytes. An optional minimum decision sequence rejects receipts below an independently trusted checkpoint; neither discovers a missing newest receipt.

ECDSA need not yield a unique signature for a payload, and DER serialization alone is not a claim of low-S uniqueness. The persisted envelope is the exact retry identity. Key revocation is distributed as a new trusted snapshot; an offline verifier with old trust cannot infer it. All keys marked REVOKED are rejected, including historical use.

Private software keys reside in file-backed 0600 storage; they are not protected against the same OS identity, root, memory compromise, or rollback of all trusted state. A chain stored on the same disk is not a nonrollback witness. Checkpoint/trust signatures establish who attested the payload, not that all test declarations are true, that a captured artifact is scientifically correct, or that Drive has uploaded it.
