
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
CREATE TRIGGER pins_only_live_generations BEFORE INSERT ON pins
WHEN (SELECT state FROM generations WHERE generation_id=NEW.generation_id) NOT IN ('WRITING','AVAILABLE','CORRUPT')
BEGIN SELECT RAISE(ABORT,'cannot pin a retiring or absent generation'); END;
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


CREATE TABLE audit_seals (
 audit_sequence INTEGER PRIMARY KEY REFERENCES audit(sequence),
 event_sha256 TEXT NOT NULL UNIQUE, event_bytes BLOB NOT NULL);
CREATE TABLE receipt_keys (
 key_id TEXT PRIMARY KEY, public_bytes BLOB NOT NULL, private_relative TEXT NOT NULL UNIQUE,
 backend TEXT NOT NULL, private_format TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('ACTIVE','VERIFY_ONLY','REVOKED')), created_at_utc TEXT NOT NULL);
CREATE UNIQUE INDEX receipt_one_active_key ON receipt_keys(state) WHERE state='ACTIVE';
CREATE TABLE receipt_qualifications (
 qualification_id TEXT PRIMARY KEY, record_bytes BLOB NOT NULL,
 record_sha256 TEXT NOT NULL UNIQUE, active INTEGER NOT NULL CHECK(active IN (0,1)));
CREATE TABLE receipt_activations (
 activation_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE,
 receipt_sha256 TEXT NOT NULL REFERENCES acceptances(receipt_sha256),
 qualification_id TEXT NOT NULL REFERENCES receipt_qualifications(qualification_id),
 fresh_evidence_bytes BLOB NOT NULL, fresh_evidence_sha256 TEXT NOT NULL,
 audit_sequence INTEGER NOT NULL REFERENCES audit(sequence), created_at_utc TEXT NOT NULL);
CREATE TABLE signed_receipt_outbox (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL UNIQUE,
 source_kind TEXT NOT NULL CHECK(source_kind IN ('HISTORICAL','ACTIVATION')),
 source_id TEXT NOT NULL, receipt_sha256 TEXT NOT NULL REFERENCES acceptances(receipt_sha256),
 binding_id TEXT NOT NULL REFERENCES bindings(binding_id),
 key_id TEXT NOT NULL REFERENCES receipt_keys(key_id), body_bytes BLOB NOT NULL,
 envelope_bytes BLOB, envelope_sha256 TEXT UNIQUE,
 state TEXT NOT NULL DEFAULT 'PENDING', attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
 last_error TEXT, published_path TEXT, UNIQUE(source_kind,source_id));
CREATE TRIGGER receipt_body_immutable BEFORE UPDATE OF source_kind,source_id,receipt_sha256,binding_id,key_id,body_bytes ON signed_receipt_outbox
BEGIN SELECT RAISE(ABORT,'receipt intent is immutable'); END;
CREATE TRIGGER receipt_signature_once BEFORE UPDATE OF envelope_bytes,envelope_sha256 ON signed_receipt_outbox
WHEN OLD.envelope_bytes IS NOT NULL
BEGIN SELECT RAISE(ABORT,'signed bytes are immutable'); END;
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'audit is append only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'audit is append only'); END;
CREATE TRIGGER seals_no_update BEFORE UPDATE ON audit_seals BEGIN SELECT RAISE(ABORT,'audit seal is immutable'); END;
CREATE TRIGGER seals_no_delete BEFORE DELETE ON audit_seals BEGIN SELECT RAISE(ABORT,'audit seal is immutable'); END;
CREATE TRIGGER IF NOT EXISTS pins_only_live_generations BEFORE INSERT ON pins
WHEN (SELECT state FROM generations WHERE generation_id=NEW.generation_id) NOT IN ('WRITING','AVAILABLE','CORRUPT')
BEGIN SELECT RAISE(ABORT,'cannot pin a retiring or absent generation'); END;
CREATE TRIGGER pins_only_live_updates BEFORE UPDATE OF generation_id ON pins
WHEN (SELECT state FROM generations WHERE generation_id=NEW.generation_id) NOT IN ('WRITING','AVAILABLE','CORRUPT')
BEGIN SELECT RAISE(ABORT,'cannot pin a retiring or absent generation'); END;
