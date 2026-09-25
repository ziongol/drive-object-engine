
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


CREATE TABLE t6_meta(key TEXT PRIMARY KEY,value BLOB NOT NULL);
CREATE TABLE t6_audit_seals(ordinal INTEGER PRIMARY KEY REFERENCES audit(ordinal),event_sha256 TEXT NOT NULL UNIQUE,event_bytes BLOB NOT NULL);
CREATE TABLE t6_receipt_keys(key_id TEXT PRIMARY KEY,public_bytes BLOB NOT NULL,private_relative TEXT NOT NULL UNIQUE,backend TEXT NOT NULL,private_format TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('ACTIVE','VERIFY_ONLY','REVOKED')));
CREATE UNIQUE INDEX t6_one_signer ON t6_receipt_keys(state) WHERE state='ACTIVE';
CREATE TABLE t6_qualifications(qualification_id TEXT PRIMARY KEY,record_bytes BLOB NOT NULL,record_sha256 TEXT NOT NULL UNIQUE,active INTEGER NOT NULL CHECK(active IN (0,1)));
CREATE TABLE t6_activations(activation_id TEXT PRIMARY KEY,operation_id TEXT NOT NULL UNIQUE,receipt_sha256 TEXT NOT NULL REFERENCES acceptances(receipt_hash),qualification_id TEXT NOT NULL REFERENCES t6_qualifications(qualification_id),fresh_bytes BLOB NOT NULL,audit_ordinal INTEGER NOT NULL REFERENCES audit(ordinal));
CREATE TABLE t6_receipt_outbox(sequence INTEGER PRIMARY KEY AUTOINCREMENT,job_id TEXT NOT NULL UNIQUE,source_kind TEXT NOT NULL CHECK(source_kind IN ('HISTORICAL','ACTIVATION')),source_id TEXT NOT NULL,receipt_sha256 TEXT NOT NULL REFERENCES acceptances(receipt_hash),task_key TEXT NOT NULL REFERENCES tasks(k),key_id TEXT NOT NULL REFERENCES t6_receipt_keys(key_id),body_bytes BLOB NOT NULL,envelope_bytes BLOB,envelope_sha256 TEXT UNIQUE,state TEXT NOT NULL DEFAULT 'PENDING',attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),last_error TEXT,published_path TEXT,UNIQUE(source_kind,source_id));
CREATE TRIGGER t6_immutable_body BEFORE UPDATE OF job_id,source_kind,source_id,receipt_sha256,task_key,key_id,body_bytes ON t6_receipt_outbox BEGIN SELECT RAISE(ABORT,'receipt intent immutable'); END;
CREATE TRIGGER t6_signature_once BEFORE UPDATE OF envelope_bytes,envelope_sha256 ON t6_receipt_outbox WHEN OLD.envelope_bytes IS NOT NULL BEGIN SELECT RAISE(ABORT,'signed bytes immutable'); END;
CREATE TRIGGER t6_audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'audit append only'); END;
CREATE TRIGGER t6_audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'audit append only'); END;
CREATE TRIGGER t6_seal_no_update BEFORE UPDATE ON t6_audit_seals BEGIN SELECT RAISE(ABORT,'audit seal immutable'); END;
CREATE TRIGGER t6_seal_no_delete BEFORE DELETE ON t6_audit_seals BEGIN SELECT RAISE(ABORT,'audit seal immutable'); END;
CREATE TRIGGER t6_acceptance_no_update BEFORE UPDATE ON acceptances BEGIN SELECT RAISE(ABORT,'acceptance immutable'); END;
CREATE TRIGGER t6_acceptance_no_delete BEFORE DELETE ON acceptances BEGIN SELECT RAISE(ABORT,'acceptance immutable'); END;
CREATE TRIGGER t6_pin_live_insert BEFORE INSERT ON pins WHEN (SELECT state FROM generations WHERE g=NEW.g) NOT IN ('AVAILABLE','CORRUPT') BEGIN SELECT RAISE(ABORT,'generation cannot be pinned'); END;
CREATE TRIGGER t6_pin_live_update BEFORE UPDATE OF g ON pins WHEN (SELECT state FROM generations WHERE g=NEW.g) NOT IN ('AVAILABLE','CORRUPT') BEGIN SELECT RAISE(ABORT,'generation cannot be pinned'); END;
