"""Turn 6 receipt authentication, explicit activation and restart-safe drainage.

The versioned outer envelope signs unchanged historic receipts. Signing alone
NEVER upgrades an old LAB receipt. Explicit production activation additionally
requires independently enrolled current-build qualification and fresh protected
snapshot readback. Native signing keys remain private; receipts contain no keys.
"""
from __future__ import annotations
import contextlib
import hashlib
import os
from pathlib import Path
import platform
import sqlite3
import stat
import sys
from typing import Callable
import drive_cas as cas
from receipt_crypto import ALGORITHM, DOMAIN, CryptoError, b64, unb64, native_backend, public_id

VERSION='0.6.0-rc1'
RUNTIME_FILES=('drive_cas.py','drive_cas_native.py','receipt_crypto.py','receipt_engine.py','native_receipts.py','native_jobs.py','release_profiles.py','tools/drive_engine.py','tools/receipt_admin.py')
EXTENSION_DDL='''
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
'''

def build_fingerprint() -> dict:
    root=Path(__file__).resolve().parent
    return {name:cas.sha((root/name).read_bytes()) for name in RUNTIME_FILES}

def release_environment(cfg: dict) -> dict:
    return dict(runtime=cas.environment_record(),build=build_fingerprint(),
                config_sha256=cas.sha(cas.json_bytes(cfg)),crypto_backend=native_backend().name)

def _script(conn,script):
    pending=''
    for line in script.splitlines(True):
        pending+=line
        if sqlite3.complete_statement(pending):
            conn.execute(pending); pending=''
    cas.require(not pending.strip(),'SCHEMA_SCRIPT_INCOMPLETE',code=11)

def install_extension(config_path: str) -> dict:
    """Explicit additive migration. No authority reset, no signing key generation."""
    cfg=cas.load_config(config_path)
    cas.require(cfg['role']=='authority','AUTHORITY_LOCAL_ONLY',code=6)
    with cas.AuthorityRegistry(cfg) as reg, reg.transaction() as c:
        old=c.execute("SELECT value FROM meta WHERE key='receipt_extension_version'").fetchone()
        if old:
            cas.require(cas.json_read(old[0].encode())==1,'EXTENSION_VERSION_UNSUPPORTED',code=7)
            check_audit(reg)
            return dict(state='ALREADY_INSTALLED',version=1)
        _script(c,EXTENSION_DDL)
        # This seals a present observation of existing audit rows, NOT a claim
        # that those rows were cryptographically authenticated when first made.
        for row in c.execute('SELECT * FROM audit ORDER BY sequence').fetchall():
            cas.seal_audit_row(c,row['sequence'],row['action'],row['detail_json'],row['at_utc'])
        c.execute("INSERT INTO meta VALUES('receipt_extension_version',?)",(cas.json_bytes(1).decode(),))
        reg.log(c,'INSTALL_RECEIPT_EXTENSION',dict(version=1,prior_history='IMPORTED_AT_UPGRADE',build=build_fingerprint()))
    return dict(state='INSTALLED',version=1,production_qualification='NOT_CHANGED')

def require_extension(reg):
    r=reg.db.execute("SELECT value FROM meta WHERE key='receipt_extension_version'").fetchone()
    cas.require(r is not None and cas.json_read(r[0].encode())==1,'RECEIPTS_NOT_INITIALIZED',code=7)

def check_audit(reg, maximum: int = 100000) -> dict:
    """Verify retained chain against audit rows and head in one read snapshot.

    A whole-trust-base rollback is NOT detectable without an independent head.
    Call inside the caller's write/read transaction when concurrency is possible.
    """
    require_extension(reg)
    rows=reg.db.execute('SELECT a.*,s.event_sha256,s.event_bytes FROM audit a LEFT JOIN audit_seals s ON s.audit_sequence=a.sequence ORDER BY a.sequence')
    prev='0'*64; count=0; last=0
    for r in rows:
        count+=1; cas.require(count<=maximum,'AUDIT_LIMIT',code=8)
        expected=cas.json_bytes(dict(protocol='gdoe-audit/1',sequence=r['sequence'],action=r['action'],
            detail=cas.json_read(r['detail_json'].encode()),at_utc=r['at_utc'],previous_sha256=prev))
        cas.require(r['event_bytes'] is not None and bytes(r['event_bytes'])==expected
            and cas.sha(expected)==r['event_sha256'],'AUDIT_HISTORY_MISMATCH',code=10)
        prev=r['event_sha256']; last=r['sequence']
    h=reg.meta('audit_head')
    cas.require(h==dict(sequence=last,sha256=prev),'AUDIT_HISTORY_MISMATCH',code=10)
    cas.require(reg.db.execute('SELECT COUNT(*) FROM audit_seals').fetchone()[0]==count,'AUDIT_HISTORY_MISMATCH',code=10)
    return h

@contextlib.contextmanager
def read_snapshot(reg):
    owned=not reg.db.in_transaction
    if owned: reg.db.execute('BEGIN')
    try: yield
    finally:
        if owned: reg.db.execute('ROLLBACK')

def initialize_signing(config_path: str, rotate: bool = False) -> dict:
    cfg=cas.load_config(config_path); install_extension(config_path)
    backend=native_backend()
    with cas.AuthorityRegistry(cfg) as reg:
        old=reg.db.execute("SELECT * FROM receipt_keys WHERE state='ACTIVE'").fetchone()
        if old and not rotate:
            return dict(key_id=old['key_id'],state='EXISTING',public_key_b64=b64(bytes(old['public_bytes'])))
        private,public=backend.generate(); kid=public_id(public)
        keyrel='keys/'+kid+'.private'
        # Directory perms and no-follow creation keep key material out of receipts.
        with cas.SafeTree(cfg['private_root']) as tree:
            try: tree.mkdir('keys')
            except FileExistsError: pass
            with tree.parent(keyrel) as (fd,_):
                cas.require(os.fstat(fd).st_mode & 0o077 == 0,'KEY_DIRECTORY_PERMISSIONS',code=6)
            tree.write_once(keyrel,private)
        with reg.transaction() as c:
            check_audit(reg)
            current=c.execute("SELECT key_id FROM receipt_keys WHERE state='ACTIVE'").fetchone()
            cas.require((current[0] if current else None)==(old['key_id'] if old else None),'KEY_ROTATION_RACE',code=5)
            if rotate: c.execute("UPDATE receipt_keys SET state='VERIFY_ONLY' WHERE state='ACTIVE'")
            c.execute('INSERT INTO receipt_keys VALUES(?,?,?,?,?,?,?)',
                (kid,public,keyrel,backend.name,backend.private_format,'ACTIVE',cas.utc_now()))
            reg.log(c,'ENROLL_RECEIPT_KEY',dict(key_id=kid,algorithm=ALGORITHM,rotated=rotate))
        return dict(key_id=kid,state='CREATED',public_key_b64=b64(public),backend=backend.name)

def revoke_key(config_path: str, key_id: str, reason: str) -> None:
    cas.digest(key_id); cas.require(bool(reason),'REASON_REQUIRED')
    with cas.AuthorityRegistry(cas.load_config(config_path)) as reg,reg.transaction() as c:
        require_extension(reg)
        cas.require(c.execute('SELECT 1 FROM receipt_keys WHERE key_id=?',(key_id,)).fetchone() is not None,'KEY_NOT_FOUND',code=7)
        c.execute("UPDATE receipt_keys SET state='REVOKED' WHERE key_id=?",(key_id,))
        reg.log(c,'REVOKE_RECEIPT_KEY',dict(key_id=key_id,reason=reason[:300]))

def public_trust(config_path: str) -> dict:
    cfg=cas.load_config(config_path)
    with cas.AuthorityRegistry(cfg,readonly=True) as reg,read_snapshot(reg):
        require_extension(reg); check_audit(reg)
        return dict(protocol='gdoe-receipt-trust/1',store_id=cfg['store_id'],authority_id=cfg['authority_id'],
            keys=[dict(key_id=r['key_id'],algorithm=ALGORITHM,public_key_b64=b64(bytes(r['public_bytes'])),state=r['state'])
                  for r in reg.db.execute('SELECT * FROM receipt_keys ORDER BY key_id')])

def _validate_body(body: dict) -> None:
    cas.fields(body,'protocol event_type store_id authority_id task_key submission_sha256 decision_sequence request_sequence snapshot_id acceptance_b64 acceptance_sha256 verification_b64 verification_sha256 audit_event_b64 audit_event_sha256 qualification activation build prepared_at_utc')
    cas.require(body['protocol']=='gdoe-receipt-attestation/1' and body['event_type'] in ('HISTORICAL','ACTIVATION'),'RECEIPT_SCHEMA')
    receipt_raw=unb64(body['acceptance_b64']); verification_raw=unb64(body['verification_b64'])
    cas.require(cas.sha(receipt_raw)==body['acceptance_sha256'] and cas.sha(verification_raw)==body['verification_sha256'],'RECEIPT_DIGEST_MISMATCH')
    ar=cas.wire_read(receipt_raw); vr=cas.wire_read(verification_raw)
    cas.require(cas.task_key(ar)==body['task_key'] and ar['store_id']==body['store_id']
        and ar['authority_id']==body['authority_id'] and ar['submission_sha256']==body['submission_sha256']
        and ar['decision_sequence']==body['decision_sequence'] and ar['verification_receipt_sha256']==body['verification_sha256'], 'RECEIPT_BINDING_MISMATCH')
    native_receipt=ar['kind']=='candidate_acceptance_receipt'
    required_acceptance='kind schema_version receipt_id operation_id store_id campaign task_id task_revision contract_sha256 submission_sha256 verification_receipt_sha256 authority_id authority_epoch fence_epoch decision_sequence accepted_at_utc state semantic_review'
    if native_receipt: required_acceptance+=' qualification'
    elif ar['kind'] in ('acceptance_receipt','qualification_acceptance'): required_acceptance+=' wire_profile'
    else: raise cas.CASError('RECEIPT_SCHEMA')
    cas.fields(ar,required_acceptance)
    cas.require(ar['state']==('ACCEPTED_LAB_CANDIDATE' if ar['kind']=='qualification_acceptance' else 'ACCEPTED_LOCAL') and ar['schema_version']==1,'RECEIPT_SCHEMA')
    cas.require(vr.get('root_hash' if native_receipt else 'submission_sha256')==body['submission_sha256'] and vr['snapshot_id']==body['snapshot_id']
        and vr['store_id']==body['store_id'] and vr['contract_sha256']==ar['contract_sha256'],'RECEIPT_BINDING_MISMATCH')
    eventraw=unb64(body['audit_event_b64']); event=cas.json_read(eventraw)
    cas.require(cas.sha(eventraw)==body['audit_event_sha256'] and cas.json_bytes(event)==eventraw,'AUDIT_HISTORY_MISMATCH',code=10)
    if body['event_type']=='HISTORICAL':
        expected='PROCESS_CRASH_QUALIFIED' if ar['kind']=='acceptance_receipt' else 'LAB_CANDIDATE_UNQUALIFIED'
        cas.require(body['qualification']==expected and body['activation'] is None,'QUALIFICATION_MISMATCH',code=7)
        if native_receipt:
            cas.require(ar['qualification']=='NOT_GRANTED' and vr['qualification']=='NOT_GRANTED','QUALIFICATION_MISMATCH',code=7)
            expected_k=[body['task_key'][k] for k in ('store_id','campaign','task_id','task_revision')]
            cas.require(event['action']=='ACCEPTED_LOCAL' and event['detail']['a']==body['decision_sequence']
                and event['detail']['q']==body['request_sequence'] and event['detail']['root']==body['submission_sha256']
                and cas.json_read(event['detail']['k'].encode())==expected_k,'AUDIT_BINDING_MISMATCH',code=10)
        else:
            cas.require(event['action']=='ACCEPT' and event['detail']['decision_sequence']==body['decision_sequence']
                and event['detail']['root']==body['submission_sha256'] and event['detail']['operation_id']==ar['operation_id'],'AUDIT_BINDING_MISMATCH',code=10)
    else:
        act=body['activation']
        cas.fields(act,'activation_id qualification_id qualification_record_sha256 fresh_evidence_b64 fresh_evidence_sha256')
        fresh=unb64(act['fresh_evidence_b64'],1024*1024)
        cas.require(cas.sha(fresh)==act['fresh_evidence_sha256'],'RECEIPT_DIGEST_MISMATCH')
        evidence=cas.json_read(fresh)
        cas.require(evidence['root']==body['submission_sha256'] and evidence['scope']=='FULL_CLOSURE','RECEIPT_BINDING_MISMATCH')
        cas.require(body['qualification'] in ('PROCESS_CRASH_QUALIFIED','FIXTURE_ONLY'),'QUALIFICATION_MISMATCH',code=7)
        cas.require(event['action']=='ACTIVATE_RECEIPT' and event['detail']['acceptance_sha256']==body['acceptance_sha256']
             and event['detail']['fresh_evidence_sha256']==act['fresh_evidence_sha256']
             and event['detail']['activation_id']==act['activation_id'],'AUDIT_BINDING_MISMATCH',code=10)

def verify_signed_receipt(raw: bytes, trusted: dict, expected_digest: str | None = None,
                          minimum_decision_sequence: int = 0) -> dict:
    """Public-key verification using caller-enrolled trust. Does not admit a task."""
    cas.require(len(raw)<=cas.MAX_FRAME,'RECEIPT_SIZE_LIMIT',code=8)
    if expected_digest is not None: cas.require(cas.sha(raw)==cas.digest(expected_digest),'RECEIPT_DIGEST_MISMATCH')
    env=cas.json_read(raw,cas.MAX_FRAME); cas.fields(env,'protocol algorithm key_id payload_b64 signature_b64')
    cas.require(cas.json_bytes(env)==raw and env['protocol']=='gdoe-signed-receipt/1' and env['algorithm']==ALGORITHM,'RECEIPT_SCHEMA')
    cas.fields(trusted,'protocol store_id authority_id keys')
    cas.require(trusted['protocol']=='gdoe-receipt-trust/1','TRUST_SCHEMA',code=6)
    keys=[k for k in trusted['keys'] if k.get('key_id')==env['key_id']]
    cas.require(len(keys)==1,'UNTRUSTED_SIGNER',code=6)
    key=keys[0]; cas.fields(key,'key_id algorithm public_key_b64 state')
    cas.require(key['state'] in ('ACTIVE','VERIFY_ONLY') and key['algorithm']==ALGORITHM,'SIGNER_REVOKED',code=6)
    public=unb64(key['public_key_b64'],65)
    cas.require(public_id(public)==env['key_id'],'UNTRUSTED_SIGNER',code=6)
    payload=unb64(env['payload_b64'],cas.MAX_FRAME); sig=unb64(env['signature_b64'],80)
    cas.require(native_backend().verify(public,DOMAIN+payload,sig),'SIGNATURE_MISMATCH',code=4)
    body=cas.json_read(payload,cas.MAX_FRAME); cas.require(cas.json_bytes(body)==payload,'RECEIPT_SCHEMA')
    _validate_body(body)
    cas.require(body['store_id']==trusted['store_id'] and body['authority_id']==trusted['authority_id'],'SIGNER_SCOPE_MISMATCH',code=6)
    cas.uint(minimum_decision_sequence)
    cas.require(body['decision_sequence']>=minimum_decision_sequence,'HISTORICAL_RECEIPT_BELOW_CHECKPOINT',code=6)
    return dict(signature='VALID',key_id=env['key_id'],envelope_sha256=cas.sha(raw),body=body,
                remote_evidence='NOT_ASSERTED',current_integrity='NOT_ASSESSED')

class ReceiptService:
    def __init__(self, config_path: str, wait_ms: int = 900000,
                 barrier: Callable[[str,dict],None] | None = None):
        self.config_path=cas.normalized_absolute(config_path); self.cfg=cas.load_config(config_path)
        self.supervisor=cas.WorkerSupervisor(self.cfg['private_root'],wait_ms)
        self.barrier=barrier or (lambda phase, detail: None)

    def _key(self,reg, key_id, require_active=False):
        key=reg.db.execute('SELECT * FROM receipt_keys WHERE key_id=?',(key_id,)).fetchone()
        cas.require(key is not None and key['state'] in (('ACTIVE',) if require_active else ('ACTIVE','VERIFY_ONLY')),'SIGNER_UNAVAILABLE',code=6)
        return key

    def _body(self,reg,accepted,activation=None):
        raw=bytes(accepted['receipt_bytes']); vr=bytes(accepted['verification_bytes'])
        ar=cas.wire_read(raw); verification=cas.wire_read(vr)
        cas.require(cas.sha(raw)==accepted['receipt_sha256'] and cas.sha(vr)==ar['verification_receipt_sha256'],'ACCEPTANCE_RECORD_MISMATCH',code=10)
        cas.require(cas.key_text(ar)==accepted['task_key'] and ar['submission_sha256']==accepted['root']
            and ar['decision_sequence']==accepted['decision_sequence'] and ar['operation_id']==accepted['operation_id']
            and verification['snapshot_id']==accepted['generation_id'],'ACCEPTANCE_RECORD_MISMATCH',code=10)
        if activation is None:
            found=[]
            for r in reg.db.execute("SELECT a.*,s.event_sha256,s.event_bytes FROM audit a JOIN audit_seals s ON s.audit_sequence=a.sequence WHERE a.action='ACCEPT'"):
                detail=cas.json_read(r['detail_json'].encode())
                if detail.get('decision_sequence')==accepted['decision_sequence']: found.append(r)
            cas.require(len(found)==1,'ACCEPTANCE_AUDIT_MISSING',code=10)
            audit=found[0]; act=None
            qualification='PROCESS_CRASH_QUALIFIED' if accepted['qualified'] else 'LAB_CANDIDATE_UNQUALIFIED'
        else:
            audit=reg.db.execute('SELECT * FROM audit_seals WHERE audit_sequence=?',(activation['audit_sequence'],)).fetchone()
            qr=reg.db.execute('SELECT * FROM receipt_qualifications WHERE qualification_id=?',(activation['qualification_id'],)).fetchone()
            cas.require(qr is not None and audit is not None,'QUALIFICATION_MISMATCH',code=10)
            qualification=cas.json_read(qr['record_bytes'])['scope']
            act=dict(activation_id=activation['activation_id'],qualification_id=activation['qualification_id'],
                     qualification_record_sha256=qr['record_sha256'],fresh_evidence_b64=b64(bytes(activation['fresh_evidence_bytes'])),
                     fresh_evidence_sha256=activation['fresh_evidence_sha256'])
        body=dict(protocol='gdoe-receipt-attestation/1',event_type='ACTIVATION' if activation else 'HISTORICAL',
            store_id=self.cfg['store_id'],authority_id=self.cfg['authority_id'],task_key=cas.json_read(accepted['task_key'].encode()),
            submission_sha256=accepted['root'],decision_sequence=accepted['decision_sequence'],request_sequence=accepted['request_sequence'],
            snapshot_id=accepted['generation_id'],acceptance_b64=b64(raw),acceptance_sha256=cas.sha(raw),
            verification_b64=b64(vr),verification_sha256=cas.sha(vr),audit_event_b64=b64(bytes(audit['event_bytes'])),
            audit_event_sha256=audit['event_sha256'],qualification=qualification,activation=act,
            build=build_fingerprint(),prepared_at_utc=cas.utc_now())
        _validate_body(body)
        return cas.json_bytes(body)

    def _enqueue(self,reg,accepted,activation=None):
        kind='ACTIVATION' if activation else 'HISTORICAL'
        source=activation['activation_id'] if activation else accepted['receipt_sha256']
        if reg.db.execute('SELECT 1 FROM signed_receipt_outbox WHERE source_kind=? AND source_id=?',(kind,source)).fetchone(): return
        key=reg.db.execute("SELECT key_id FROM receipt_keys WHERE state='ACTIVE'").fetchone()
        cas.require(key is not None,'SIGNING_KEY_REQUIRED',code=7)
        body=self._body(reg,accepted,activation)
        cas.require(len(body)<=24000,'SIGNED_RECEIPT_SIZE_LIMIT',code=8)
        binding=reg.db.execute('SELECT binding_id FROM bindings WHERE task_key=? ORDER BY binding_id',(accepted['task_key'],)).fetchone()
        cas.require(binding is not None,'TASK_BINDING_REQUIRED',code=7)
        job=cas.sha((kind+':'+source).encode())
        reg.db.execute('INSERT INTO signed_receipt_outbox(job_id,source_kind,source_id,receipt_sha256,binding_id,key_id,body_bytes) VALUES(?,?,?,?,?,?,?)',
            (job,kind,source,accepted['receipt_sha256'],binding[0],key[0],body))
        reg.log(reg.db,'QUEUE_SIGNED_RECEIPT',dict(job_id=job,source_kind=kind,source_id=source,body_sha256=cas.sha(body)))

    def enqueue(self, maximum=16):
        cas.uint(maximum,128,1)
        with cas.AuthorityRegistry(self.cfg) as reg,reg.transaction() as c:
            check_audit(reg)
            rows=c.execute("SELECT a.* FROM acceptances a WHERE NOT EXISTS(SELECT 1 FROM signed_receipt_outbox s WHERE s.source_kind='HISTORICAL' AND s.source_id=a.receipt_sha256) ORDER BY decision_sequence LIMIT ?",(maximum,)).fetchall()
            for accepted in rows: self._enqueue(reg,accepted)
        return len(rows)

    def _seal(self,reg,row):
        key=self._key(reg,row['key_id'],row['envelope_bytes'] is None)
        if row['envelope_bytes'] is not None: return bytes(row['envelope_bytes'])
        backend=native_backend()
        cas.require(backend.name==key['backend'] and backend.private_format==key['private_format'],'SIGNING_BACKEND_MISMATCH',code=7)
        with cas.SafeTree(self.cfg['private_root']) as tree:
            with tree.open_read(key['private_relative']) as stream:
                st=os.fstat(stream.fileno())
                cas.require(st.st_mode&0o077==0 and st.st_uid==os.getuid(),'PRIVATE_KEY_PERMISSIONS',code=6)
                private=stream.read(4097); cas.require(len(private)<=4096,'PRIVATE_KEY_INVALID',code=6)
        public=bytes(key['public_bytes'])
        cas.require(backend.public_from_private(private)==public,'PRIVATE_KEY_MISMATCH',code=10)
        body=bytes(row['body_bytes']); _validate_body(cas.json_read(body))
        signature=backend.sign(private,DOMAIN+body)
        cas.require(backend.verify(public,DOMAIN+body,signature),'SIGNATURE_SELF_CHECK_FAILED',code=10)
        raw=cas.json_bytes(dict(protocol='gdoe-signed-receipt/1',algorithm=ALGORITHM,key_id=row['key_id'],
                               payload_b64=b64(body),signature_b64=b64(signature)))
        cas.require(len(raw)<cas.MAX_FRAME-4096,'SIGNED_RECEIPT_SIZE_LIMIT',code=8)
        with reg.transaction() as c:
            self._key(reg,row['key_id'],True)
            c.execute("UPDATE signed_receipt_outbox SET envelope_bytes=?,envelope_sha256=?,state='SEALED' WHERE job_id=? AND envelope_bytes IS NULL",(raw,cas.sha(raw),row['job_id']))
            reg.log(c,'SEAL_SIGNED_RECEIPT',dict(job_id=row['job_id'],envelope_sha256=cas.sha(raw)))
        return raw

    def drain_receipts(self, maximum: int = 16, offline: bool = False) -> list[dict]:
        """One bounded iteration. Existing lab loop may call again; no hidden daemon."""
        cas.uint(maximum,128,1)
        cas.require(self.cfg['role']=='authority','AUTHORITY_LOCAL_ONLY',code=6)
        if offline: return [dict(state='OFFLINE_HOLD',provider_calls=0,remote_evidence='NOT_ASSERTED')]
        self.enqueue(maximum)
        results=[]
        with cas.AuthorityRegistry(self.cfg) as reg:
            with read_snapshot(reg): check_audit(reg)
            jobs=reg.db.execute("SELECT job_id FROM signed_receipt_outbox WHERE state<>'LOCAL_PUBLISHED' ORDER BY sequence LIMIT ?",(maximum,)).fetchall()
            for j in jobs:
                job=j[0]
                try:
                    # Inherited by publisher so timeout cannot create concurrent drain ownership.
                    with cas.file_guard(str(Path(self.cfg['private_root'])/'locks'/('receipt.'+job)),timeout=0,create=True) as fd:
                        row=reg.db.execute('SELECT * FROM signed_receipt_outbox WHERE job_id=?',(job,)).fetchone()
                        if row['state']=='LOCAL_PUBLISHED': continue
                        if row['attempts']>=8:
                            results.append(dict(job_id=job,state='HOLD_RETRY',attempts=row['attempts'])); continue
                        raw=self._seal(reg,row)
                        # Recheck full provenance before export; self-signed attacker material
                        # cannot bypass the local registry/key binding.
                        verify_signed_receipt(raw,public_trust(self.config_path),cas.sha(raw))
                        with reg.transaction() as c:
                            self._key(reg,row['key_id'])
                            c.execute("UPDATE signed_receipt_outbox SET attempts=attempts+1,state='UNKNOWN',last_error=NULL WHERE job_id=?",(job,))
                            reg.log(c,'DISPATCH_SIGNED_RECEIPT',dict(job_id=job,envelope_sha256=cas.sha(raw)))
                        self.barrier('signed-receipt-before-publish',dict(job_id=job,sha256=cas.sha(raw)))
                        b=reg.db.execute('SELECT path FROM bindings WHERE binding_id=?',(row['binding_id'],)).fetchone()
                        outcome=self.supervisor.run('receipt_export',dict(binding=reg.binding(b[0]),receipt=raw.decode('ascii'),directory='receipt_outbox'),
                            op_guard_fd=fd,timeout_ms=self.cfg['limits']['publish_timeout_ms'])
                        self.barrier('signed-receipt-published-before-record',outcome)
                        with reg.transaction() as c:
                            c.execute("UPDATE signed_receipt_outbox SET state='LOCAL_PUBLISHED',published_path=?,last_error=NULL WHERE job_id=?",(outcome['path'],job))
                            c.execute("UPDATE receipt_outbox SET state='SIGNED_ENVELOPE_LOCAL_PUBLISHED' WHERE receipt_sha256=?",(row['receipt_sha256'],))
                            reg.log(c,'PUBLISH_SIGNED_RECEIPT',dict(job_id=job,envelope_sha256=cas.sha(raw),remote_evidence='NOT_ASSERTED'))
                        results.append(outcome|dict(job_id=job,state='LOCAL_PUBLISHED',remote_evidence='NOT_ASSERTED'))
                except (cas.CASError,CryptoError) as e:
                    reason=e.reason if isinstance(e,cas.CASError) else 'CRYPTO_BACKEND_ERROR'
                    code=e.code if isinstance(e,cas.CASError) else 7
                    state='UNKNOWN' if code==9 else 'BLOCKED'
                    # Contention leaves the winning worker's row untouched.
                    if reason!='REGISTRY_CONTENDED':
                        with reg.transaction() as c:
                            c.execute("UPDATE signed_receipt_outbox SET state=?,last_error=? WHERE job_id=? AND state<>'LOCAL_PUBLISHED'",(state,reason,job))
                    results.append(dict(job_id=job,state=state,reason=reason))
        return results

    def _activation_qualification(self,reg, qualification_id):
        cas.require(reg.qualified(),'VERIFICATION_UNQUALIFIED',code=7)
        row=reg.db.execute('SELECT * FROM receipt_qualifications WHERE qualification_id=? AND active=1',(qualification_id,)).fetchone()
        cas.require(row is not None,'RECEIPT_QUALIFICATION_REQUIRED',code=7)
        record=cas.json_read(row['record_bytes'])
        cas.require(record['environment']==release_environment(self.cfg) and record['scope']=='PROCESS_CRASH_QUALIFIED','VERIFICATION_UNQUALIFIED',code=7)
        return row

    def activate_receipt(self, receipt_sha256: str, qualification_id: str, operation_id: str) -> dict:
        """New attestation of freshly checked retained bytes; original receipt unchanged."""
        cas.digest(receipt_sha256); cas.uuid_value(qualification_id); cas.uuid_value(operation_id)
        with cas.AuthorityRegistry(self.cfg) as reg,cas.file_guard(str(Path(self.cfg['private_root'])/'locks'/('activation.'+operation_id)),create=True) as fd:
            with read_snapshot(reg):
                require_extension(reg); check_audit(reg)
                old=reg.db.execute('SELECT * FROM receipt_activations WHERE operation_id=?',(operation_id,)).fetchone()
                if old:
                    cas.require(old['receipt_sha256']==receipt_sha256 and old['qualification_id']==qualification_id,'INTENT_CONFLICT',code=5)
                    return dict(activation_id=old['activation_id'],replayed=True,original_receipt_unchanged=True)
                approval=self._activation_qualification(reg,qualification_id)
                a=reg.db.execute('SELECT * FROM acceptances WHERE receipt_sha256=?',(receipt_sha256,)).fetchone()
                cas.require(a is not None,'ACCEPTANCE_NOT_FOUND',code=7)
                g=reg.db.execute('SELECT * FROM generations WHERE generation_id=?',(a['generation_id'],)).fetchone()
                cas.require(g and g['state']=='AVAILABLE','SNAPSHOT_NOT_PROTECTED',code=10)
                cas.require(reg.db.execute("SELECT 1 FROM pins WHERE generation_id=? AND kind='ACCEPTANCE_RETENTION'",(a['generation_id'],)).fetchone() is not None,'SNAPSHOT_NOT_PROTECTED',code=10)
                contract=cas.wire_read(reg.task(a['task_key'])['contract'].encode())
            workspace=str(Path(self.cfg['private_root'])/g['relative_path'])
            scratch_id=cas.new_id(); scratch='scratch/'+scratch_id
            with cas.SafeTree(self.cfg['private_root']) as tree: tree.mkdir(scratch)
            report=str(Path(self.cfg['private_root'])/scratch/'activation-evidence.json')
            try:
                fresh=self.supervisor.run('check',dict(candidate=str(Path(workspace)/'tree'),workspace=workspace,
                    root=a['root'],contract=contract,limits=self.cfg['limits'],enforce_approval=False,report_path=report),
                    operation_id=operation_id,op_guard_fd=fd,timeout_ms=self.cfg['limits']['job_timeout_ms'])
                raw=cas.json_bytes(fresh); aid=cas.new_id(); at=cas.utc_now()
                with reg.transaction() as c:
                    check_audit(reg); self._activation_qualification(reg,qualification_id)
                    cas.require(c.execute("SELECT 1 FROM generations WHERE generation_id=? AND state='AVAILABLE'",(a['generation_id'],)).fetchone() is not None,'SNAPSHOT_NOT_PROTECTED',code=10)
                    cas.require(c.execute("SELECT 1 FROM pins WHERE generation_id=? AND kind='ACCEPTANCE_RETENTION'",(a['generation_id'],)).fetchone() is not None,'SNAPSHOT_NOT_PROTECTED',code=10)
                    cas.require(c.execute("SELECT 1 FROM incidents WHERE root=? OR reason='HASH_IDENTITY_INCIDENT'",(a['root'],)).fetchone() is None,'HASH_IDENTITY_INCIDENT',code=10)
                    seq=reg.log(c,'ACTIVATE_RECEIPT',dict(activation_id=aid,operation_id=operation_id,
                        acceptance_sha256=receipt_sha256,qualification_id=qualification_id,fresh_evidence_sha256=cas.sha(raw)))
                    c.execute('INSERT INTO receipt_activations VALUES(?,?,?,?,?,?,?,?)',
                              (aid,operation_id,receipt_sha256,qualification_id,raw,cas.sha(raw),seq,at))
                    activation=c.execute('SELECT * FROM receipt_activations WHERE activation_id=?',(aid,)).fetchone()
                    self._enqueue(reg,a,activation)
                return dict(activation_id=aid,replayed=False,original_receipt_unchanged=True,receipt_export='PENDING')
            finally:
                if self.supervisor.last_observation.get('reaped'): cas.remove_private_tree(self.cfg['private_root'],scratch)

    def reopen_drain_window(self, job_id: str, reason: str):
        cas.digest(job_id); cas.require(bool(reason),'REASON_REQUIRED')
        with cas.AuthorityRegistry(self.cfg) as reg,reg.transaction() as c:
            require_extension(reg)
            row=c.execute('SELECT state FROM signed_receipt_outbox WHERE job_id=?',(job_id,)).fetchone()
            cas.require(row is not None,'RECEIPT_NOT_FOUND',code=7)
            cas.require(row[0]!='LOCAL_PUBLISHED','RECEIPT_ALREADY_PUBLISHED',code=5)
            c.execute("UPDATE signed_receipt_outbox SET attempts=0,state='PENDING' WHERE job_id=?",(job_id,))
            reg.log(c,'REOPEN_RECEIPT_WINDOW',dict(job_id=job_id,reason=reason[:300]))

    def status(self):
        with cas.AuthorityRegistry(self.cfg,readonly=True) as reg,read_snapshot(reg):
            require_extension(reg); head=check_audit(reg)
            states={r[0]:r[1] for r in reg.db.execute('SELECT state,COUNT(*) FROM signed_receipt_outbox GROUP BY state')}
            return dict(audit_head=head,signed_outbox=states,remote_evidence='NOT_ASSERTED')

def record_receipt_qualification(config_path: str, record: dict):
    """Explicit trusted administrative review; candidate never self-qualifies."""
    cfg=cas.load_config(config_path)
    cas.fields(record,'qualification_id environment evidence_sha256 approved_by mandatory_suites capabilities scope')
    cas.uuid_value(record['qualification_id']); cas.digest(record['evidence_sha256']); cas.label(record['approved_by'])
    cas.require(sys.platform=='darwin' and platform.machine()=='arm64','VERIFICATION_UNQUALIFIED',code=7)
    cas.require(record['environment']==release_environment(cfg),'VERIFICATION_UNQUALIFIED',code=7)
    cas.require(record['mandatory_suites']=={f'AT-{i:02d}':'PASS' for i in range(1,33)}
        and record['capabilities']=={'native_signatures':'PASS','receipt_drainage':'PASS','generation_lifecycle':'PASS','wrapper':'PASS'}
        and record['scope']=='PROCESS_CRASH_QUALIFIED','VERIFICATION_UNQUALIFIED',code=7)
    with cas.AuthorityRegistry(cfg) as reg,reg.transaction() as c:
        require_extension(reg); cas.require(reg.qualified(),'VERIFICATION_UNQUALIFIED',code=7)
        raw=cas.json_bytes(record)
        c.execute('UPDATE receipt_qualifications SET active=0')
        c.execute('INSERT INTO receipt_qualifications VALUES(?,?,?,1)',(record['qualification_id'],raw,cas.sha(raw)))
        reg.log(c,'ENROLL_RECEIPT_QUALIFICATION',dict(qualification_id=record['qualification_id'],record_sha256=cas.sha(raw)))

def arbitrate_candidates(config_path: str, submissions: list[dict], maximum: int = 16) -> list[dict]:
    """Bounded admission adapter for immutable candidates from any producer route.

    This runs on the ONE authority. Actual eligible requests are serialized by Q;
    the caller's list is a dispatch order, not a distributed election or a promise
    of the same winner under different delivery histories.
    """
    cas.uint(maximum,128,1)
    cas.require(type(submissions) is list and len(submissions)<=maximum,'CANDIDATE_BATCH_LIMIT',code=8)
    engine=cas.DriveEngine(config_path)
    cas.require(engine.cfg['role']=='authority','AUTHORITY_LOCAL_ONLY',code=6)
    outcomes=[]
    for submission in submissions:
        cas.fields(submission,'dropzone_dir operation_id')
        cas.uuid_value(submission['operation_id'])
        try:
            result=engine.commit(submission['dropzone_dir'],submission['operation_id'])
            outcomes.append(dict(operation_id=submission['operation_id'],state='ACCEPTED',result=result))
        except cas.CASError as e:
            outcomes.append(dict(operation_id=submission['operation_id'],state='UNRESOLVED' if e.code in (3,9) else 'REJECTED',reason=e.reason))
            if e.code in (9,10): break # Never bypass unresolved authority history.
    return outcomes
