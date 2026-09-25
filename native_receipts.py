"""Turn 6 extension for the exact 54-test gdoe-config/2 deployment.

No base schema conversion or source patch. Additive t6_* tables hold signatures,
activation and audit checkpoints. Historical NOT_GRANTED evidence stays intact.
The base engine's new audit tail is checkpointed when the extension next runs;
this is a signed observation of committed rows, not retroactive signing at commit.
"""
from __future__ import annotations
import contextlib
import os
from pathlib import Path
import platform
import sqlite3
import sys
from typing import Callable
import drive_cas as common
import drive_cas_native as native
from receipt_crypto import ALGORITHM, DOMAIN, CryptoError, b64, unb64, native_backend, public_id
from receipt_engine import build_fingerprint, verify_signed_receipt, _validate_body, _script

EXTENSION_DDL='''
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
'''


def configuration(path):
    c=native.load_config(path)
    common.require(c['role']=='authority','AUTHORITY_LOCAL_ONLY',code=6)
    return c


def require_extension(con):
    ok=con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='t6_meta'").fetchone()
    common.require(ok is not None,'RECEIPTS_NOT_INITIALIZED',code=7)
    row=con.execute("SELECT value FROM t6_meta WHERE key='version'").fetchone()
    common.require(row is not None and bytes(row[0])==b'1','EXTENSION_VERSION_UNSUPPORTED',code=7)


def audit_checkpoint(con, extend=False, maximum=100000):
    require_extension(con)
    previous='0'*64; count=0; last=0; sealed=0; unsealed=0; last_sealed=0; sealed_digest=previous
    rows=con.execute('SELECT a.*,s.event_bytes,s.event_sha256 FROM audit a LEFT JOIN t6_audit_seals s USING(ordinal) ORDER BY ordinal LIMIT ?', (maximum+1,)).fetchall()
    common.require(len(rows)<=maximum,'AUDIT_LIMIT',code=8)
    old=con.execute("SELECT value FROM t6_meta WHERE key='audit_head'").fetchone()
    head=common.json_read(bytes(old[0])) if old else {'sequence':0,'sha256':previous}
    validated_head=head=={'sequence':0,'sha256':previous}
    pending=[]
    for row in rows:
        count+=1; last=row['ordinal']
        expected=common.json_bytes(dict(protocol='gdoe-audit/1',sequence=last,action=row['event'],
            detail=native.decode(bytes(row['detail']),wire=False),at_utc=row['at_utc'],previous_sha256=previous))
        digest=common.sha(expected)
        if row['event_bytes'] is not None:
            common.require(not unsealed and bytes(row['event_bytes'])==expected and row['event_sha256']==digest,'AUDIT_HISTORY_MISMATCH',code=10)
            sealed+=1; last_sealed=last; sealed_digest=digest
            if last==head['sequence']:
                common.require(digest==head['sha256'],'AUDIT_HISTORY_MISMATCH',code=10); validated_head=True
        else:
            unsealed+=1; pending.append((last,digest,expected))
        previous=digest
    common.require(head=={'sequence':last_sealed,'sha256':sealed_digest},'AUDIT_HISTORY_MISMATCH',code=10)
    common.require(validated_head and con.execute('SELECT COUNT(*) FROM t6_audit_seals').fetchone()[0]==sealed,'AUDIT_HISTORY_MISMATCH',code=10)
    common.require(not rows or head['sequence']<=last,'AUDIT_HISTORY_MISMATCH',code=10)
    if extend:
        for row in pending: con.execute('INSERT INTO t6_audit_seals VALUES(?,?,?)',row)
        con.execute("INSERT INTO t6_meta VALUES('audit_head',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(common.json_bytes({'sequence':last,'sha256':previous}),))
    return dict(sequence=last,sha256=previous,unsealed_tail=0 if extend else unsealed)


def log(con,event,detail):
    result=native.AuthorityRegistry.audit(con,event,detail)
    audit_checkpoint(con,True)
    return result


def _runtime_dirs(cfg):
    # All private; no cloud operation and no overwrite of existing control files.
    with common.SafeTree(cfg['private_root']) as tree:
        for rel in ('receipt_runtime','receipt_runtime/locks','keys','scratch'):
            try: tree.mkdir(rel)
            except FileExistsError: pass
        for name in ('publication.0','acquisition.0','acquisition.1'):
            rel='receipt_runtime/locks/'+name
            tree.write_once(rel,b'',equal_existing=True)


def install_extension(config_path):
    cfg=configuration(config_path); reg=native.AuthorityRegistry(cfg)
    _runtime_dirs(cfg)
    with reg.transaction() as con:
        exists=con.execute("SELECT 1 FROM sqlite_master WHERE name='t6_meta'").fetchone()
        if exists:
            audit_checkpoint(con,True)
            return dict(state='ALREADY_INSTALLED',version=1,profile='NATIVE54')
        _script(con,EXTENSION_DDL)
        con.execute("INSERT INTO t6_meta VALUES('version',?)",(b'1',))
        audit_checkpoint(con,True)
        log(con,'T6_EXTENSION_INSTALLED',{'profile':'NATIVE54','source_sha256':cfg['engine_sha256'],
            'prior_history':'OBSERVED_AT_CHECKPOINT_NOT_SIGNED_AT_ORIGINAL_COMMIT'})
    return dict(state='INSTALLED',profile='NATIVE54',version=1,original_receipts='UNCHANGED')


def initialize_signing(config_path,rotate=False):
    cfg=configuration(config_path); install_extension(config_path); reg=native.AuthorityRegistry(cfg)
    old=reg.read("SELECT * FROM t6_receipt_keys WHERE state='ACTIVE'")
    if old and not rotate: return dict(state='EXISTING',key_id=old[0]['key_id'],public_key_b64=b64(old[0]['public_bytes']))
    backend=native_backend(); private,public=backend.generate(); kid=public_id(public); rel='keys/'+kid+'.private'
    with common.SafeTree(cfg['private_root']) as tree:
        with tree.parent(rel) as (fd,_): common.require(os.fstat(fd).st_mode&0o077==0,'KEY_DIRECTORY_PERMISSIONS',code=6)
        tree.write_once(rel,private)
    with reg.transaction() as con:
        audit_checkpoint(con,True)
        now=con.execute("SELECT key_id FROM t6_receipt_keys WHERE state='ACTIVE'").fetchone()
        common.require((now[0] if now else None)==(old[0]['key_id'] if old else None),'KEY_ROTATION_RACE',code=5)
        if rotate: con.execute("UPDATE t6_receipt_keys SET state='VERIFY_ONLY' WHERE state='ACTIVE'")
        con.execute('INSERT INTO t6_receipt_keys VALUES(?,?,?,?,?,?)',(kid,public,rel,backend.name,backend.private_format,'ACTIVE'))
        log(con,'T6_SIGNER_ENROLLED',dict(key_id=kid,rotated=rotate))
    return dict(state='CREATED',key_id=kid,public_key_b64=b64(public),backend=backend.name)


def revoke_key(config_path,key_id,reason):
    common.digest(key_id); common.require(bool(reason.strip()),'REASON_REQUIRED')
    reg=native.AuthorityRegistry(configuration(config_path))
    with reg.transaction() as con:
        audit_checkpoint(con,True)
        common.require(con.execute('SELECT 1 FROM t6_receipt_keys WHERE key_id=?',(key_id,)).fetchone() is not None,'KEY_NOT_FOUND',code=7)
        con.execute("UPDATE t6_receipt_keys SET state='REVOKED' WHERE key_id=?",(key_id,))
        log(con,'T6_SIGNER_REVOKED',dict(key_id=key_id,reason=reason[:300]))


def public_trust(config_path):
    cfg=configuration(config_path); reg=native.AuthorityRegistry(cfg)
    with reg.connection(readonly=True) as con:
        con.execute('BEGIN'); audit_checkpoint(con)
        keys=[dict(key_id=r['key_id'],algorithm=ALGORITHM,public_key_b64=b64(bytes(r['public_bytes'])),state=r['state'])
            for r in con.execute('SELECT * FROM t6_receipt_keys ORDER BY key_id')]
        return dict(protocol='gdoe-receipt-trust/1',store_id=cfg['store_id'],authority_id=cfg['authority_id'],keys=keys)


def release_environment(cfg):
    return dict(profile='NATIVE54',runtime={'platform':sys.platform,'architecture':platform.machine(),
        'release':platform.release(),'python':platform.python_version(),'sqlite':sqlite3.sqlite_version},
        build=build_fingerprint(),config_sha256=common.sha(common.json_bytes(cfg)),crypto_backend=native_backend().name)


class NativeSupervisor(common.WorkerSupervisor):
    def worker_command(self): return [sys.executable,'-I',str(Path(__file__).with_name('native_jobs.py')),'--_worker']


class ReceiptService:
    def __init__(self,config_path,wait_ms=900000,barrier: Callable|None=None):
        self.config_path=str(config_path); self.cfg=configuration(config_path)
        self.reg=native.AuthorityRegistry(self.cfg); self.wait_ms=wait_ms
        self.supervisor=NativeSupervisor(str(Path(self.cfg['private_root'])/'receipt_runtime'),wait_ms)
        self.barrier=barrier or (lambda phase, detail:None)

    def _key(self,con,kid,active=False):
        r=con.execute('SELECT * FROM t6_receipt_keys WHERE key_id=?',(kid,)).fetchone()
        common.require(r is not None and r['state'] in (('ACTIVE',) if active else ('ACTIVE','VERIFY_ONLY')),'SIGNER_UNAVAILABLE',code=6)
        return r

    def _body(self,con,a,activation=None):
        ar=native.decode(bytes(a['receipt'])); vr=native.decode(bytes(a['verification']))
        common.require(common.sha(bytes(a['receipt']))==a['receipt_hash'] and
            common.sha(bytes(a['verification']))==ar['verification_receipt_sha256'] and
            native.canonical(list(native.contract_key(ar))).decode()==a['k'] and
            ar['submission_sha256']==a['root'] and ar['operation_id']==a['o'] and ar['decision_sequence']==a['a']
            and vr['snapshot_id']==a['g'],'ACCEPTANCE_RECORD_MISMATCH',code=10)
        if activation is None:
            found=[]
            for row in con.execute("SELECT a.*,s.event_sha256,s.event_bytes FROM audit a JOIN t6_audit_seals s USING(ordinal) WHERE a.event='ACCEPTED_LOCAL'"):
                detail=native.decode(bytes(row['detail']),wire=False)
                if detail.get('a')==a['a']: found.append(row)
            common.require(len(found)==1,'ACCEPTANCE_AUDIT_MISSING',code=10)
            event=found[0]; act=None; qualification='LAB_CANDIDATE_UNQUALIFIED'
        else:
            event=con.execute('SELECT * FROM t6_audit_seals WHERE ordinal=?',(activation['audit_ordinal'],)).fetchone()
            q=con.execute('SELECT * FROM t6_qualifications WHERE qualification_id=?',(activation['qualification_id'],)).fetchone()
            common.require(event is not None and q is not None,'QUALIFICATION_MISMATCH',code=10)
            qualification=common.json_read(bytes(q['record_bytes']))['scope']
            act=dict(activation_id=activation['activation_id'],qualification_id=activation['qualification_id'],
                qualification_record_sha256=q['record_sha256'],fresh_evidence_b64=b64(bytes(activation['fresh_bytes'])),
                fresh_evidence_sha256=common.sha(bytes(activation['fresh_bytes'])))
        body=dict(protocol='gdoe-receipt-attestation/1',event_type='ACTIVATION' if activation else 'HISTORICAL',
            store_id=self.cfg['store_id'],authority_id=self.cfg['authority_id'],task_key=native.task_key(ar),
            submission_sha256=a['root'],decision_sequence=a['a'],request_sequence=a['q'],snapshot_id=a['g'],
            acceptance_b64=b64(bytes(a['receipt'])),acceptance_sha256=a['receipt_hash'],
            verification_b64=b64(bytes(a['verification'])),verification_sha256=common.sha(bytes(a['verification'])),
            audit_event_b64=b64(bytes(event['event_bytes'])),audit_event_sha256=event['event_sha256'],
            qualification=qualification,activation=act,build=build_fingerprint(),prepared_at_utc=common.utc_now())
        _validate_body(body)
        raw=common.json_bytes(body); common.require(len(raw)<=24000,'SIGNED_RECEIPT_SIZE_LIMIT',code=8)
        return raw

    def _enqueue(self,con,a,activation=None):
        kind='ACTIVATION' if activation else 'HISTORICAL'; source=activation['activation_id'] if activation else a['receipt_hash']
        if con.execute('SELECT 1 FROM t6_receipt_outbox WHERE source_kind=? AND source_id=?',(kind,source)).fetchone(): return
        key=con.execute("SELECT key_id FROM t6_receipt_keys WHERE state='ACTIVE'").fetchone()
        common.require(key is not None,'SIGNING_KEY_REQUIRED',code=7)
        body=self._body(con,a,activation); job=common.sha((kind+':'+source).encode())
        con.execute('INSERT INTO t6_receipt_outbox(job_id,source_kind,source_id,receipt_sha256,task_key,key_id,body_bytes) VALUES(?,?,?,?,?,?,?)',
            (job,kind,source,a['receipt_hash'],a['k'],key[0],body))
        log(con,'T6_RECEIPT_QUEUED',dict(job_id=job,body_sha256=common.sha(body)))

    def enqueue(self,maximum=16):
        common.uint(maximum,128,1)
        with self.reg.transaction() as con:
            audit_checkpoint(con,True)
            rows=con.execute("SELECT a.* FROM acceptances a WHERE NOT EXISTS(SELECT 1 FROM t6_receipt_outbox o WHERE o.source_kind='HISTORICAL' AND o.source_id=a.receipt_hash) ORDER BY a LIMIT ?",(maximum,)).fetchall()
            for a in rows: self._enqueue(con,a)
        return len(rows)

    def _seal(self,row):
        with self.reg.connection(readonly=True) as con:
            key=self._key(con,row['key_id'],row['envelope_bytes'] is None)
        if row['envelope_bytes'] is not None: return bytes(row['envelope_bytes'])
        backend=native_backend()
        common.require(backend.name==key['backend'] and backend.private_format==key['private_format'],'SIGNING_BACKEND_MISMATCH',code=7)
        with common.SafeTree(self.cfg['private_root']) as tree,tree.open_read(key['private_relative']) as stream:
            st=os.fstat(stream.fileno())
            common.require(st.st_uid==os.getuid() and st.st_mode&0o077==0,'PRIVATE_KEY_PERMISSIONS',code=6)
            private=stream.read(4097); common.require(len(private)<=4096,'PRIVATE_KEY_INVALID',code=6)
        public=bytes(key['public_bytes']); body=bytes(row['body_bytes']); _validate_body(common.json_read(body))
        common.require(backend.public_from_private(private)==public,'PRIVATE_KEY_MISMATCH',code=10)
        signature=backend.sign(private,DOMAIN+body)
        common.require(backend.verify(public,DOMAIN+body,signature),'SIGNATURE_SELF_CHECK_FAILED',code=10)
        raw=common.json_bytes(dict(protocol='gdoe-signed-receipt/1',algorithm=ALGORITHM,key_id=key['key_id'],payload_b64=b64(body),signature_b64=b64(signature)))
        common.require(len(raw)<common.MAX_FRAME-4096,'SIGNED_RECEIPT_SIZE_LIMIT',code=8)
        with self.reg.transaction() as con:
            self._key(con,row['key_id'],True); audit_checkpoint(con,True)
            con.execute("UPDATE t6_receipt_outbox SET envelope_bytes=?,envelope_sha256=?,state='SEALED' WHERE job_id=? AND envelope_bytes IS NULL",(raw,common.sha(raw),row['job_id']))
            log(con,'T6_RECEIPT_SEALED',dict(job_id=row['job_id'],sha256=common.sha(raw)))
        return raw

    def drain_receipts(self,maximum=16,offline=False):
        common.uint(maximum,128,1)
        if offline: return [dict(state='OFFLINE_HOLD',provider_calls=0,remote_evidence='NOT_ASSERTED')]
        self.enqueue(maximum); out=[]
        jobs=self.reg.read("SELECT job_id FROM t6_receipt_outbox WHERE state<>'LOCAL_PUBLISHED' ORDER BY sequence LIMIT ?",(maximum,))
        for item in jobs:
            job=item['job_id']
            try:
                guard=Path(self.cfg['private_root'])/'receipt_runtime'/'locks'/('receipt.'+job)
                with common.file_guard(str(guard),timeout=0,create=True) as fd:
                    row=self.reg.read('SELECT * FROM t6_receipt_outbox WHERE job_id=?',(job,))[0]
                    if row['state']=='LOCAL_PUBLISHED': continue
                    if row['attempts']>=8:
                        out.append(dict(job_id=job,state='HOLD_RETRY',attempts=row['attempts'])); continue
                    raw=self._seal(row)
                    verify_signed_receipt(raw,public_trust(self.config_path),common.sha(raw))
                    with self.reg.transaction() as con:
                        audit_checkpoint(con,True); self._key(con,row['key_id'])
                        con.execute("UPDATE t6_receipt_outbox SET attempts=attempts+1,state='UNKNOWN',last_error=NULL WHERE job_id=?",(job,))
                        log(con,'T6_RECEIPT_DISPATCHED',dict(job_id=job,sha256=common.sha(raw)))
                    self.barrier('signed-receipt-before-publish',dict(job_id=job,sha256=common.sha(raw)))
                    task=self.reg.read('SELECT * FROM tasks WHERE k=?',(row['task_key'],))[0]
                    binding=dict(path=task['intake'],identity=dict(dev=task['intake_dev'],ino=task['intake_ino']))
                    result=self.supervisor.run('receipt_export',dict(binding=binding,receipt=raw.decode('ascii'),directory='receipt_outbox'),op_guard_fd=fd,timeout_ms=300000)
                    self.barrier('signed-receipt-published-before-record',result)
                    with self.reg.transaction() as con:
                        audit_checkpoint(con,True)
                        con.execute("UPDATE t6_receipt_outbox SET state='LOCAL_PUBLISHED',published_path=?,last_error=NULL WHERE job_id=?",(result['path'],job))
                        # Legacy row says only that its signed envelope is published.
                        con.execute("UPDATE receipt_outbox SET state='SIGNED_ENVELOPE_LOCAL_PUBLISHED' WHERE receipt_hash=?",(row['receipt_sha256'],))
                        log(con,'T6_RECEIPT_PUBLISHED',dict(job_id=job,sha256=common.sha(raw),remote_evidence='NOT_ASSERTED'))
                    out.append(result|dict(job_id=job,state='LOCAL_PUBLISHED',remote_evidence='NOT_ASSERTED'))
            except (common.CASError,native.CASError,CryptoError) as exc:
                code=getattr(exc,'code',7); reason=getattr(exc,'reason','CRYPTO_BACKEND_ERROR'); state='UNKNOWN' if code==9 else 'BLOCKED'
                if reason!='REGISTRY_CONTENDED':
                    with self.reg.transaction() as con:
                        con.execute("UPDATE t6_receipt_outbox SET state=?,last_error=? WHERE job_id=? AND state<>'LOCAL_PUBLISHED'",(state,reason,job))
                out.append(dict(job_id=job,state=state,reason=reason))
        return out

    def _activation_qualification(self,con,qid):
        require_extension(con)
        row=con.execute('SELECT * FROM t6_qualifications WHERE qualification_id=? AND active=1',(qid,)).fetchone()
        common.require(row is not None,'RECEIPT_QUALIFICATION_REQUIRED',code=7)
        record=common.json_read(bytes(row['record_bytes']))
        common.require(record['environment']==release_environment(self.cfg) and record['scope']=='PROCESS_CRASH_QUALIFIED','VERIFICATION_UNQUALIFIED',code=7)
        return row

    def activate_receipt(self,receipt_sha256,qualification_id,operation_id):
        common.digest(receipt_sha256); common.uuid_value(qualification_id); common.uuid_value(operation_id)
        guard=Path(self.cfg['private_root'])/'receipt_runtime'/'locks'/('activate.'+operation_id)
        with common.file_guard(str(guard),create=True) as fd:
            old=self.reg.read('SELECT * FROM t6_activations WHERE operation_id=?',(operation_id,))
            if old:
                common.require(old[0]['receipt_sha256']==receipt_sha256 and old[0]['qualification_id']==qualification_id,'INTENT_CONFLICT',code=5)
                return dict(activation_id=old[0]['activation_id'],replayed=True,original_receipt_unchanged=True)
            with self.reg.transaction() as con:
                audit_checkpoint(con,True); self._activation_qualification(con,qualification_id)
                a=con.execute('SELECT * FROM acceptances WHERE receipt_hash=?',(receipt_sha256,)).fetchone()
                common.require(a is not None,'RECEIPT_NOT_FOUND',code=7)
                task=con.execute('SELECT * FROM tasks WHERE k=?',(a['k'],)).fetchone(); self.reg.authorize(task,a['root'],con)
                g=con.execute('SELECT * FROM generations WHERE g=?',(a['g'],)).fetchone()
                common.require(g is not None and g['state']=='AVAILABLE' and con.execute("SELECT 1 FROM pins WHERE g=? AND owner=? AND kind='ACCEPTANCE'",(a['g'],a['k'])).fetchone(),'SNAPSHOT_NOT_PROTECTED',code=10)
                contract=native.decode(bytes(task['contract'])); evidence=bytes(g['evidence']); original_fence=task['fence']; snapshot=dict(g); accepted=dict(a)
            scratchbase=Path(self.cfg['private_root'])/'scratch'/common.new_id()
            with common.SafeTree(self.cfg['private_root']) as tree:
                rel=scratchbase.relative_to(self.cfg['private_root']).as_posix(); tree.mkdir(rel); tree.write_once(rel+'/evidence.json',evidence)
            try:
                fresh=self.supervisor.run('native_snapshot_check',dict(snapshot=snapshot['path'],evidence_path=str(scratchbase/'evidence.json'),
                    contract=contract,root=accepted['root'],scratch=str(scratchbase/'capture')),op_guard_fd=fd,timeout_ms=300000)
                freshbytes=common.json_bytes(fresh); self.barrier('activation-readback-complete',fresh)
                activation_id=common.new_id()
                with self.reg.transaction() as con:
                    audit_checkpoint(con,True); self._activation_qualification(con,qualification_id)
                    task=con.execute('SELECT * FROM tasks WHERE k=?',(accepted['k'],)).fetchone(); self.reg.authorize(task,accepted['root'],con)
                    common.require(task['fence']==original_fence,'STALE_FENCE',code=6)
                    current=con.execute('SELECT * FROM generations WHERE g=?',(accepted['g'],)).fetchone()
                    common.require(current['state']=='AVAILABLE' and con.execute("SELECT 1 FROM pins WHERE g=? AND kind='ACCEPTANCE'",(accepted['g'],)).fetchone(),'SNAPSHOT_NOT_PROTECTED',code=10)
                    ordinal=log(con,'ACTIVATE_RECEIPT',dict(activation_id=activation_id,acceptance_sha256=receipt_sha256,
                        fresh_evidence_sha256=common.sha(freshbytes),qualification_id=qualification_id))
                    con.execute('INSERT INTO t6_activations VALUES(?,?,?,?,?,?)',(activation_id,operation_id,receipt_sha256,qualification_id,freshbytes,ordinal))
                    act=con.execute('SELECT * FROM t6_activations WHERE activation_id=?',(activation_id,)).fetchone()
                    self._enqueue(con,accepted,act)
                return dict(activation_id=activation_id,replayed=False,original_receipt_unchanged=True,receipt_export='PENDING')
            finally:
                if self.supervisor.last_observation.get('reaped'):
                    common.remove_private_tree(self.cfg['private_root'],scratchbase.relative_to(self.cfg['private_root']).as_posix())

    def reopen_drain_window(self,job_id,reason):
        common.digest(job_id); common.require(bool(reason.strip()),'REASON_REQUIRED')
        with self.reg.transaction() as con:
            audit_checkpoint(con,True)
            row=con.execute('SELECT state FROM t6_receipt_outbox WHERE job_id=?',(job_id,)).fetchone()
            common.require(row is not None and row[0]!='LOCAL_PUBLISHED','RECEIPT_NOT_PENDING',code=5)
            con.execute("UPDATE t6_receipt_outbox SET attempts=0,state='PENDING' WHERE job_id=?",(job_id,))
            log(con,'T6_DRAIN_WINDOW_REOPENED',dict(job_id=job_id,reason=reason[:300]))

    def status(self):
        with self.reg.connection(readonly=True) as con:
            con.execute('BEGIN'); head=audit_checkpoint(con)
            states={r[0]:r[1] for r in con.execute('SELECT state,COUNT(*) FROM t6_receipt_outbox GROUP BY state')}
            return dict(profile='NATIVE54',audit_head=head,signed_outbox=states,remote_evidence='NOT_ASSERTED')


def record_receipt_qualification(config_path,record):
    cfg=configuration(config_path)
    common.fields(record,'qualification_id environment evidence_sha256 approved_by mandatory_suites capabilities scope')
    common.uuid_value(record['qualification_id']); common.digest(record['evidence_sha256']); common.label(record['approved_by'])
    common.require(sys.platform=='darwin' and platform.machine()=='arm64','VERIFICATION_UNQUALIFIED',code=7)
    common.require(record['environment']==release_environment(cfg) and record['scope']=='PROCESS_CRASH_QUALIFIED','VERIFICATION_UNQUALIFIED',code=7)
    common.require(record['mandatory_suites']=={f'AT-{i:02d}':'PASS' for i in range(1,33)} and
        record['capabilities']=={'native_signatures':'PASS','receipt_drainage':'PASS','generation_lifecycle':'PASS','wrapper':'PASS'},'VERIFICATION_UNQUALIFIED',code=7)
    reg=native.AuthorityRegistry(cfg)
    with reg.transaction() as con:
        audit_checkpoint(con,True); raw=common.json_bytes(record)
        con.execute('UPDATE t6_qualifications SET active=0')
        con.execute('INSERT INTO t6_qualifications VALUES(?,?,?,1)',(record['qualification_id'],raw,common.sha(raw)))
        log(con,'T6_QUALIFICATION_ENROLLED',dict(qualification_id=record['qualification_id'],record_sha256=common.sha(raw)))


class LocalCacheEvictor:
    """Native54 lifecycle extension. Every installed pin route is trigger guarded."""
    def __init__(self,config_path,wait_ms=900000):
        self.cfg=configuration(config_path); self.reg=native.AuthorityRegistry(self.cfg)
        self.supervisor=NativeSupervisor(str(Path(self.cfg['private_root'])/'receipt_runtime'),wait_ms)

    def plan(self,target=100_000_000_000):
        common.uint(target)
        rows=self.reg.read("SELECT g.*,EXISTS(SELECT 1 FROM pins p WHERE p.g=g.g) pinned FROM generations g WHERE state<>'ABSENT' ORDER BY last_use,g")
        floor=sum(r['size_bytes'] for r in rows if r['pinned'] or r['state']=='CORRUPT')
        return dict(target_bytes=target,accounted_bytes=sum(r['size_bytes'] for r in rows),protected_floor_bytes=floor,
            protected_floor_gb=f'{floor//10**9}.{floor%10**9:09d}',
            candidates=[r['g'] for r in rows if not r['pinned'] and r['state'] in ('AVAILABLE','RETIRING')],
            target_met_now=sum(r['size_bytes'] for r in rows)<=target,target_would_be_met=floor<=target,
            unresolved_count=sum(r['state']=='RETIRING' for r in rows),cloud_deletions=0)

    def retire_generation(self,generation_id,reason):
        common.uuid_value(generation_id); common.require(bool(reason.strip()),'REASON_REQUIRED')
        with self.reg.transaction() as con:
            audit_checkpoint(con,True)
            row=con.execute('SELECT * FROM generations WHERE g=?',(generation_id,)).fetchone()
            common.require(row is not None,'GENERATION_NOT_FOUND',code=7)
            common.require(not con.execute('SELECT 1 FROM pins WHERE g=?',(generation_id,)).fetchone(),'GENERATION_PINNED',code=8)
            common.require(row['state'] in ('AVAILABLE','RETIRING','ABSENT'),'GENERATION_NOT_RETIRABLE',code=8)
            replay=row['state']!='AVAILABLE'
            if not replay:
                con.execute("UPDATE generations SET state='RETIRING' WHERE g=?",(generation_id,))
                log(con,'T6_GENERATION_RETIRING',dict(g=generation_id,reason=reason[:300]))
            return dict(generation_id=generation_id,state='RETIRING' if not replay else row['state'],replayed=replay)

    def remove_generation(self,generation_id):
        common.uuid_value(generation_id)
        guard=Path(self.cfg['private_root'])/'receipt_runtime'/'locks'/('retire.'+generation_id)
        with common.file_guard(str(guard),timeout=0,create=True) as fd:
            with self.reg.transaction() as con:
                audit_checkpoint(con,True); row=con.execute('SELECT * FROM generations WHERE g=?',(generation_id,)).fetchone()
                common.require(row is not None,'GENERATION_NOT_FOUND',code=7)
                if row['state']=='ABSENT': return dict(state='ABSENT',replayed=True)
                common.require(row['state']=='RETIRING' and not con.execute('SELECT 1 FROM pins WHERE g=?',(generation_id,)).fetchone(),'GENERATION_NOT_RETIRING',code=8)
                rel=common.relative_under(row['path'],self.cfg['private_root']); parts=common.SafeTree.parts(rel)
                common.require(len(parts)==2 and parts[0] in ('generations','exports'),'UNSAFE_GENERATION_PATH',code=10)
                # Physical path is uniquely recorded and never recycled. g may differ
                # from export directory O, so equality to g is not incorrectly required.
            self.supervisor.run('remove',dict(private_root=self.cfg['private_root'],relative=rel),op_guard_fd=fd,timeout_ms=120000)
            with self.reg.transaction() as con:
                audit_checkpoint(con,True)
                con.execute("UPDATE generations SET state='ABSENT' WHERE g=? AND state='RETIRING'",(generation_id,))
                log(con,'T6_GENERATION_ABSENT',dict(g=generation_id))
            return dict(state='ABSENT',replayed=False)

    def prune(self,target,dry_run=False,operation_id=None):
        plan=self.plan(target)
        if dry_run: return plan|dict(action='PLAN_ONLY')
        o=common.uuid_value(operation_id or common.new_id()); intent=dict(target_bytes=target,profile='t6-private-prune/1')
        with common.file_guard(str(Path(self.cfg['private_root'])/'operation_locks'/o),create=True):
            op=self.reg.bind_operation(o,'t6-prune',intent)
            if op['state']=='DONE': return native.decode(op['result'],wire=False)|dict(replayed=True)
            removed=0; skipped=0
            for g in plan['candidates']:
                current=self.plan(target)
                row=self.reg.read('SELECT state FROM generations WHERE g=?',(g,))[0]
                if current['target_met_now'] and row['state']!='RETIRING': continue
                try:
                    self.retire_generation(g,'explicit private prune '+o); self.remove_generation(g); removed+=1
                except common.CASError as exc:
                    if exc.reason=='GENERATION_PINNED': skipped+=1; continue
                    self.reg.fail(o,native.CASError(exc.reason,str(exc),exc.code)); raise
            result=self.plan(target)|dict(action='PRUNED',operation_id=o,removed_count=removed,skipped_count=skipped)
            if not result['target_met_now'] or result['unresolved_count']:
                err=native.CASError('HOLD_RESOURCE','Protected floor or unresolved retirement',8,result=result)
                self.reg.fail(o,err); raise err
            self.reg.finish(o,result); return result


def arbitrate_candidates(config_path,submissions,maximum=16):
    common.uint(maximum,128,1); common.require(type(submissions) is list and len(submissions)<=maximum,'CANDIDATE_BATCH_LIMIT',code=8)
    engine=native.DriveEngine(config_path); common.require(engine.c['role']=='authority','AUTHORITY_LOCAL_ONLY',code=6)
    outcomes=[]
    for item in submissions:
        common.fields(item,'dropzone_dir operation_id'); common.uuid_value(item['operation_id'])
        try: outcomes.append(dict(state='ACCEPTED',result=engine.commit(item['dropzone_dir'],operation_id=item['operation_id'])))
        except native.CASError as exc:
            outcomes.append(dict(state='UNRESOLVED' if exc.code in (3,9) else 'REJECTED',reason=exc.reason))
            if exc.code in (9,10): break
    return outcomes
