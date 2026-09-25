"""Turn 6 executable evidence. Live FileProvider / two physical devices NOT simulated as real.

Imports the original fixture factory; the oracle reads bytes/SQL directly rather
than invoking the engine verifier to judge its own correctness. Activation tests
explicitly use FIXTURE_ONLY qualification, never public production enrollment.
"""
from __future__ import annotations
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid
import drive_cas as cas
import receipt_engine as re
import receipt_crypto as crypto
from test_drive_cas import StoreCase, independent_candidate

ROOT=Path(__file__).resolve().parent

class FaultSupervisor(cas.WorkerSupervisor):
    def __init__(self,private,mode,target,event_path,wait_ms=900000):
        super().__init__(private,wait_ms); self.spec=dict(mode=mode,target=target,event_path=event_path)
    def worker_command(self): return [sys.executable,'-I',str(ROOT/'fileprovider_mock.py')]
    def run(self,kind,args,*a,**kw):
        return super().run(kind,dict(args,_mock_fault=self.spec),*a,**kw)

class ReceiptCase(StoreCase):
    def setUp(self):
        super().setUp(); re.install_extension(self.config); re.initialize_signing(self.config)
        self.service=re.ReceiptService(self.config)
    def accepted(self,data=b'original captured bytes'):
        proposal=self.put(data); result=self.engine.commit(proposal['submission_dir'])
        return proposal,result
    def signed(self):
        proposal,accepted=self.accepted(); result=self.service.drain_receipts()
        raw=Path(result[0]['path']).read_bytes()
        return proposal,accepted,result[0],raw
    def fixture_qualification(self):
        qid=str(uuid.uuid4()); record={'scope':'FIXTURE_ONLY','fixture':'IN_MEMORY_TEST_ONLY'}
        raw=cas.json_bytes(record)
        with cas.AuthorityRegistry(self.cfg) as reg,reg.transaction() as c:
            c.execute('INSERT INTO receipt_qualifications VALUES(?,?,?,1)',(qid,raw,cas.sha(raw)))
        def approved(reg,q):
            row=reg.db.execute('SELECT * FROM receipt_qualifications WHERE qualification_id=? AND active=1',(q,)).fetchone()
            cas.require(row is not None,'RECEIPT_QUALIFICATION_REQUIRED',code=7)
            return row
        return qid,approved

class TestNativeSignatures(unittest.TestCase):
    def test_real_native_sign_verify_tamper_wrong_key(self):
        backend=crypto.native_backend(); private,public=backend.generate(); _,other=backend.generate()
        message=crypto.DOMAIN+b'exact receipt bytes'; sig=backend.sign(private,message)
        self.assertEqual(backend.public_from_private(private),public)
        self.assertTrue(backend.verify(public,message,sig))
        self.assertFalse(backend.verify(public,message+b'!',sig))
        self.assertFalse(backend.verify(other,message,sig))
    def test_native_invalid_public_and_signature_rejected(self):
        b=crypto.native_backend(); priv,pub=b.generate()
        self.assertFalse(b.verify(pub,b'payload',b''))
        with self.assertRaises(crypto.CryptoError): b.verify(b'bad',b'payload',b'bad')
    def test_base64_is_bounded_and_canonical(self):
        for invalid in ['?','YQ','YQ==\n','YQ===']:
            with self.assertRaises(crypto.CryptoError): crypto.unb64(invalid)
        self.assertEqual(crypto.unb64('YQ=='),b'a')
        with self.assertRaises(crypto.CryptoError): crypto.unb64('YWE=',1)

class TestSignedReceipts(ReceiptCase):
    def test_migration_idempotent_existing_audit_and_acceptance_unchanged(self):
        _,accepted=self.accepted()
        before=self.db_query('SELECT receipt_bytes,verification_bytes FROM acceptances')
        head=self.service.status()['audit_head']
        self.assertEqual(re.install_extension(self.config)['state'],'ALREADY_INSTALLED')
        self.assertEqual(self.db_query('SELECT receipt_bytes,verification_bytes FROM acceptances'),before)
        self.assertEqual(self.service.status()['audit_head'],head)
    def test_roundtrip_real_signature_preserves_original_bytes(self):
        _,accepted,result,raw=self.signed()
        valid=re.verify_signed_receipt(raw,re.public_trust(self.config),hashlib.sha256(raw).hexdigest())
        body=valid['body']
        self.assertEqual(crypto.unb64(body['acceptance_b64']),self.db_query('SELECT receipt_bytes FROM acceptances')[0][0])
        self.assertEqual(body['qualification'],'LAB_CANDIDATE_UNQUALIFIED')
        self.assertEqual(body['submission_sha256'],accepted['root'])
        self.assertEqual(self.service.drain_receipts(),[])
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],1)
        self.assertEqual(valid['remote_evidence'],'NOT_ASSERTED')
    def test_payload_signature_and_trust_tampering_rejected(self):
        _,_,_,raw=self.signed(); trust=re.public_trust(self.config)
        e=json.loads(raw); body=json.loads(crypto.unb64(e['payload_b64'])); body['qualification']='PROCESS_CRASH_QUALIFIED'
        e['payload_b64']=crypto.b64(cas.json_bytes(body))
        self.assertReason('SIGNATURE_MISMATCH',lambda:re.verify_signed_receipt(cas.json_bytes(e),trust))
        other=copy.deepcopy(trust); other['store_id']=str(uuid.uuid4())
        self.assertReason('SIGNER_SCOPE_MISMATCH',lambda:re.verify_signed_receipt(raw,other))
        other=copy.deepcopy(trust); other['keys']=[]
        self.assertReason('UNTRUSTED_SIGNER',lambda:re.verify_signed_receipt(raw,other))
    def test_no_secret_or_public_key_self_enrollment_in_envelope(self):
        _,_,_,raw=self.signed()
        self.assertNotIn(b'private_key',raw); self.assertNotIn(b'public_key',raw)
        for path in (self.private/'keys').iterdir():
            self.assertNotIn(crypto.b64(path.read_bytes()).encode(),raw)
            self.assertEqual(path.stat().st_mode&0o077,0)
    def test_lost_reply_reuses_exact_signed_bytes_and_one_decision(self):
        self.accepted()
        def lost(phase,detail):
            if phase=='signed-receipt-published-before-record': raise cas.CASError('PUBLICATION_OUTCOME_UNKNOWN',code=9)
        first=re.ReceiptService(self.config,barrier=lost).drain_receipts()
        self.assertEqual(first[0]['state'],'UNKNOWN')
        signed=self.db_query('SELECT envelope_bytes FROM signed_receipt_outbox')[0][0]
        second=self.service.drain_receipts()
        self.assertEqual(second[0]['state'],'LOCAL_PUBLISHED')
        self.assertEqual(Path(second[0]['path']).read_bytes(),signed)
        self.assertEqual(self.db_query('SELECT attempts FROM signed_receipt_outbox')[0][0],2)
        self.assertEqual(len(list((self.intake/'receipt_outbox').glob('[0-9a-f]*.json'))),1)
    def test_actual_process_kill_after_publish_replays(self):
        self.accepted()
        code='''import os,signal,sys; from receipt_engine import ReceiptService

def cut(phase,detail):
 if phase=='signed-receipt-published-before-record': os.kill(os.getpid(),signal.SIGKILL)
ReceiptService(sys.argv[1],barrier=cut).drain_receipts()
'''
        proc=subprocess.run([sys.executable,'-c',code,self.config],cwd=ROOT,capture_output=True,timeout=30)
        self.assertEqual(proc.returncode,-signal.SIGKILL,proc.stderr)
        prior=self.db_query('SELECT envelope_bytes,state FROM signed_receipt_outbox')[0]
        self.assertEqual(prior[1],'UNKNOWN')
        final=self.service.drain_receipts()[0]
        self.assertEqual(Path(final['path']).read_bytes(),prior[0])
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],1)
    def test_occupied_digest_path_is_not_overwritten(self):
        self.accepted(); self.service.enqueue()
        with cas.AuthorityRegistry(self.cfg) as reg:
            row=reg.db.execute('SELECT * FROM signed_receipt_outbox').fetchone(); raw=self.service._seal(reg,row)
        destination=self.intake/'receipt_outbox'/f'{cas.sha(raw)}.json'; destination.parent.mkdir(exist_ok=True)
        destination.write_bytes(b'hostile')
        out=self.service.drain_receipts()[0]
        self.assertEqual(out['reason'],'SOURCE_CONFLICT'); self.assertEqual(destination.read_bytes(),b'hostile')
    def test_two_process_drainers_publish_same_envelope(self):
        self.accepted()
        code='import sys,json; from receipt_engine import ReceiptService; print(json.dumps(ReceiptService(sys.argv[1]).drain_receipts()))'
        children=[subprocess.Popen([sys.executable,'-c',code,self.config],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE) for _ in range(2)]
        for child in children:
            out,err=child.communicate(timeout=30); self.assertEqual(child.returncode,0,err)
        self.service.drain_receipts() # reconcile if one lost the slot
        rows=self.db_query('SELECT envelope_bytes,state FROM signed_receipt_outbox')
        self.assertEqual(len(rows),1); self.assertEqual(rows[0][1],'LOCAL_PUBLISHED')
        self.assertEqual(len(list((self.intake/'receipt_outbox').glob('[0-9a-f]*.json'))),1)
    def test_rotation_old_public_verification_and_revocation(self):
        _,_,_,raw=self.signed(); old=json.loads(raw)['key_id']
        re.initialize_signing(self.config,rotate=True)
        self.assertEqual(re.verify_signed_receipt(raw,re.public_trust(self.config))['signature'],'VALID')
        re.revoke_key(self.config,old,'fixture compromise')
        self.assertReason('SIGNER_REVOKED',lambda:re.verify_signed_receipt(raw,re.public_trust(self.config)))
    def test_revoked_key_blocks_queued_publication(self):
        self.accepted(); self.service.enqueue()
        kid=self.db_query('SELECT key_id FROM signed_receipt_outbox')[0][0]
        re.revoke_key(self.config,kid,'fixture')
        self.assertEqual(self.service.drain_receipts()[0]['reason'],'SIGNER_UNAVAILABLE')
        self.assertFalse((self.intake/'receipt_outbox').exists())
    def test_retry_budget_survives_instances_and_explicit_reopen(self):
        self.accepted()
        for _ in range(8):
            service=re.ReceiptService(self.config)
            with mock.patch.object(service.supervisor,'run',side_effect=cas.CASError('IO_FAILURE',code=3)): service.drain_receipts()
        last=self.service.drain_receipts()[0]
        self.assertEqual(last['state'],'HOLD_RETRY'); self.assertEqual(last['attempts'],8)
        self.service.reopen_drain_window(last['job_id'],'explicit fixture new window')
        self.assertEqual(self.service.drain_receipts()[0]['state'],'LOCAL_PUBLISHED')
    def test_offline_is_no_mutation_no_provider_dispatch(self):
        self.accepted(); before=self.db_query('SELECT * FROM audit')
        with mock.patch.object(self.service.supervisor,'run',side_effect=AssertionError('provider call')):
            result=self.service.drain_receipts(offline=True)
        self.assertEqual(result[0]['provider_calls'],0); self.assertEqual(self.db_query('SELECT * FROM audit'),before)
    def test_database_immutable_envelope_and_audit_triggers(self):
        self.signed()
        conn=sqlite3.connect(self.private/'state.sqlite3')
        try:
            for sql in ["UPDATE signed_receipt_outbox SET body_bytes=x'00'", "UPDATE signed_receipt_outbox SET envelope_bytes=x'00'",'DELETE FROM audit','UPDATE audit SET action=\'fake\'']:
                with self.assertRaises(sqlite3.IntegrityError): conn.execute(sql)
                conn.rollback()
        finally: conn.close()
    def test_unsealed_audit_insert_is_detected_before_signing(self):
        self.accepted()
        c=sqlite3.connect(self.private/'state.sqlite3')
        c.execute("INSERT INTO audit(action,detail_json,at_utc) VALUES('FORGED','{}','now')"); c.commit(); c.close()
        self.assertReason('AUDIT_HISTORY_MISMATCH',lambda:self.service.drain_receipts())
    def test_independent_observer_checkpoint_rejects_old_receipt(self):
        _,_,_,raw=self.signed()
        self.assertReason('HISTORICAL_RECEIPT_BELOW_CHECKPOINT',lambda:re.verify_signed_receipt(raw,re.public_trust(self.config),minimum_decision_sequence=2))

class TestActivation(ReceiptCase):
    def test_lab_receipt_not_automatically_qualified(self):
        _,accepted=self.accepted()
        self.assertReason('VERIFICATION_UNQUALIFIED',lambda:self.service.activate_receipt(accepted['acceptance_receipt_sha256'],str(uuid.uuid4()),str(uuid.uuid4())))
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM receipt_activations')[0][0],0)
    def test_fixture_activation_fresh_readback_preserves_history_and_replays(self):
        _,accepted=self.accepted(); original=self.db_query('SELECT receipt_bytes FROM acceptances')[0][0]
        qid,approved=self.fixture_qualification(); op=str(uuid.uuid4())
        with mock.patch.object(self.service,'_activation_qualification',side_effect=approved):
            activated=self.service.activate_receipt(accepted['acceptance_receipt_sha256'],qid,op)
            replay=self.service.activate_receipt(accepted['acceptance_receipt_sha256'],qid,op)
        self.assertEqual(activated['activation_id'],replay['activation_id']); self.assertTrue(replay['replayed'])
        results=self.service.drain_receipts(); bodies=[re.verify_signed_receipt(Path(x['path']).read_bytes(),re.public_trust(self.config))['body'] for x in results]
        a=next(b for b in bodies if b['event_type']=='ACTIVATION')
        self.assertEqual(a['qualification'],'FIXTURE_ONLY'); self.assertEqual(crypto.unb64(a['acceptance_b64']),original)
        self.assertEqual(self.db_query('SELECT receipt_bytes FROM acceptances')[0][0],original)
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],1)
    def test_fixture_activation_detects_private_output_tamper(self):
        _,accepted=self.accepted(); qid,approved=self.fixture_qualification()
        gid=self.db_query('SELECT generation_id FROM acceptances')[0][0]
        (self.private/'generations'/gid/'files/00000000.bin').write_bytes(b'tampered retained bytes')
        with mock.patch.object(self.service,'_activation_qualification',side_effect=approved):
            self.assertReason('DESTINATION_MISMATCH',lambda:self.service.activate_receipt(accepted['acceptance_receipt_sha256'],qid,str(uuid.uuid4())))
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM receipt_activations')[0][0],0)
    def test_activation_rechecks_approval_at_transaction_boundary(self):
        _,accepted=self.accepted(); qid,approved=self.fixture_qualification(); calls=0
        def revoke(reg,q):
            nonlocal calls
            calls+=1
            if calls>1: raise cas.CASError('VERIFICATION_UNQUALIFIED',code=7)
            return approved(reg,q)
        with mock.patch.object(self.service,'_activation_qualification',side_effect=revoke):
            self.assertReason('VERIFICATION_UNQUALIFIED',lambda:self.service.activate_receipt(accepted['acceptance_receipt_sha256'],qid,str(uuid.uuid4())))
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM receipt_activations')[0][0],0)

class TestRetirement(ReceiptCase):
    def test_pinned_generation_retirement_rejected_and_floor_exact(self):
        proposal,_=self.accepted()
        gid=self.db_query('SELECT generation_id FROM acceptances')[0][0]
        self.assertReason('GENERATION_PINNED',lambda:self.engine.retire_generation(gid,'test'))
        status=self.engine.status(); self.assertGreater(status['protected_floor_bytes'],0)
        from decimal import Decimal
        self.assertEqual(Decimal(status['protected_floor_gb'])*1000000000,status['protected_floor_bytes'])
        self.assertReason('HOLD_RESOURCE',lambda:self.engine.prune('0'))
        self.assertTrue((self.private/'generations'/gid).is_dir())
    def test_retire_recover_remove_idempotent_no_late_pin(self):
        proposal=self.put(); cas.release_prepared(self.config,proposal['root'],'discard unaccepted fixture')
        gid=self.db_query('SELECT generation_id FROM snapshots WHERE root=?',(proposal['root'],))[0][0]
        with cas.AuthorityRegistry(self.cfg) as reg:
            ev=cas.LocalCacheEvictor(reg,self.engine.supervisor)
            self.assertEqual(ev.retire_generation(gid)['state'],'RETIRING')
            self.assertEqual(ev.retire_generation(gid)['state'],'RETIRING')
            with self.assertRaises(sqlite3.IntegrityError),reg.transaction() as c:
                c.execute('INSERT INTO pins VALUES(?,?,?)',(gid,'late','READER'))
        self.engine.prune('0')
        with cas.AuthorityRegistry(self.cfg) as reg:
            result=cas.LocalCacheEvictor(reg,self.engine.supervisor).remove_generation(gid)
            self.assertTrue(result['replayed'])
    def test_delayed_cleaner_cannot_delete_new_equal_content_export(self):
        proposal,_=self.accepted(); one=self.engine.get(proposal['root']); two=self.engine.get(proposal['root'])
        op=one['operation_id']; cas.release_export(self.config,op,'first reader finished')
        gid=self.db_query('SELECT generation_id FROM exports WHERE operation_id=?',(op,))[0][0]
        with cas.AuthorityRegistry(self.cfg) as reg:
            ev=cas.LocalCacheEvictor(reg,self.engine.supervisor); ev.retire_generation(gid); ev.remove_generation(gid)
        self.assertEqual(Path(two['output_path']).read_bytes(),b'original captured bytes')
        self.assertFalse(Path(one['output_path']).exists())
    def test_unresolved_owner_is_not_retirable_even_if_pin_missing(self):
        proposal=self.put(); gid=self.db_query('SELECT generation_id FROM snapshots WHERE root=?',(proposal['root'],))[0][0]
        with cas.AuthorityRegistry(self.cfg) as reg,reg.transaction() as c:
            c.execute('DELETE FROM pins WHERE generation_id=?',(gid,))
            c.execute("UPDATE operations SET state='UNKNOWN' WHERE generation_id=?",(gid,))
        self.assertReason('GENERATION_OWNER_UNRESOLVED',lambda:self.engine.retire_generation(gid,'test'))

class TestFileProviderModel(ReceiptCase):
    def spec(self,mode,wait=900000):
        leaf,root=self.external(b'R'*100000)
        target=str(next(leaf.rglob('*.bin'))); events=str(self.base/'fault-events.jsonl')
        return leaf,root,FaultSupervisor(str(self.private),mode,target,events,wait),events
    def test_mock_dataless_hydration_real_bytes_success(self):
        leaf,root,supervisor,events=self.spec('HYDRATE')
        self.engine.supervisor=supervisor
        accepted=self.engine.commit(str(leaf))
        self.assertEqual(accepted['root'],root)
        self.assertEqual(json.loads(Path(events).read_text().splitlines()[0])['phase'],'AFTER_REAL_READ')
        self.assertEqual(Path(self.engine.get(root)['output_path']).read_bytes(),b'R'*100000)
    def test_real_read_eio_does_not_admit(self):
        leaf,root,supervisor,events=self.spec('EIO'); self.engine.supervisor=supervisor
        self.assertReason('IO_FAILURE',lambda:self.engine.commit(str(leaf)))
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],0)
        self.assertGreater(json.loads(Path(events).read_text())['bytes_read'],0)
    def test_injected_sigbus_after_real_read_is_contained(self):
        leaf,root,supervisor,events=self.spec('SIGBUS'); self.engine.supervisor=supervisor
        self.assertReason('WORKER_SIGNAL',lambda:self.engine.commit(str(leaf)))
        self.assertEqual(supervisor.last_observation['returncode'],-signal.SIGBUS)
        self.assertTrue(Path(events).exists()); self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],0)
    def test_stalled_mock_read_times_out_without_acceptance(self):
        leaf,root,supervisor,events=self.spec('STALL',500); self.engine.supervisor=supervisor
        self.assertReason('ACQUISITION_TIMEOUT',lambda:self.engine.commit(str(leaf)))
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],0)
    def test_actual_private_mmap_truncation_child_fault(self):
        result=subprocess.run([sys.executable,'-I',str(ROOT/'fileprovider_mock.py'),'--private-mmap-fault',str(self.base/'owned-map'),str(self.base/'map-event')],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,-signal.SIGBUS,result.stderr)
        self.assertEqual(json.loads((self.base/'map-event').read_text())['fault'],'ACTUAL_PRIVATE_MMAP_TRUNCATION')
    def test_mock_short_reads_preserve_logical_bytes(self):
        leaf,root,supervisor,events=self.spec('SHORT_READ'); self.engine.supervisor=supervisor
        self.assertEqual(self.engine.commit(str(leaf))['root'],root)

class TestArbitrationAndWrapper(ReceiptCase):
    def test_two_producer_candidates_same_task_one_acceptance(self):
        a,ra=self.external(b'producer A'); b,rb=self.external(b'producer B')
        outcomes=re.arbitrate_candidates(self.config,[{'dropzone_dir':str(a),'operation_id':str(uuid.uuid4())},{'dropzone_dir':str(b),'operation_id':str(uuid.uuid4())}])
        self.assertEqual(outcomes[0]['state'],'ACCEPTED'); self.assertEqual(outcomes[1]['reason'],'TASK_ALREADY_ACCEPTED')
        self.assertEqual(self.db_query('SELECT root FROM acceptances'),[(ra,)])
        ma=json.loads((a/'manifest.json').read_bytes()); mb=json.loads((b/'manifest.json').read_bytes())
        self.assertNotEqual(ma['producer_installation'],mb['producer_installation'])
    def test_producer_role_cannot_arbitrate(self):
        cfg=cas.load_config(self.config); cfg['role']='producer'; Path(self.config).write_bytes(cas.json_bytes(cfg))
        self.assertReason('AUTHORITY_LOCAL_ONLY',lambda:re.arbitrate_candidates(self.config,[]))
    def test_wrapper_status_private_only_after_transport_disappears(self):
        self.accepted(); self.exchange.rename(self.base/'exchange-offline')
        proc=subprocess.run([sys.executable,str(ROOT/'tools/drive_engine.py'),'--config',self.config,'--offline','status'],capture_output=True,timeout=10,cwd='/')
        self.assertEqual(proc.returncode,0,proc.stderr)
        result=json.loads(proc.stdout); self.assertEqual(result['result']['accepted_tasks'],1)
        self.assertEqual(result['result']['observation'],'PRIVATE_REGISTRY_ONLY')
    def test_wrapper_put_get_verify_status_prune_and_explicit_commit_drain(self):
        source=self.sources/'cli.bin'; source.write_bytes(b'wrapper exact bytes')
        def call(*args,code=0):
            p=subprocess.run([sys.executable,str(ROOT/'tools/drive_engine.py'),'--config',self.config,*args],capture_output=True,timeout=30,cwd='/')
            self.assertEqual(p.returncode,code,p.stderr+p.stdout); return json.loads(p.stdout)
        put=call('put',str(source))['result']; cas.approve_candidate(self.config,put['root'],self.contract)
        call('verify',put['submission_dir']); self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],0)
        call('commit',put['submission_dir']); call('drain'); call('status')
        get=call('get',put['root'])['result']; self.assertEqual(Path(get['output_path']).read_bytes(),b'wrapper exact bytes')
        call('prune','--max-size-gb','0',code=8)
    def test_wrapper_no_abbreviated_options(self):
        p=subprocess.run([sys.executable,str(ROOT/'tools/drive_engine.py'),'--conf',self.config,'status'],capture_output=True,timeout=10)
        self.assertEqual(p.returncode,2)

if __name__=='__main__': unittest.main(verbosity=2)
