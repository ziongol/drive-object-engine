"""Turn6 adapter tests against the byte-preserved 54-test deployment profile.
All files/keys/authorities are disposable. FIXTURE_ONLY activation is injected via
Python mocks, never a runtime flag or a production qualification claim.
"""
from pathlib import Path
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid
import drive_cas as common
import drive_cas_native as native
import native_receipts as receipts
from receipt_engine import verify_signed_receipt
from release_profiles import profile

ROOT=Path(__file__).resolve().parent

class NativeFixture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.base=Path(self.temp.name).resolve()
        self.exchange=self.base/'exchange'; self.exchange.mkdir(); self.outputs=self.base/'outputs'; self.outputs.mkdir()
        self.config=self.base/'config.json'; self.private=self.base/'private'
        native.enroll_store(self.config,self.private,self.exchange,export_roots=[str(self.outputs)],reserve_bytes=0,reserve_fraction_milli=0)
        self.contract=native.enroll_task(self.config,campaign='fixture',task_id='task',artifacts=[native.artifact_slot('file.bin',allow_empty=True)],selection='ANY_VALID_ENROLLED')
        self.e=native.DriveEngine(self.config); self.source=self.base/'source'; self.source.write_bytes(b'Native receipts retained bytes\x00\xff')
        self.put=self.e.put(str(self.source)); self.accepted=self.e.commit(self.put['submission_dir']); self.rh=self.accepted['acceptance_receipt_sha256']
        receipts.initialize_signing(self.config); self.service=receipts.ReceiptService(self.config)
    def tearDown(self): self.temp.cleanup()
    def read_signed(self):
        result=self.service.drain_receipts(); self.assertTrue(result and result[0]['state']=='LOCAL_PUBLISHED',result)
        raw=Path(result[0]['path']).read_bytes(); return raw,verify_signed_receipt(raw,receipts.public_trust(self.config))
    def assert_reason(self,reason,fn,*args,**kw):
        with self.assertRaises((common.CASError,native.CASError)) as c: fn(*args,**kw)
        self.assertEqual(reason,c.exception.reason)

class TestNativeSignedReceipts(NativeFixture):
    def test_exact_source_and_profile_preserved(self):
        self.assertEqual(hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest(),'ea67d29fef864715842de895742de2f3a605911c2ea0c647c9d7c0948389c68e')
        self.assertEqual(profile(self.config)[0],'NATIVE54')
        self.assertEqual(self.e.c['engine_sha256'],hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest())
    def test_install_idempotent_keeps_decisions(self):
        before=self.e.reg.read('SELECT * FROM acceptances')
        self.assertEqual(receipts.install_extension(self.config)['state'],'ALREADY_INSTALLED')
        self.assertEqual(before,self.e.reg.read('SELECT * FROM acceptances'))
    def test_sign_public_verify_no_upgrade(self):
        before=self.e.reg.read('SELECT receipt,verification FROM acceptances')[0]
        raw,v=self.read_signed(); self.assertEqual(v['signature'],'VALID')
        self.assertEqual(v['body']['qualification'],'LAB_CANDIDATE_UNQUALIFIED')
        self.assertEqual(before,self.e.reg.read('SELECT receipt,verification FROM acceptances')[0])
        self.assertEqual(json.loads(__import__('base64').b64decode(v['body']['acceptance_b64']))['qualification'],'NOT_GRANTED')
    def test_hash_and_signature_tamper_rejected(self):
        raw,v=self.read_signed(); envelope=json.loads(raw); sig=bytearray(__import__('base64').b64decode(envelope['signature_b64'])); sig[-1]^=1
        envelope['signature_b64']=__import__('base64').b64encode(sig).decode()
        self.assert_reason('SIGNATURE_MISMATCH',verify_signed_receipt,common.json_bytes(envelope),receipts.public_trust(self.config))
    def test_lost_publish_response_reuses_exact_signature(self):
        def lost(phase,detail):
            if phase=='signed-receipt-published-before-record': raise common.CASError('PUBLICATION_OUTCOME_UNKNOWN',code=9)
        first=receipts.ReceiptService(self.config,barrier=lost).drain_receipts(); self.assertEqual(first[0]['state'],'UNKNOWN')
        old=self.e.reg.read('SELECT envelope_bytes FROM t6_receipt_outbox')[0]['envelope_bytes']
        raw,v=self.read_signed(); self.assertEqual(old,raw); self.assertEqual(len(list((self.exchange/'receipt_outbox').glob('*.json'))),1)
    def test_offline_never_calls_provider(self):
        with mock.patch.object(self.service.supervisor,'run',side_effect=AssertionError('provider')):
            self.assertEqual(self.service.drain_receipts(offline=True)[0]['provider_calls'],0)
        self.assertFalse((self.exchange/'receipt_outbox').exists())
    def test_rotate_and_revoke(self):
        raw,v=self.read_signed(); receipts.initialize_signing(self.config,rotate=True)
        self.assertEqual(verify_signed_receipt(raw,receipts.public_trust(self.config))['signature'],'VALID')
        receipts.revoke_key(self.config,v['key_id'],'fixture revocation')
        self.assert_reason('SIGNER_REVOKED',verify_signed_receipt,raw,receipts.public_trust(self.config))
    def test_audit_append_only_and_unsealed_tail(self):
        with self.e.reg.transaction() as con: self.e.reg.audit(con,'POST_UPGRADE_BASE_EVENT',{'fixture':True})
        self.assertGreater(self.service.status()['audit_head']['unsealed_tail'],0)
        self.read_signed(); self.assertEqual(self.service.status()['audit_head']['unsealed_tail'],0)
        with self.assertRaises(sqlite3.IntegrityError):
            with self.e.reg.transaction() as con: con.execute("UPDATE audit SET event='FORGED' WHERE ordinal=1")
    def test_replay_returns_no_new_decision(self):
        self.read_signed(); self.assertEqual(self.service.drain_receipts(),[])
        self.assertEqual(len(self.e.reg.read('SELECT * FROM acceptances')),1)
    def test_no_secret_in_cloud_files(self):
        self.read_signed()
        private_keys=[p.read_bytes() for p in (self.private/'keys').glob('*.private')]
        for p in (self.exchange/'receipt_outbox').glob('*.json'):
            raw=p.read_bytes()
            for secret in private_keys:
                self.assertNotIn(secret,raw); self.assertNotIn(__import__('base64').b64encode(secret),raw)
    def test_retry_budget_survives_reconstruction(self):
        self.service.enqueue()
        with self.e.reg.transaction() as con: con.execute('UPDATE t6_receipt_outbox SET attempts=8')
        result=receipts.ReceiptService(self.config).drain_receipts()
        self.assertEqual(result[0]['state'],'HOLD_RETRY'); self.assertFalse((self.exchange/'receipt_outbox').exists())

class TestNativeLifecycleAndWrapper(NativeFixture):
    def test_retire_pinned_refused_and_floor_preserved(self):
        ev=receipts.LocalCacheEvictor(self.config); row=self.e.reg.read('SELECT g FROM acceptances')[0]
        self.assert_reason('GENERATION_PINNED',ev.retire_generation,row['g'],'fixture')
        before=ev.plan(0); self.assertGreater(before['protected_floor_bytes'],0)
        self.assert_reason('HOLD_RESOURCE',ev.prune,0)
        self.assertEqual(before['protected_floor_bytes'],ev.plan(0)['protected_floor_bytes'])
    def test_default_export_survives_prune(self):
        result=self.e.get(self.put['root_hash']); destination=Path(result['output_path']); before=destination.read_bytes()
        self.assert_reason('HOLD_RESOURCE',receipts.LocalCacheEvictor(self.config).prune,0)
        self.assertEqual(before,destination.read_bytes())
    def test_retire_exact_generation_resumable_no_new_pin(self):
        result=self.e.get(self.put['root_hash']); operation=result['operation_id']
        native.release_export(self.config,operation,reason='completed fixture consumer')
        row=self.e.reg.read('SELECT output_g FROM exports WHERE o=?',(operation,))[0]; g=row['output_g']
        ev=receipts.LocalCacheEvictor(self.config)
        self.assertEqual(ev.retire_generation(g,'fixture')['state'],'RETIRING')
        with self.assertRaises(sqlite3.IntegrityError):
            with self.e.reg.transaction() as con: con.execute('INSERT INTO pins VALUES(?,?,?,?)',(g,'late-reader','READER',native.utc()))
        self.assertEqual(ev.remove_generation(g)['state'],'ABSENT'); self.assertTrue(ev.remove_generation(g)['replayed'])
        self.assertFalse(Path(result['output_path']).exists())
    def test_wrapper_selects_native_status_and_drains(self):
        cmd=[sys.executable,str(ROOT/'tools/drive_engine.py'),'--config',str(self.config)]
        status=subprocess.run(cmd+['status'],capture_output=True,timeout=30)
        self.assertEqual(status.returncode,0,status.stderr); self.assertEqual(json.loads(status.stdout)['profile'],'NATIVE54')
        drain=subprocess.run(cmd+['drain'],capture_output=True,timeout=30)
        self.assertEqual(drain.returncode,0,drain.stdout)
        self.assertEqual(json.loads(drain.stdout)['result'][0]['state'],'LOCAL_PUBLISHED')
    def test_wrapper_prune_floor_and_plan(self):
        cmd=[sys.executable,str(ROOT/'tools/drive_engine.py'),'--config',str(self.config),'prune','--max-size-gb','0']
        actual=subprocess.run(cmd,capture_output=True,timeout=30); self.assertEqual(actual.returncode,8,actual.stdout)
        plan=subprocess.run(cmd+['--dry-run'],capture_output=True,timeout=30); self.assertEqual(plan.returncode,0,plan.stdout)
    def test_single_authority_distinct_candidates_do_not_reopen_k(self):
        self.source.write_bytes(b'a distinct alternative'); alternate=self.e.put(str(self.source))
        result=receipts.arbitrate_candidates(self.config,[dict(dropzone_dir=alternate['submission_dir'],operation_id=str(uuid.uuid4()))])
        self.assertEqual(result[0]['state'],'REJECTED'); self.assertEqual(len(self.e.reg.read('SELECT * FROM acceptances')),1)

class TestNativeActivation(NativeFixture):
    def fixture_qualification(self):
        q=str(uuid.uuid4()); record={'scope':'FIXTURE_ONLY'}
        with self.e.reg.transaction() as con:
            raw=common.json_bytes(record); con.execute('INSERT INTO t6_qualifications VALUES(?,?,?,1)',(q,raw,common.sha(raw)))
        return q
    def test_no_implicit_activation(self):
        self.assert_reason('RECEIPT_QUALIFICATION_REQUIRED',self.service.activate_receipt,self.rh,str(uuid.uuid4()),str(uuid.uuid4()))
        self.assertEqual(self.e.reg.read('SELECT * FROM t6_activations'),[])
    def test_fixture_activation_fresh_readback_not_history_rewrite(self):
        q=self.fixture_qualification(); o=str(uuid.uuid4()); original=self.e.reg.read('SELECT receipt FROM acceptances')[0]['receipt']
        with mock.patch.object(self.service,'_activation_qualification',return_value={'fixture':True}):
            result=self.service.activate_receipt(self.rh,q,o)
            self.assertTrue(self.service.activate_receipt(self.rh,q,o)['replayed'])
        out=self.service.drain_receipts(); self.assertEqual(len(out),2,out)
        bodies=[verify_signed_receipt(Path(r['path']).read_bytes(),receipts.public_trust(self.config))['body'] for r in out]
        self.assertEqual({b['qualification'] for b in bodies},{'LAB_CANDIDATE_UNQUALIFIED','FIXTURE_ONLY'})
        self.assertEqual(original,self.e.reg.read('SELECT receipt FROM acceptances')[0]['receipt'])
    def test_fixture_activation_destination_tamper_blocks(self):
        q=self.fixture_qualification(); row=self.e.reg.read('SELECT g.* FROM generations g JOIN acceptances a ON a.g=g.g')[0]
        ev=json.loads(row['evidence']); file=Path(row['path'])/'files'/ev['files'][0]['path']; file.write_bytes(b'corrupted private bytes')
        with mock.patch.object(self.service,'_activation_qualification',return_value={'fixture':True}):
            with self.assertRaises(common.CASError): self.service.activate_receipt(self.rh,q,str(uuid.uuid4()))
        self.assertEqual(self.e.reg.read('SELECT * FROM t6_activations'),[])

class TestNativeProviderReadModel(NativeFixture):
    def exercise(self,mode):
        target=next(Path(self.put['submission_dir']).glob('blocks/sha256/*/*/*.bin'))
        event=self.base/'fault-event.jsonl'; dest=self.base/'fault-capture'
        actual_popen=subprocess.Popen
        def injected(argv,*args,**kwargs):
            argv=list(argv)
            if str(Path(native.__file__).absolute()) in argv:
                argv[argv.index(str(Path(native.__file__).absolute()))]=str(ROOT/'native_fileprovider_mock.py')
            return actual_popen(argv,*args,**kwargs)
        call=dict(source=self.put['submission_dir'],output=str(dest),root=self.put['root_hash'],contract=self.contract,
                  _mock_fault=dict(mode=mode,target=str(target),event=str(event)))
        with mock.patch.object(subprocess,'Popen',side_effect=injected):
            if mode=='HYDRATE':
                result=self.e.supervisor.run('capture',call,timeout=15)
                self.assertEqual((dest/'files'/'file.bin').read_bytes(),self.source.read_bytes())
            else:
                self.assert_reason('WORKER_SIGNAL' if mode=='SIGBUS' else 'FILESYSTEM_ERROR',self.e.supervisor.run,'capture',call,timeout=15)
        records=[json.loads(line) for line in event.read_text().splitlines()]
        self.assertGreater(records[0]['size'],0)
        self.assertEqual(records[0]['phase'],'AFTER_REAL_READ')
        self.assertEqual(len(self.e.reg.read('SELECT * FROM acceptances')),1)
    def test_native_modeled_hydration_actual_bytes(self): self.exercise('HYDRATE')
    def test_native_injected_sigbus_after_actual_read(self): self.exercise('SIGBUS')
    def test_native_injected_eio_after_actual_read(self): self.exercise('EIO')

if __name__=='__main__': unittest.main(verbosity=2)
