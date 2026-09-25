#!/usr/bin/env python3
"""Executable independent expectations for Turn 5's selected acceptance scope.

Run: python -m unittest -v test_drive_cas
Actual filesystem/process tests run on THIS machine; Linux != Apple/FileProvider.
Fixtures are owned TemporaryDirectories. No real Drive account is changed.
"""
from __future__ import annotations
import copy
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

import drive_cas as cas

B = 4194304

def independent_bytes(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')

def independent_sha(data): return hashlib.sha256(data).hexdigest()

def independent_node(kind, **values):
    return dict(kind=kind,schema_version=1,wire_profile='ascii-json-1',**values)

def independent_candidate(chunks_parent: Path, contract: dict, payloads: dict[str, bytes],
                          layout='fixed-4m-v1', wrong_whole=False, reverse=False,
                          wrong_totals=False, root_extra=None):
    """Independent wire fixture. Never invokes the engine builder/verifier."""
    files={}; metadata={}; blocks={}; artifacts=[]; logical=occurrences=0
    block_size={'fixed-4m-v1':4194304,'fixed-16m-v1':16777216}[layout]
    def store(v):
        raw=independent_bytes(v); h=independent_sha(raw)
        ref=dict(kind=v['kind'],sha256=h,size_bytes=len(raw))
        name=f'nodes/{v["kind"]}/sha256/{h[:2]}/{h[2:4]}/{h}.json'
        files[name]=raw; metadata[(v['kind'],h)]=len(raw)
        return ref
    for slot in contract['slots']:
        data=payloads[slot['path']]; refs=[]
        for start in range(0,len(data),block_size):
            part=data[start:start+block_size]; h=independent_sha(part)
            files[f'blocks/sha256/{h[:2]}/{h[2:4]}/{h}.bin']=part
            blocks[h]=len(part); refs.append(dict(sha256=h,size_bytes=len(part)))
        ordered=list(reversed(refs)) if reverse else refs
        pages=[store(independent_node('chunk_page',chunks=ordered[i:i+4096])) for i in range(0,len(ordered),4096)]
        fm=store(independent_node('file_map',layout_profile=layout,size_bytes=len(data),
            content_sha256=('0'*64 if wrong_whole else independent_sha(data)),chunk_count=len(refs),pages=pages))
        artifacts.append(dict(path=slot['path'],role=slot['role'],media_type=slot['media_type'],file_map=fm))
        logical+=len(data); occurrences+=len(refs)
    dataset=store(independent_node('dataset',artifacts=artifacts))
    totals=dict(artifact_count=len(artifacts),logical_bytes=logical,chunk_references=occurrences,
                unique_blocks=len(blocks),unique_block_bytes=sum(blocks.values()),
                unique_metadata_nodes=len(metadata),unique_metadata_bytes=sum(metadata.values()))
    if wrong_totals: totals['unique_blocks']+=1
    attempt=str(uuid.uuid4())
    m=independent_node('submission',protocol='gdoe-cas/1',
        **{k:contract[k] for k in ('store_id','campaign','task_id','task_revision')},
        contract_sha256=independent_sha(independent_bytes(contract)),producer_agent='lab',
        producer_installation=str(uuid.uuid4()),attempt_id=attempt,
        created_at_utc='2026-09-23T00:00:00.000000Z',dataset=dataset,
        storage=dict(profile='self-contained-v1',pool_id=None),totals=totals)
    if root_extra: m.update(root_extra)
    raw=independent_bytes(m); root=independent_sha(raw); files['manifest.json']=raw
    files['COMMIT.json']=independent_bytes(independent_node('producer_commit',submission_sha256=root,
        manifest_size_bytes=len(raw),attempt_id=attempt,prepared_at_utc='2026-09-23T00:00:00.000000Z'))
    leaf=chunks_parent/root; leaf.mkdir()
    for name,data in files.items():
        target=leaf/name; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(data)
    return leaf,root

def independent_layout(leaf):
    def load(ref):
        h=ref['sha256']
        raw=(leaf/f'nodes/{ref["kind"]}/sha256/{h[:2]}/{h[2:4]}/{h}.json').read_bytes()
        assert len(raw)==ref['size_bytes'] and independent_sha(raw)==h
        return json.loads(raw)
    rootbytes=(leaf/'manifest.json').read_bytes()
    assert independent_sha(rootbytes)==leaf.name
    manifest=json.loads(rootbytes); dataset=load(manifest['dataset']); outputs=[]
    for a in dataset['artifacts']:
        fm=load(a['file_map']); parts=[]; refs=[]
        for pr in fm['pages']:
            for ref in load(pr)['chunks']:
                h=ref['sha256']; b=(leaf/f'blocks/sha256/{h[:2]}/{h[2:4]}/{h}.bin').read_bytes()
                assert len(b)==ref['size_bytes'] and independent_sha(b)==h
                parts.append(b); refs.append(ref)
        content=b''.join(parts)
        assert len(content)==fm['size_bytes'] and independent_sha(content)==fm['content_sha256']
        outputs.append((a,fm,refs,content))
    return manifest,outputs


class StoreCase(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='drive-cas-tests-')
        self.base=Path(self.tmp.name).resolve()
        self.exchange=self.base/'exchange'; self.exchange.mkdir()
        self.sources=self.base/'sources'; self.sources.mkdir()
        self.outputs=self.base/'outputs'; self.outputs.mkdir()
        self.private=self.base/'private'
        self.config=cas.enroll_store(str(self.private),str(self.exchange),[str(self.sources)],
            [str(self.outputs)],limits=dict(reserve_bytes=0,reserve_percent=0,max_file_bytes=256*1024**2,max_task_bytes=512*1024**2))
        self.cfg=cas.load_config(self.config)
        self.contract=cas.make_contract(self.cfg['store_id'],'campaign','task')
        self.intake=self.exchange/'intake'
        cas.enroll_task(self.config,str(self.intake),self.contract)
        self.engine=cas.DriveEngine(self.config)

    def tearDown(self): self.tmp.cleanup()

    def put(self,data=b'payload',approve=True):
        path=self.sources/(str(uuid.uuid4())+'.bin'); path.write_bytes(data)
        r=self.engine.put(str(path))
        if approve: cas.approve_candidate(self.config,r['root'],self.contract)
        return r

    def db_query(self,sql,args=()):
        # Independent read-only observer: no engine query or acceptance predicate.
        db=sqlite3.connect((self.private/'state.sqlite3').as_uri()+'?mode=ro',uri=True)
        try: return db.execute(sql,args).fetchall()
        finally: db.close()

    def assertReason(self,reason,call):
        with self.assertRaises(cas.CASError) as raised: call()
        self.assertEqual(raised.exception.reason,reason)
        return raised.exception

    def external(self,data=b'bytes',**kwargs):
        leaf,root=independent_candidate(self.intake/'chunks',self.contract,{'artifact.bin':data},**kwargs)
        cas.approve_candidate(self.config,root,self.contract)
        return leaf,root


class TestAT02(StoreCase):
    def test_empty_stream_allow(self):
        # Separate explicitly enrolled task, not a producer manifest policy.
        c=cas.make_contract(self.cfg['store_id'],'campaign','empty')
        c['slots'][0]['allow_empty']=1
        intake=self.exchange/'empty'; cas.enroll_task(self.config,str(intake),c)
        src=self.sources/'empty'; src.write_bytes(b'')
        r=self.engine.put(str(src),str(intake)); cas.approve_candidate(self.config,r['root'],c)
        m,out=independent_layout(Path(r['submission_dir']))
        self.assertEqual(out[0][1]['pages'],[]); self.assertEqual(m['totals']['unique_blocks'],0)
        self.assertEqual(out[0][1]['content_sha256'],'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
        self.engine.commit(r['submission_dir'])
        got=self.engine.get(r['root']); self.assertEqual(Path(got['output_path']).read_bytes(),b'')

    def test_empty_stream_forbid(self):
        self.assertReason('CONTRACT_MISMATCH',lambda:self.put(b''))
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],0)

    def test_empty_dataset_allowed_and_forbidden(self):
        for allowed in (True,False):
            c=cas.make_contract(self.cfg['store_id'],'campaign','ds'+str(int(allowed)),slots=[],allow_empty_dataset=allowed)
            intake=self.exchange/('ds'+str(int(allowed))); cas.enroll_task(self.config,str(intake),c)
            leaf,root=independent_candidate(intake/'chunks',c,{})
            cas.approve_candidate(self.config,root,c)
            if allowed:
                self.engine.verify(str(leaf)); self.engine.commit(str(leaf))
                self.assertReason('TASK_SHAPE_UNSUPPORTED',lambda:self.engine.get(root))
            else: self.assertReason('CONTRACT_MISMATCH',lambda:self.engine.commit(str(leaf)))

    def test_zero_length_block_ref_rejected(self):
        self.assertReason('INVALID_INTEGER',lambda:cas.block_ref(dict(sha256=independent_sha(b''),size_bytes=0)))


class TestAT03(unittest.TestCase):
    def test_boundary_packing_both_profiles(self):
        for size in (4194304,16777216):
            for length in (size-1,size,size+1,2*size):
                with self.subTest(size=size,length=length):
                    data=(bytes(range(251))*((length+250)//251))[:length]
                    chunks=list(cas.fixed_chunks(io.BytesIO(data),size))
                    self.assertEqual([len(x) for x in chunks],[min(size,length-i) for i in range(0,length,size)])
                    self.assertEqual(b''.join(chunks),data)

    def test_short_reads_are_not_eof(self):
        class Short(io.BytesIO):
            def read(self,n=-1): return super().read(min(n,11731))
        data=b'x'*(B+31)
        chunks=list(cas.fixed_chunks(Short(data),B))
        self.assertEqual([len(x) for x in chunks],[B,31]); self.assertEqual(b''.join(chunks),data)

    def test_no_empty_tail(self):
        self.assertEqual(list(cas.fixed_chunks(io.BytesIO(b''))),[])
        self.assertEqual(len(list(cas.fixed_chunks(io.BytesIO(b'a'*B)))),1)


class TestAT06(StoreCase):
    def test_trailing_byte_even_if_prefix_hash_matches(self):
        leaf,root=self.external(b'prefix')
        block=next((leaf/'blocks').rglob('*.bin')); block.write_bytes(b'prefix!')
        self.assertReason('LENGTH_MISMATCH',lambda:self.engine.verify(str(leaf)))
        self.assertReason('LENGTH_MISMATCH',lambda:self.engine.commit(str(leaf)))
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],0)

    def test_early_eof(self):
        leaf,root=self.external(b'long-enough'); next((leaf/'blocks').rglob('*.bin')).write_bytes(b'x')
        self.assertReason('LENGTH_MISMATCH',lambda:self.engine.verify(str(leaf)))

    def test_read_exact_without_hash_is_still_exact(self):
        p=self.sources/'short'; p.write_bytes(b'a')
        with cas.SafeTree(self.sources) as tree:
            self.assertReason('LENGTH_MISMATCH',lambda:tree.read('short',2,2))

    def test_correct_chunks_wrong_whole_digest(self):
        leaf,root=self.external(b'data',wrong_whole=True)
        self.assertReason('WHOLE_FILE_MISMATCH',lambda:self.engine.verify(str(leaf)))

    def test_same_length_changed_payload(self):
        leaf,root=self.external(b'AAAA'); next((leaf/'blocks').rglob('*.bin')).write_bytes(b'BBBB')
        self.assertReason('DIGEST_MISMATCH',lambda:self.engine.verify(str(leaf)))

    def test_totals_recomputed(self):
        leaf,root=self.external(b'data',wrong_totals=True)
        self.assertReason('TOTALS_MISMATCH',lambda:self.engine.verify(str(leaf)))


class TestAT07(StoreCase):
    def test_reordered_leaves_rehashed_metadata_wrong_reconstruction(self):
        leaf,root=self.external(b'A'*B+b'B'*B,reverse=True)
        self.assertReason('WHOLE_FILE_MISMATCH',lambda:self.engine.verify(str(leaf)))

    def test_valid_fully_rehashed_alternate_root_needs_approval(self):
        good=self.put(b'approved')
        alternate,root=independent_candidate(self.intake/'chunks',self.contract,{'artifact.bin':b'unapproved'})
        self.assertReason('ROOT_NOT_APPROVED',lambda:self.engine.verify(str(alternate)))
        self.assertReason('APPROVAL_REQUIRED',lambda:self.engine.commit(str(alternate)))
        # A producer-written adjacent approval does not become authority.
        (alternate/'APPROVAL.json').write_bytes(independent_bytes({'root':root,'approved':True}))
        self.assertReason('APPROVAL_REQUIRED',lambda:self.engine.commit(str(alternate)))
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],0)

    def test_legitimate_repetition_preserved(self):
        r=self.put(b'X'*B+b'X'*B)
        m,outputs=independent_layout(Path(r['submission_dir']))
        self.assertEqual(m['totals']['chunk_references'],2); self.assertEqual(m['totals']['unique_blocks'],1)
        got=self.engine.get(r['root']); self.assertEqual(Path(got['output_path']).read_bytes(),b'X'*B*2)

    def test_root_bytes_not_repaired(self):
        r=self.put(b'valid'); leaf=Path(r['submission_dir'])
        parsed=json.loads((leaf/'manifest.json').read_bytes())
        (leaf/'manifest.json').write_text(json.dumps(parsed,indent=2))
        self.assertReason('DIGEST_MISMATCH',lambda:self.engine.verify(str(leaf)))


class TestAT15(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name).resolve()
    def tearDown(self): self.tmp.cleanup()

    def test_file_no_clobber_native(self):
        (self.root/'a').write_bytes(b'left'); (self.root/'b').write_bytes(b'right')
        with cas.SafeTree(self.root) as t:
            with self.assertRaises(cas.CASError) as error: cas.AtomicPublisher().rename(t,'a',t,'b')
            self.assertEqual(error.exception.reason,'OUTPUT_EXISTS')
        self.assertEqual((self.root/'a').read_bytes(),b'left'); self.assertEqual((self.root/'b').read_bytes(),b'right')

    def test_directory_no_clobber_and_success(self):
        (self.root/'a').mkdir(); (self.root/'b').mkdir(); (self.root/'a/x').write_bytes(b'complete')
        with cas.SafeTree(self.root) as t:
            with self.assertRaises(cas.CASError): cas.AtomicPublisher().rename(t,'a',t,'b')
            cas.AtomicPublisher().rename(t,'a',t,'c')
        self.assertFalse((self.root/'a').exists()); self.assertEqual((self.root/'c/x').read_bytes(),b'complete')

    def test_unsupported_does_not_fall_back(self):
        (self.root/'a').write_bytes(b'x')
        pub=cas.AtomicPublisher()
        def unavailable(*args): ctypes.set_errno(38 if sys.platform=='linux' else 78); return -1
        pub.fn=unavailable
        with cas.SafeTree(self.root) as t, self.assertRaises(cas.CASError) as error: pub.rename(t,'a',t,'b')
        self.assertEqual(error.exception.reason,'ATOMIC_PUBLISH_UNSUPPORTED')
        self.assertTrue((self.root/'a').exists()); self.assertFalse((self.root/'b').exists())


class TestPublication(StoreCase):
    def test_same_operation_replay_source_changed(self):
        path=self.sources/'original'; path.write_bytes(b'first'); o=str(uuid.uuid4())
        first=self.engine.put(str(path),operation_id=o); path.write_bytes(b'changed')
        replay=self.engine.put(str(path),operation_id=o)
        self.assertEqual(first['root'],replay['root'])
        _,out=independent_layout(Path(replay['submission_dir'])); self.assertEqual(out[0][3],b'first')
        self.assertEqual(len(list((self.intake/'chunks').iterdir())),1)

    def test_occupied_final_identical_reconciles(self):
        r=self.put(b'whole'); root=r['root']; summary=self.db_query('SELECT summary_json FROM snapshots WHERE root=?',(root,))[0][0]
        relative=self.db_query('SELECT relative_path FROM generations WHERE root=?',(root,))[0][0]
        with cas.AuthorityRegistry(self.cfg) as reg:
            binding=reg.binding()
        result=self.engine.supervisor.run('publish',dict(source=str(self.private/relative/'tree'),root=root,
            binding=binding,contract=self.contract,limits=self.cfg['limits']))
        self.assertEqual(result['local_publication'],'EXISTING_IDENTICAL')
        _,out=independent_layout(Path(r['submission_dir'])); self.assertEqual(out[0][3],b'whole')

    def test_occupied_final_corrupt_never_repaired(self):
        r=self.put(b'whole'); leaf=Path(r['submission_dir']); block=next((leaf/'blocks').rglob('*.bin')); block.write_bytes(b'BROKE')
        relative=self.db_query('SELECT relative_path FROM generations WHERE root=?',(r['root'],))[0][0]
        with cas.AuthorityRegistry(self.cfg) as reg: binding=reg.binding()
        self.assertReason('DIGEST_MISMATCH',lambda:self.engine.supervisor.run('publish',dict(source=str(self.private/relative/'tree'),root=r['root'],binding=binding,contract=self.contract,limits=self.cfg['limits'])))
        self.assertEqual(block.read_bytes(),b'BROKE')


class TestAT18(StoreCase):
    def queued(self):
        a=self.put(b'candidate-A'); b=self.put(b'candidate-B'); oa=str(uuid.uuid4()); ob=str(uuid.uuid4())
        qa=self.engine.commit(a['submission_dir'],oa,queue_only=True)
        qb=self.engine.commit(b['submission_dir'],ob,queue_only=True)
        return a,b,oa,ob,qa,qb

    def test_durable_order_restart_one_root(self):
        a,b,oa,ob,qa,qb=self.queued(); self.assertLess(qa['request_sequence'],qb['request_sequence'])
        with cas.AuthorityRegistry(self.cfg) as reg: cas.DropzoneAdmissionBroker(reg).advance_admission_queue()
        decisions=self.db_query('SELECT root,operation_id FROM acceptances')
        self.assertEqual(decisions,[(a['root'],oa)])
        self.assertReason('TASK_ALREADY_ACCEPTED',lambda:self.engine.commit(b['submission_dir'],ob))
        r1=self.engine.commit(a['submission_dir'],oa); r2=self.engine.commit(a['submission_dir'],oa)
        self.assertEqual(independent_bytes(r1['acceptance_receipt']),independent_bytes(r2['acceptance_receipt']))
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM receipt_outbox')[0][0],1)

    def test_stale_fence_blocks_request(self):
        a=self.put(b'A'); oa=str(uuid.uuid4()); self.engine.commit(a['submission_dir'],oa,queue_only=True)
        with cas.AuthorityRegistry(self.cfg) as reg:
            with reg.transaction() as c: c.execute('UPDATE tasks SET fence=fence+1')
            cas.DropzoneAdmissionBroker(reg).advance_admission_queue()
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],0)
        self.assertEqual(self.db_query('SELECT state,reason FROM admission_requests')[0],('BLOCKED','STALE_FENCE'))

    def test_earlier_unknown_prevents_bypass(self):
        a,b,oa,ob,qa,qb=self.queued()
        with cas.AuthorityRegistry(self.cfg) as reg:
            with reg.transaction() as c: c.execute("UPDATE admission_requests SET state='UNKNOWN' WHERE operation_id=?",(oa,))
            self.assertReason('COMMIT_OUTCOME_UNKNOWN',lambda:cas.DropzoneAdmissionBroker(reg).advance_admission_queue())
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],0)

    def test_epoch_never_reopens_task(self):
        a=self.put(b'A'); b=self.put(b'B'); self.engine.commit(a['submission_dir'])
        with cas.AuthorityRegistry(self.cfg) as reg, reg.transaction() as c:
            c.execute("UPDATE meta SET value='2\n' WHERE key='authority_epoch'")
        self.assertReason('TASK_ALREADY_ACCEPTED',lambda:self.engine.commit(b['submission_dir']))
        self.assertEqual(self.db_query('SELECT root FROM acceptances'),[(a['root'],)])

    def test_two_actual_processes_compete(self):
        a=self.put(b'A'); b=self.put(b'B')
        children=[]
        for x in (a,b):
            children.append(subprocess.Popen([sys.executable,str(Path(cas.__file__).resolve()),'--config',self.config,
                '--operation-id',str(uuid.uuid4()),'commit',x['submission_dir']],stdout=subprocess.PIPE,stderr=subprocess.PIPE))
        results=[p.communicate(timeout=30) for p in children]
        codes=sorted(p.returncode for p in children)
        self.assertEqual(codes,[0,5],results)
        self.assertEqual(self.db_query('SELECT COUNT(DISTINCT root) FROM acceptances')[0][0],1)


class TestAT22(StoreCase):
    def test_private_snapshot_survives_source_tamper_and_loss(self):
        good=b'private verified bytes'; r=self.put(good); leaf=Path(r['submission_dir'])
        self.engine.commit(str(leaf))
        next((leaf/'blocks').rglob('*.bin')).write_bytes(b'!'*len(good))
        self.assertReason('DIGEST_MISMATCH',lambda:self.engine.verify(str(leaf)))
        out=self.engine.get(r['root']); self.assertEqual(Path(out['output_path']).read_bytes(),good)
        shutil.rmtree(leaf)
        out2=self.engine.get(r['root']); self.assertEqual(Path(out2['output_path']).read_bytes(),good)

    def test_tamper_after_capture_before_admission_uses_good_generation(self):
        r=self.put(b'captured'); leaf=Path(r['submission_dir'])
        next((leaf/'blocks').rglob('*.bin')).write_bytes(b'TAMPERED')
        self.engine.commit(str(leaf))
        got=self.engine.get(r['root']); self.assertEqual(Path(got['output_path']).read_bytes(),b'captured')

    def test_destination_tamper_before_readback_detected(self):
        leaf,root=self.external(b'original')
        workspace=self.base/'capture'; workspace.mkdir()
        def barrier(phase,info):
            if phase=='before-destination-readback': (Path(info['workspace'])/info['path']).write_bytes(b'!riginal')
        v=cas.MerkleVerifier(self.cfg['limits'],barrier=barrier)
        self.assertReason('DESTINATION_MISMATCH',lambda:v.verify_tree(str(leaf),root,self.contract,
            capture_to=str(workspace),approved_roots=[root]))

    def test_private_corruption_not_certified_by_old_receipt(self):
        r=self.put(b'protected'); self.engine.commit(r['submission_dir'])
        relative=self.db_query('SELECT relative_path FROM generations WHERE root=?',(r['root'],))[0][0]
        (self.private/relative/'files/00000000.bin').write_bytes(b'CORRUPTED')
        self.assertReason('DESTINATION_MISMATCH',lambda:self.engine.get(r['root']))
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],1)
        self.assertEqual(self.db_query('SELECT state FROM generations WHERE root=?',(r['root'],))[0][0],'CORRUPT')

    def test_fresh_verify_is_read_only(self):
        r=self.put(b'readonly'); leaf=Path(r['submission_dir']); before=(self.private/'state.sqlite3').read_bytes()
        source_hashes={str(p.relative_to(leaf)):independent_sha(p.read_bytes()) for p in leaf.rglob('*') if p.is_file()}
        result=self.engine.verify(str(leaf))
        self.assertEqual(result['scope'],'OBSERVED_CLOSURE'); self.assertEqual(before,(self.private/'state.sqlite3').read_bytes())
        self.assertEqual(source_hashes,{str(p.relative_to(leaf)):independent_sha(p.read_bytes()) for p in leaf.rglob('*') if p.is_file()})
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],0)


class TestAdditional(StoreCase):
    def test_strict_canonical_profile(self):
        for raw in (b'{"a":1,"a":2}\n',b'{ "a":1}\n',b'{"a":true}\n',b'{"a":1e0}\n',b'{"a":1}\n\n'):
            with self.subTest(raw=raw), self.assertRaises(cas.CASError): cas.wire_read(raw)

    def test_symlink_source_rejected(self):
        real=self.sources/'real'; real.write_bytes(b'x'); link=self.sources/'link'; link.symlink_to(real)
        with self.assertRaises(cas.CASError): self.engine.put(str(link))
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM snapshots')[0][0],0)

    def test_unregistered_root_get_refused(self):
        leaf,root=self.external(b'external')
        self.assertReason('ROOT_NOT_REGISTERED',lambda:self.engine.get(root))

    def test_external_candidate_commit_reconstructs(self):
        leaf,root=self.external(b'external')
        r=self.engine.commit(str(leaf)); got=self.engine.get(root)
        self.assertEqual(Path(got['output_path']).read_bytes(),b'external')
        self.assertEqual(r['acceptance_receipt']['kind'],'qualification_acceptance')
        self.assertEqual(self.db_query('PRAGMA foreign_key_check'),[])

    def test_output_no_overwrite(self):
        r=self.put(b'new'); dest=self.outputs/'occupied'; dest.write_bytes(b'keep')
        self.assertReason('OUTPUT_EXISTS',lambda:self.engine.get(r['root'],str(dest)))
        self.assertEqual(dest.read_bytes(),b'keep')

    def test_explicit_output_and_replay(self):
        r=self.put(b'export'); dest=self.outputs/'export'; o=str(uuid.uuid4())
        self.engine.get(r['root'],str(dest),o)
        self.engine.get(r['root'],str(dest),o)
        self.assertEqual(dest.read_bytes(),b'export')
        dest.write_bytes(b'edited')
        self.assertReason('OUTPUT_EXISTS',lambda:self.engine.get(r['root'],str(dest),o))

    def test_pins_survive_prune_zero(self):
        r=self.put(b'keep'); got=self.engine.get(r['root']); self.engine.commit(r['submission_dir'])
        self.assertReason('HOLD_RESOURCE',lambda:self.engine.prune('0'))
        self.assertEqual(Path(got['output_path']).read_bytes(),b'keep')
        self.assertGreater(self.db_query('SELECT COUNT(*) FROM pins')[0][0],0)

    def test_explicit_release_then_prune(self):
        r=self.put(b'garbage'); got=self.engine.get(r['root'])
        cas.release_export(self.config,got['operation_id'],'test consumer is finished')
        cas.release_prepared(self.config,r['root'],'test proposal abandoned')
        result=self.engine.prune('0')
        self.assertTrue(result['target_met_now']); self.assertFalse(Path(got['output_path']).exists())
        self.assertTrue(Path(r['submission_dir']).exists())  # no cloud deletion

    def test_prune_dry_run_no_mutation(self):
        r=self.put(b'protected'); before=(self.private/'state.sqlite3').read_bytes()
        plan=self.engine.prune('0',dry_run=True)
        self.assertFalse(plan['target_would_be_met']); self.assertEqual(before,(self.private/'state.sqlite3').read_bytes())

    def test_lost_authority_does_not_reinitialize(self):
        (self.private/'state.sqlite3').rename(self.private/'state.saved')
        self.assertReason('AUTHORITY_RECOVERY_REQUIRED',lambda:self.engine.prune('0'))
        self.assertFalse((self.private/'state.sqlite3').exists())

    def test_modified_operation_intent_rejected(self):
        r=self.put(b'R'); o=str(uuid.uuid4()); self.engine.get(r['root'],operation_id=o)
        self.assertReason('INTENT_CONFLICT',lambda:self.engine.get(r['root'],str(self.outputs/'different'),o))

    def test_decimal_gb_exact(self):
        self.assertEqual(cas.parse_gb('0.001'),1000000)
        self.assertEqual(cas.parse_gb('1.234'),1234000000)
        for v in ('01','1e3','-1','+1','1.0001','nan'):
            with self.subTest(v=v), self.assertRaises(cas.CASError): cas.parse_gb(v)

    def test_offline_no_new_provider_observation(self):
        r=self.put(b'offline')
        with mock.patch.object(self.engine.supervisor,'run',side_effect=AssertionError('provider call')):
            self.assertReason('OFFLINE_HOLD',lambda:self.engine.verify(r['submission_dir'],offline=True))
        got=self.engine.get(r['root'],offline=True); self.assertEqual(Path(got['output_path']).read_bytes(),b'offline')

    def test_cli_json_and_root_operand(self):
        r=self.put(b'cli')
        p=subprocess.run([sys.executable,str(Path(cas.__file__).resolve()),'--config',self.config,'get',r['root']],capture_output=True,timeout=30)
        self.assertEqual(p.returncode,0,p.stderr+p.stdout)
        result=json.loads(p.stdout); self.assertEqual(result['protocol'],'gdoe-cli/2')
        self.assertEqual(Path(result['result']['output_path']).read_bytes(),b'cli')
        p=subprocess.run([sys.executable,str(Path(cas.__file__).resolve()),'--config',self.config,'prune','--max-size','0'],capture_output=True,timeout=30)
        self.assertEqual(p.returncode,2); self.assertFalse(json.loads(p.stdout)['goal_met'])

    def test_receipt_outbox_export_is_not_remote_receipt(self):
        r=self.put(b'outbox'); self.engine.commit(r['submission_dir'])
        result=self.engine.service_pending()
        self.assertEqual(result[0]['state'],'LOCAL_PUBLISHED')
        receipt=next((self.intake/'receipts').glob('*.json'))
        data=receipt.read_bytes(); self.assertEqual(receipt.stem,independent_sha(data))
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],1)


class TestRecoveryAndContainment(StoreCase):
    def test_unrelated_equal_output_stays_unowned_on_retry(self):
        r=self.put(b'equal'); dest=self.outputs/'already-there'; dest.write_bytes(b'equal')
        o=str(uuid.uuid4())
        self.assertReason('OUTPUT_EXISTS',lambda:self.engine.get(r['root'],str(dest),o))
        self.assertReason('OUTPUT_EXISTS',lambda:self.engine.get(r['root'],str(dest),o))
        self.assertEqual(dest.read_bytes(),b'equal')

    def test_blocked_earlier_request_does_not_choose_directory_order(self):
        a=self.put(b'A'); b=self.put(b'B'); oa=str(uuid.uuid4()); ob=str(uuid.uuid4())
        self.engine.commit(a['submission_dir'],oa,queue_only=True)
        with cas.AuthorityRegistry(self.cfg) as reg,reg.transaction() as c:
            c.execute('UPDATE tasks SET fence=fence+1')
        self.engine.commit(b['submission_dir'],ob,queue_only=True)
        with cas.AuthorityRegistry(self.cfg) as reg:
            cas.DropzoneAdmissionBroker(reg).advance_admission_queue()
        self.assertEqual(self.db_query('SELECT root FROM acceptances'),[(b['root'],)])
        self.assertEqual(self.db_query('SELECT state FROM admission_requests ORDER BY request_sequence'),[('BLOCKED',),('DECIDED',)])

    def test_sigkill_after_decision_commit_replays_exact_receipt(self):
        import signal
        r=self.put(b'crash-safe-reference'); o=str(uuid.uuid4())
        self.engine.commit(r['submission_dir'],o,queue_only=True)
        script="""import os, signal, drive_cas as d
cfg=d.load_config(__import__('sys').argv[1])
with d.AuthorityRegistry(cfg) as reg:
    def cut(event, detail):
        if event=='decision-committed-before-reply':
            os.kill(os.getpid(),signal.SIGKILL)
    d.DropzoneAdmissionBroker(reg,barrier=cut).advance_admission_queue()
"""
        child=subprocess.run([sys.executable,'-c',script,self.config],cwd=str(Path(cas.__file__).parent),capture_output=True,timeout=30)
        self.assertEqual(child.returncode,-signal.SIGKILL)
        before=self.db_query('SELECT receipt_bytes FROM acceptances')[0][0]
        replay=self.engine.commit(r['submission_dir'],o)
        self.assertEqual(independent_bytes(replay['acceptance_receipt']),before)
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],1)
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM receipt_outbox')[0][0],1)
        self.assertGreater(self.db_query("SELECT COUNT(*) FROM pins WHERE kind='ACCEPTANCE_RETENTION'")[0][0],0)

    def test_reader_pin_not_expired_with_approval(self):
        r=self.put(b'pin'); got=self.engine.get(r['root'])
        with cas.AuthorityRegistry(self.cfg) as reg,reg.transaction() as c:
            c.execute('UPDATE approvals SET deadline_ns=0')
        self.assertReason('HOLD_RESOURCE',lambda:self.engine.prune('0'))
        self.assertEqual(Path(got['output_path']).read_bytes(),b'pin')

    def test_worker_timeout_is_bounded_and_no_output_registered(self):
        original=subprocess.Popen
        def sleepy(argv,**kw):
            return original([sys.executable,'-c','import time; time.sleep(30)'],**kw)
        supervisor=cas.WorkerSupervisor(str(self.private),wait_ms=200)
        import time
        start=time.monotonic()
        with mock.patch.object(cas.subprocess,'Popen',side_effect=sleepy):
            self.assertReason('ACQUISITION_TIMEOUT',lambda:supervisor.run('probe',dict(path=str(self.sources))))
        self.assertLess(time.monotonic()-start,3)
        self.assertTrue(supervisor.last_observation['reaped'])
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM snapshots')[0][0],0)

    def test_injected_child_sigbus_does_not_kill_controller(self):
        import signal
        original=subprocess.Popen
        def fault(argv,**kw):
            return original([sys.executable,'-c','import os, signal; os.kill(os.getpid(),signal.SIGBUS)'],**kw)
        with mock.patch.object(cas.subprocess,'Popen',side_effect=fault):
            self.assertReason('WORKER_SIGNAL',lambda:self.engine.supervisor.run('probe',dict(path=str(self.sources))))
        self.assertEqual(self.engine.supervisor.last_observation['returncode'],-signal.SIGBUS)
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],0)

    def test_source_fifo_rejected_without_waiting_for_writer(self):
        fifo=self.sources/'fifo'; os.mkfifo(fifo)
        with self.assertRaises(cas.CASError): self.engine.put(str(fifo))
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM snapshots')[0][0],0)

    def test_restored_known_history_barrier_blocks_new_decision(self):
        cas.enter_recovery(self.config,'explicit restoration boundary fixture')
        source=self.sources/'new'; source.write_bytes(b'new')
        self.assertReason('AUTHORITY_RECOVERY_REQUIRED',lambda:self.engine.put(str(source)))

    def test_digest_namespace_is_not_guessed(self):
        r=self.put(b'not-root')
        self.assertReason('ROOT_NOT_REGISTERED',lambda:self.engine.get(r['content_sha256']))
        self.assertReason('ROOT_NOT_REGISTERED',lambda:self.engine.get(r['file_map_sha256']))

    def test_raw_canonical_only_guard(self):
        self.assertReason('NONCANONICAL_ENCODING',lambda:cas.wire_read(b'{ "a":1}\n'))


class TestExtraFaults(StoreCase):
    def test_export_rename_response_lost_reconciles_original_inode(self):
        source=self.sources/'raw'; source.write_bytes(b'protected-export')
        o=str(uuid.uuid4()); args=dict(source=str(source),sha256=independent_sha(source.read_bytes()),
            size_bytes=source.stat().st_size,output_root=dict(path=str(self.outputs),identity=cas.identity(self.outputs.stat())),
            output_rel='result',operation_id=o,invocation_id=str(uuid.uuid4()),proof_path=str(self.private/'scratch'/'export-proof'))
        original=cas.AtomicPublisher.rename
        def lose_reply(instance,*pos):
            original(instance,*pos)
            raise cas.CASError('PUBLICATION_OUTCOME_UNKNOWN',code=9)
        with mock.patch.object(cas.AtomicPublisher,'rename',lose_reply):
            self.assertReason('PUBLICATION_OUTCOME_UNKNOWN',lambda:cas._worker_dispatch('export',args))
        before=(self.outputs/'result').stat().st_ino
        args['invocation_id']=str(uuid.uuid4())
        result=cas._worker_dispatch('export',args)
        self.assertEqual(result['observation'],'RECONCILED_OWN_INODE')
        self.assertEqual((self.outputs/'result').stat().st_ino,before)
        self.assertEqual((self.outputs/'result').read_bytes(),b'protected-export')

    def test_artificial_equal_key_different_bytes_is_not_overwritten(self):
        # Artificial hash adapter. This is NOT a real SHA-256 collision test.
        source=self.sources/'two-blocks'; source.write_bytes(b'A'*B+b'B'*B)
        workspace=self.base/'collision'; workspace.mkdir()
        with mock.patch.object(cas,'sha',return_value='1'*64):
            self.assertReason('HASH_IDENTITY_INCIDENT',lambda:cas.CASChunkManager(self.cfg['limits']).build_candidate(
                str(workspace),{'artifact.bin':str(source)},self.contract,'lab',self.cfg['installation_id'],
                str(uuid.uuid4()),'2026-09-23T00:00:00.000000Z'))
        kept=next((workspace/'tree/blocks').rglob('*.bin'))
        self.assertEqual(kept.read_bytes(),b'A'*B)
        self.assertFalse((workspace/'tree/manifest.json').exists())

    def test_inconsistent_lengths_rejected_before_cache_reuse(self):
        leaf,oldroot=self.external(b'A'*B+b'A')
        m=json.loads((leaf/'manifest.json').read_bytes())
        def load(ref):
            h=ref['sha256']; return json.loads((leaf/f'nodes/{ref["kind"]}/sha256/{h[:2]}/{h[2:4]}/{h}.json').read_bytes())
        def store(value):
            raw=independent_bytes(value); h=independent_sha(raw)
            path=leaf/f'nodes/{value["kind"]}/sha256/{h[:2]}/{h[2:4]}/{h}.json'
            path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(raw)
            return dict(kind=value['kind'],sha256=h,size_bytes=len(raw))
        dataset=load(m['dataset']); fm=load(dataset['artifacts'][0]['file_map']); page=load(fm['pages'][0])
        page['chunks'][1]['sha256']=page['chunks'][0]['sha256']
        fm['pages'][0]=store(page); dataset['artifacts'][0]['file_map']=store(fm); m['dataset']=store(dataset)
        raw=independent_bytes(m); root=independent_sha(raw); (leaf/'manifest.json').write_bytes(raw)
        marker=json.loads((leaf/'COMMIT.json').read_bytes()); marker['submission_sha256']=root; marker['manifest_size_bytes']=len(raw)
        (leaf/'COMMIT.json').write_bytes(independent_bytes(marker)); renamed=leaf.parent/root; leaf.rename(renamed)
        cas.approve_candidate(self.config,root,self.contract)
        self.assertReason('LENGTH_MISMATCH',lambda:self.engine.verify(str(renamed)))

    def test_native_16m_layout_reader(self):
        leaf,root=self.external(b'A'*(B+7),layout='fixed-16m-v1')
        self.engine.commit(str(leaf)); output=self.engine.get(root)
        self.assertEqual(Path(output['output_path']).read_bytes(),b'A'*(B+7))


class TestEnrollmentGuards(StoreCase):
    def test_outer_root_swap_detected_even_with_original_intake_inode(self):
        r=self.put(b'root continuity')
        old=self.base/'old-exchange'; self.exchange.rename(old); self.exchange.mkdir()
        (old/'intake').rename(self.exchange/'intake')
        self.assertReason('ROOT_IDENTITY_CHANGED',lambda:self.engine.verify(r['submission_dir']))

    def test_production_mutation_requires_external_qualification(self):
        source=self.sources/'raw'; source.write_bytes(b'qualification')
        cfg=json.loads(Path(self.config).read_bytes()); cfg['mode']='PRODUCTION'
        Path(self.config).write_bytes(independent_bytes(cfg))
        engine=cas.DriveEngine(self.config)
        self.assertReason('VERIFICATION_UNQUALIFIED',lambda:engine.put(str(source)))
        self.assertReason('VERIFICATION_UNQUALIFIED',lambda:engine.prune('0'))
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM acceptances')[0][0],0)

    def test_failed_capture_does_not_rebind_same_operation_to_new_source(self):
        source=self.sources/'changing'; source.write_bytes(b'')
        o=str(uuid.uuid4())
        self.assertReason('CONTRACT_MISMATCH',lambda:self.engine.put(str(source),operation_id=o))
        source.write_bytes(b'now different')
        self.assertReason('SOURCE_CAPTURE_OUTCOME_UNKNOWN',lambda:self.engine.put(str(source),operation_id=o))
        self.assertEqual(self.db_query('SELECT COUNT(*) FROM snapshots')[0][0],0)

    def test_cli_bad_identifiers_are_usage_errors(self):
        for args in (['get','not-a-digest'],['--operation-id','not-a-uuid','prune']):
            p=subprocess.run([sys.executable,str(Path(cas.__file__).resolve()),'--config',self.config]+args,capture_output=True,timeout=30)
            self.assertEqual(p.returncode,2,p.stdout+p.stderr)
            self.assertFalse(json.loads(p.stdout)['goal_met'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
