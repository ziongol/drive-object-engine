#!/usr/bin/env python3
"""Executable acceptance subcases. Only disposable owned fixtures are modified.

This suite does not qualify live FileProvider, cellular recovery or power loss.
Its byte/history oracles do not call the engine verifier or canonical serializer.
"""
from __future__ import annotations
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid

import drive_cas as cas

SCRIPT = Path(cas.__file__).absolute()
SUITE_NOTES = {
    "AT-02": "Empty file/dataset, exact encoding and independent contract permission",
    "AT-03": "4/16 MiB boundaries and non-EOF short reads",
    "AT-04": "Strict JSON subset, depth, unknown fields",
    "AT-06": "EOF/trailing byte/whole digest and declared length",
    "AT-07": "Order/repetition and trusted root binding",
    "AT-08": "Symlink/special-file confinement subcases only",
    "AT-09": "Missing block and read-only verification subcases",
    "AT-14": "Injected child failure; no live FileProvider SIGBUS claim",
    "AT-15": "Native local rename on recorded host; FileProvider remains unqualified",
    "AT-18": "Real local SQLite ordering, conflict and process race",
    "AT-19": "Stable intent and exact receipt replay subcases",
    "AT-22": "Before/after capture tampering, private output readback",
    "AT-24": "Explicit export lifetime and generation-specific reclamation",
    "AT-25": "Private-only prune, exact decimal target, protected floor",
    "AT-28": "Missing/replaced authority refuses initialization",
    "AT-32": "Five verbs, machine output and no hidden admission subcases",
}


def suite(name):
    def apply(fn):
        fn.suite_id = name
        return fn
    return apply


def wire(obj):
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def h(data):
    return hashlib.sha256(data).hexdigest()


def loc(ref, block=False):
    d = ref["sha256"]
    return (f"blocks/sha256/{d[:2]}/{d[2:4]}/{d}.bin" if block else
            f"nodes/{ref['kind']}/sha256/{d[:2]}/{d[2:4]}/{d}.json")


def load_ref(leaf, ref):
    data = (leaf / loc(ref)).read_bytes()
    assert len(data) == ref["size_bytes"] and h(data) == ref["sha256"]
    return json.loads(data)


def independent_bytes(leaf):
    """Small independent fixture oracle: raw JSON + ordered bytes, no engine functions."""
    raw = (leaf / "manifest.json").read_bytes()
    assert h(raw) == leaf.name
    root = json.loads(raw); dataset = load_ref(leaf, root["dataset"])
    output = {}
    for art in dataset["artifacts"]:
        fmap = load_ref(leaf, art["file_map"])
        chunks = []
        for pref in fmap["pages"]:
            page = load_ref(leaf, pref)
            for ref in page["chunks"]:
                data = (leaf / loc(ref, True)).read_bytes()
                assert len(data) == ref["size_bytes"] and h(data) == ref["sha256"]
                chunks.append(data)
        joined = b"".join(chunks)
        assert len(joined) == fmap["size_bytes"] and h(joined) == fmap["content_sha256"]
        output[art["path"]] = joined
    return output


def rewrite(leaf, change_map=None, change_page=None):
    """Independent hostile-fixture generator: intentionally produces a new complete root."""
    root = json.loads((leaf / "manifest.json").read_bytes())
    ds = load_ref(leaf, root["dataset"])
    fm = load_ref(leaf, ds["artifacts"][0]["file_map"])
    def put_node(record):
        data = wire(record)
        ref = {"kind": record["kind"], "sha256": h(data), "size_bytes": len(data)}
        path = leaf / loc(ref); path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        return ref
    if change_page:
        page = load_ref(leaf, fm["pages"][0]); change_page(page)
        fm["pages"][0] = put_node(page)
    if change_map: change_map(fm)
    ds["artifacts"][0]["file_map"] = put_node(fm)
    root["dataset"] = put_node(ds)
    refs = {}
    def visit(ref):
        refs[(ref["kind"], ref["sha256"])] = ref
        node = json.loads((leaf / loc(ref)).read_bytes())
        if node["kind"] == "dataset":
            for a in node["artifacts"]: visit(a["file_map"])
        elif node["kind"] == "file_map":
            for p in node["pages"]: visit(p)
    visit(root["dataset"])
    root["totals"]["unique_metadata_nodes"] = len(refs)
    root["totals"]["unique_metadata_bytes"] = sum(r["size_bytes"] for r in refs.values())
    allowed_nodes = {loc(ref) for ref in refs.values()}
    for f in (leaf / "nodes").rglob("*.json"):
        if f.relative_to(leaf).as_posix() not in allowed_nodes: f.unlink()
    raw = wire(root); newroot = h(raw)
    (leaf / "manifest.json").write_bytes(raw)
    marker = json.loads((leaf / "COMMIT.json").read_bytes())
    marker["submission_sha256"] = newroot; marker["manifest_size_bytes"] = len(raw)
    (leaf / "COMMIT.json").write_bytes(wire(marker))
    target = leaf.parent / newroot
    leaf.rename(target)
    return target


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="gdoe-test-")
        self.base = Path(self.tmp.name).resolve()
        self.exchange = self.base / "exchange"; self.exchange.mkdir()
        self.outputs = self.base / "outputs"; self.outputs.mkdir()
        self.config = self.base / "config.json"
        cas.enroll_store(self.config, self.base / "private", self.exchange,
                         export_roots=[str(self.outputs)], reserve_bytes=0, reserve_fraction_milli=0)
        self.private = self.base / "private"
        self.contract = cas.enroll_task(self.config, campaign="fixture", task_id="task",
                  artifacts=[cas.artifact_slot("artifact.bin", allow_empty=True, max_size_bytes=128*1024**2)],
                  selection="ANY_VALID_ENROLLED")
        self.e = cas.DriveEngine(self.config)

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, data=b"abc", layout="fixed-4m-v1", contract=None):
        contract = contract or self.contract
        sources = {}
        for slot in contract["artifacts"]:
            p = self.base / (str(uuid.uuid4()) + ".bin"); p.write_bytes(data)
            sources[slot["path"]] = str(p)
        stage = self.base / str(uuid.uuid4())
        result = cas.CASChunkManager.build(sources, contract, stage, "fixture-producer",
                                           self.e.c["installation_id"], str(uuid.uuid4()), layout)
        leaf = self.exchange / "chunks" / result["root_hash"]
        stage.rename(leaf)
        return leaf

    def direct_verify(self, leaf, contract=None):
        return cas.MerkleVerifier(contract or self.contract, leaf.name).capture(
            leaf, self.base / ("capture-" + str(uuid.uuid4())))

    def put(self, data=b"test payload", o=None):
        p = self.base / "source.bin"; p.write_bytes(data)
        return self.e.put(str(p), operation_id=o)

    def assert_reason(self, reason, fn, *args, **kwargs):
        with self.assertRaises(cas.CASError) as ctx: fn(*args, **kwargs)
        self.assertEqual(ctx.exception.reason, reason)
        return ctx.exception

    def db(self, query, args=()):
        con = sqlite3.connect((self.private / "state.sqlite3").as_uri() + "?mode=ro", uri=True)
        try: return con.execute(query, args).fetchall()
        finally: con.close()

    def cli(self, *args):
        p = subprocess.run([sys.executable, str(SCRIPT), "--config", str(self.config), *args],
                           capture_output=True, timeout=30)
        self.assertEqual(p.stderr, b"")
        result = json.loads(p.stdout)
        self.assertEqual(result["exit_code"], p.returncode)
        return p.returncode, result

    @suite("AT-02")
    def test_empty_file_has_zero_blocks_and_known_hash(self):
        leaf = self.make(b"")
        ev = self.direct_verify(leaf)
        self.assertEqual(independent_bytes(leaf), {"artifact.bin": b""})
        self.assertEqual(ev["files"][0]["sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(ev["totals"]["chunk_references"], 0)
        self.assertEqual(list(leaf.rglob("*.bin")), [])
        accepted = self.e.commit(str(leaf))
        self.assertEqual(accepted["acceptance_receipt"]["state"], "ACCEPTED_LOCAL")

    @suite("AT-02")
    def test_empty_artifact_requires_independent_permission(self):
        c = json.loads(wire(self.contract)); c["artifacts"][0]["allow_empty"] = 0
        self.assert_reason("CONTRACT_MISMATCH", self.make, b"", contract=c)
        leaf = self.make(b"")
        self.assert_reason("CONTRACT_MISMATCH", self.direct_verify, leaf, c)
        self.assertEqual(self.db("SELECT COUNT(*) FROM acceptances")[0][0], 0)

    @suite("AT-02")
    def test_empty_dataset_allow_and_forbid(self):
        empty = json.loads(wire(self.contract)); empty["artifacts"] = []
        leaf = self.make(contract=empty)
        ev = self.direct_verify(leaf, empty)
        self.assertEqual(ev["files"], [])
        self.assertEqual(independent_bytes(leaf), {})
        self.assert_reason("CONTRACT_MISMATCH", self.direct_verify, leaf, self.contract)

    @suite("AT-02")
    def test_zero_byte_block_reference_is_invalid(self):
        self.assert_reason("INVALID_INTEGER", cas.validate_ref,
                           {"sha256": h(b""), "size_bytes": 0})

    @suite("AT-03")
    def test_boundary_packing_both_profiles(self):
        for layout, b in (("fixed-4m-v1", 4194304), ("fixed-16m-v1", 16777216)):
            for size in (b-1, b, b+1, 2*b):
                with self.subTest(layout=layout, length=size):
                    data = b"A" * (size-1) + b"B"
                    leaf = self.make(data, layout)
                    ev = self.direct_verify(leaf)
                    self.assertEqual(independent_bytes(leaf)["artifact.bin"], data)
                    self.assertEqual(ev["totals"]["chunk_references"], (size+b-1)//b)

    @suite("AT-03")
    def test_short_reads_do_not_end_chunk(self):
        class Short(io.BytesIO):
            def read(self, n=-1): return super().read(min(n, 7919))
        data = b"X"*4194304 + b"tail"
        blocks = list(cas.CASChunkManager.chunks(Short(data)))
        self.assertEqual([len(x) for x in blocks], [4194304, 4])
        self.assertEqual(b"".join(blocks), data)

    @suite("AT-03")
    def test_repeated_blocks_deduplicate_storage_not_occurrences(self):
        data = b"A" * (4194304 * 2)
        leaf = self.make(data); ev = self.direct_verify(leaf)
        self.assertEqual(ev["totals"]["unique_blocks"], 1)
        self.assertEqual(ev["totals"]["chunk_references"], 2)
        self.assertEqual(independent_bytes(leaf)["artifact.bin"], data)

    @suite("AT-04")
    def test_strict_json_rejects_ambiguous_encodings(self):
        variants = [b'{"a":1,"a":2}\n', b'{"a":true}\n', b'{"a":1e0}\n',
                    b'{"a":1}\r\n', b'{"a":1}', b'{"a":"\\u0061"}\n', b'{"a":NaN}\n',
                    b'{"a":-1}\n', b'{"a":1}\n\n', b'\xef\xbb\xbf{}\n']
        for data in variants:
            with self.subTest(data=data), self.assertRaises(cas.CASError): cas.decode(data)
        self.assertEqual(cas.decode(b'{"a":1,"b":null}\n'), {"a": 1, "b": None})

    @suite("AT-04")
    def test_depth_is_rejected_before_unbounded_parser(self):
        self.assert_reason("JSON_DEPTH_LIMIT", cas.decode, b"["*10000 + b"0" + b"]"*10000 + b"\n")

    @suite("AT-06")
    def test_trailing_byte_rejected_not_valid_prefix(self):
        leaf = self.make(b"prefix")
        block = next((leaf / "blocks").rglob("*.bin"))
        block.write_bytes(b"prefix!")
        self.assert_reason("LENGTH_MISMATCH", self.direct_verify, leaf)
        with self.assertRaises(AssertionError): independent_bytes(leaf)

    @suite("AT-06")
    def test_early_eof_rejected(self):
        leaf = self.make(b"whole")
        next((leaf / "blocks").rglob("*.bin")).write_bytes(b"wh")
        self.assert_reason("LENGTH_MISMATCH", self.direct_verify, leaf)

    @suite("AT-06")
    def test_same_length_bit_tamper_rejected(self):
        leaf = self.make(b"whole")
        next((leaf / "blocks").rglob("*.bin")).write_bytes(b"whale")
        self.assert_reason("DIGEST_MISMATCH", self.direct_verify, leaf)

    @suite("AT-06")
    def test_correct_leaves_wrong_whole_digest_rejected(self):
        leaf = self.make(b"correct leaf")
        leaf = rewrite(leaf, change_map=lambda fm: fm.update(content_sha256="0"*64))
        self.assert_reason("DIGEST_MISMATCH", self.direct_verify, leaf)

    @suite("AT-06")
    def test_inconsistent_reference_size_rejected(self):
        leaf = self.make(b"A"*(4194304*2))
        leaf = rewrite(leaf, change_page=lambda p: p["chunks"][1].update(size_bytes=1))
        self.assert_reason("CHUNK_PACKING_MISMATCH", self.direct_verify, leaf)

    @suite("AT-07")
    def test_changed_order_with_old_whole_digest_rejected(self):
        data = b"A"*4194304 + b"B"*4194304 + b"tail"
        leaf = self.make(data)
        def swap(page): page["chunks"][0], page["chunks"][1] = page["chunks"][1], page["chunks"][0]
        changed = rewrite(leaf, change_page=swap)
        self.assert_reason("DIGEST_MISMATCH", self.direct_verify, changed)

    @suite("AT-07")
    def test_fully_rehashed_alternate_cannot_replace_approved_root(self):
        good = self.make(b"approved")
        other = self.make(b"unapproved")
        with self.e.reg.transaction() as con:
            con.execute("UPDATE tasks SET selection='EXACT_ROOT'")
        cas.approve_candidate(self.config, good.name)
        self.assertEqual(self.e.verify(str(good))["integrity"], "MATCH")
        self.assert_reason("APPROVAL_REQUIRED", self.e.verify, str(other))
        (other / "approval.json").write_text(json.dumps({"root": other.name}))
        self.assert_reason("APPROVAL_REQUIRED", self.e.commit, str(other))
        self.assertEqual(self.db("SELECT COUNT(*) FROM acceptances")[0][0], 0)

    @suite("AT-07")
    def test_original_root_rejects_modified_manifest(self):
        leaf = self.make(b"data")
        root = json.loads((leaf/"manifest.json").read_bytes()); root["producer_agent"] = "attacker"
        (leaf/"manifest.json").write_bytes(wire(root))
        self.assert_reason("ROOT_MISMATCH", self.direct_verify, leaf)

    @suite("AT-08")
    def test_symlink_block_never_followed(self):
        leaf = self.make(b"secret")
        block = next((leaf/"blocks").rglob("*.bin"))
        sentinel = self.base/"sentinel"; sentinel.write_bytes(b"secret")
        block.unlink(); block.symlink_to(sentinel)
        with self.assertRaises((OSError, cas.CASError)): self.direct_verify(leaf)
        self.assertEqual(sentinel.read_bytes(), b"secret")

    @suite("AT-08")
    def test_logical_case_and_ancestor_collisions(self):
        for names in (["A", "a"], ["a", "a/b"], ["A/b", "a"]):
            with self.subTest(names=names), self.assertRaises(cas.CASError): cas.check_paths(sorted(names))
        self.assert_reason("INVALID_PATH", cas.logical_path, "../escape")

    @suite("AT-09")
    def test_missing_block_never_admitted_even_with_marker(self):
        leaf = self.make(b"A"*4194304 + b"B")
        next((leaf/"blocks").rglob("*.bin")).unlink()
        exc = self.assert_reason("PENDING_CONTENT", self.e.commit, str(leaf))
        self.assertEqual(exc.code, 3)
        self.assertEqual(self.db("SELECT COUNT(*) FROM acceptances")[0][0], 0)
        self.assertEqual(self.db("SELECT COUNT(*) FROM receipt_outbox")[0][0], 0)

    @suite("AT-09")
    def test_verify_does_not_mutate_source_or_database(self):
        leaf = self.make(b"fresh observation")
        before_files = {str(p.relative_to(leaf)):h(p.read_bytes()) for p in leaf.rglob('*') if p.is_file()}
        before_db = h((self.private/'state.sqlite3').read_bytes())
        self.e.verify(str(leaf))
        after_files = {str(p.relative_to(leaf)):h(p.read_bytes()) for p in leaf.rglob('*') if p.is_file()}
        self.assertEqual(before_files, after_files)
        self.assertEqual(before_db, h((self.private/'state.sqlite3').read_bytes()))
        self.assertEqual(self.db("SELECT COUNT(*) FROM acceptances")[0][0], 0)

    @suite("AT-15")
    def test_native_no_clobber_file_and_directory_probe(self):
        result = cas.AtomicPublisher.probe(self.base)
        self.assertTrue(result["file_and_directory_no_replace"])
        self.assertEqual(result["platform"], sys.platform)

    @suite("AT-15")
    def test_native_occupied_destination_preserves_both_files(self):
        a,b = self.base/'a',self.base/'b'; a.write_bytes(b'new'); b.write_bytes(b'old')
        with self.assertRaises(FileExistsError): cas.AtomicPublisher.rename(a,b)
        self.assertEqual(a.read_bytes(),b'new'); self.assertEqual(b.read_bytes(),b'old')

    @suite("AT-15")
    def test_same_operation_put_is_identical_replay(self):
        o=str(uuid.uuid4()); first=self.put(b'original',o)
        (self.base/'source.bin').write_bytes(b'changed source')
        second=self.e.put(str(self.base/'source.bin'),operation_id=o)
        self.assertEqual(first['root_hash'],second['root_hash'])
        self.assertEqual(independent_bytes(Path(first['submission_dir']))['artifact.bin'],b'original')
        self.assertTrue(second['replayed'])

    @suite("AT-15")
    def test_occupied_explicit_output_even_matching_bytes_is_refused(self):
        put=self.put(b'matching'); target=self.outputs/'target'; target.write_bytes(b'matching')
        o=str(uuid.uuid4())
        self.assert_reason('OUTPUT_EXISTS',self.e.get,put['root_hash'],output=str(target),operation_id=o)
        self.assert_reason('OUTPUT_EXISTS',self.e.get,put['root_hash'],output=str(target),operation_id=o)
        self.assertEqual(target.read_bytes(),b'matching')

    @suite("AT-15")
    def test_unsupported_native_symbol_fails_closed(self):
        a,b=self.base/'a',self.base/'b'; a.write_bytes(b'a')
        with mock.patch.object(cas.ctypes,'CDLL',return_value=object()):
            self.assert_reason('ATOMIC_PUBLISH_UNSUPPORTED',cas.AtomicPublisher.rename,a,b)
        self.assertEqual(a.read_bytes(),b'a'); self.assertFalse(b.exists())

    @suite("AT-18")
    def test_one_root_per_task_and_epoch_never_reopens_it(self):
        a=self.make(b'A'); b=self.make(b'B')
        one=self.e.commit(str(a))
        with self.e.reg.transaction() as con: con.execute('UPDATE store_info SET authority_epoch=2')
        self.assert_reason('TASK_ALREADY_ACCEPTED',self.e.commit,str(b))
        self.assertEqual(self.db('SELECT root FROM acceptances'),[(a.name,)])
        self.assertEqual(one['decision_sequence'],1)

    @suite("AT-18")
    def test_durable_request_order_survives_registry_reopen(self):
        a=self.put(b'A'); b=self.put(b'B'); row=self.e.reg.task()
        roots=[b,a]; orders=[]
        for candidate in roots:
            o=str(uuid.uuid4()); r=candidate['root_hash']
            self.e.reg.bind_operation(o,'commit',{'root':r,'k':row['k']})
            q=self.e.broker.request_admission(o,row,r,candidate['generation_id']); orders.append(q)
        self.assertLess(orders[0],orders[1])
        reopened=cas.DriveEngine(self.config); reopened.broker.advance_admission_queue()
        self.assertEqual(self.db('SELECT root FROM acceptances'),[(b['root_hash'],)])
        self.assertEqual(self.db('SELECT state FROM requests ORDER BY q'),[('DECIDED',),('REJECTED',)])

    @suite("AT-18")
    def test_unknown_earlier_request_blocks_later(self):
        a=self.put(b'A'); b=self.put(b'B'); row=self.e.reg.task()
        for item in (a,b):
            o=str(uuid.uuid4()); self.e.reg.bind_operation(o,'commit',{'root':item['root_hash'],'k':row['k']})
            self.e.broker.request_admission(o,row,item['root_hash'],item['generation_id'])
        with self.e.reg.transaction() as con: con.execute("UPDATE requests SET state='UNKNOWN' WHERE q=1")
        self.e.broker.advance_admission_queue()
        self.assertEqual(self.db('SELECT COUNT(*) FROM acceptances')[0][0],0)

    @suite("AT-18")
    def test_real_two_process_admission_race(self):
        a=self.make(b'A'); b=self.make(b'B')
        procs=[subprocess.Popen([sys.executable,str(SCRIPT),'--config',str(self.config),'commit',str(x)],
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE) for x in (a,b)]
        returns=[]
        for proc in procs:
            out,err=proc.communicate(timeout=30); self.assertEqual(err,b'')
            value=json.loads(out); self.assertEqual(value['exit_code'],proc.returncode); returns.append(proc.returncode)
        self.assertEqual(sorted(returns),[0,5])
        self.assertEqual(self.db('SELECT COUNT(*),COUNT(DISTINCT root) FROM acceptances'),[(1,1)])

    @suite("AT-19")
    def test_exact_receipt_replay_after_source_deletion(self):
        leaf=self.make(b'accepted')
        o=str(uuid.uuid4()); a=self.e.commit(str(leaf),operation_id=o)
        original=self.db('SELECT receipt FROM acceptances')[0][0]
        shutil.rmtree(leaf)
        b=cas.DriveEngine(self.config).commit(str(leaf),operation_id=o)
        self.assertEqual(a['acceptance_receipt'],b['acceptance_receipt'])
        self.assertEqual(original,self.db('SELECT receipt FROM acceptances')[0][0])
        self.assertEqual(h(original),a['acceptance_receipt_sha256'])

    @suite("AT-19")
    def test_same_operation_rejects_altered_intent(self):
        a=self.make(b'A'); b=self.make(b'B'); o=str(uuid.uuid4())
        self.e.commit(str(a),operation_id=o)
        self.assert_reason('INTENT_CONFLICT',self.e.commit,str(b),operation_id=o)

    @suite("AT-22")
    def test_transport_tamper_does_not_change_private_consumption(self):
        put=self.put(b'original private bytes')
        self.e.commit(put['submission_dir'])
        leaf=Path(put['submission_dir']); block=next((leaf/'blocks').rglob('*.bin'))
        block.write_bytes(b'x'*len(b'original private bytes'))
        self.assert_reason('DIGEST_MISMATCH',self.e.verify,str(leaf))
        got=self.e.get(put['root_hash'])
        self.assertEqual(Path(got['output_path']).read_bytes(),b'original private bytes')
        self.assertEqual(self.db('SELECT COUNT(*) FROM acceptances')[0][0],1)

    @suite("AT-22")
    def test_private_corruption_blocks_get_and_admission(self):
        put=self.put(b'original')
        row=self.db('SELECT path FROM generations WHERE g=?',(put['generation_id'],))[0][0]
        (Path(row)/'files/artifact.bin').write_bytes(b'tampered')
        self.assert_reason('DIGEST_MISMATCH',self.e.get,put['root_hash'])
        self.assert_reason('DIGEST_MISMATCH',self.e.commit,put['submission_dir'])
        self.assertEqual(self.db('SELECT COUNT(*) FROM acceptances')[0][0],0)

    @suite("AT-22")
    def test_destination_readback_is_required(self):
        leaf=self.make(b'good')
        real=cas.check_file
        def corrupt_before_readback(path,expected,size):
            if '/files/' in str(path): Path(path).write_bytes(b'evil')
            return real(path,expected,size)
        with mock.patch.object(cas,'check_file',side_effect=corrupt_before_readback):
            self.assert_reason('DIGEST_MISMATCH',self.direct_verify,leaf)

    @suite("AT-22")
    def test_get_replay_checks_current_output(self):
        put=self.put(b'good'); o=str(uuid.uuid4()); got=self.e.get(put['root_hash'],operation_id=o)
        Path(got['output_path']).write_bytes(b'evil')
        self.assert_reason('DIGEST_MISMATCH',self.e.get,put['root_hash'],operation_id=o)

    @suite("AT-24")
    def test_export_is_pinned_until_explicit_release(self):
        put=self.put(b'retained'); got=self.e.get(put['root_hash'])
        self.assert_reason('HOLD_RESOURCE',self.e.prune,max_size_gb='0')
        self.assertTrue(Path(got['output_path']).exists())
        cas.release_export(self.config,got['operation_id'],reason='Fixture reader ended')
        self.assert_reason('HOLD_RESOURCE',self.e.prune,max_size_gb='0')
        self.assertFalse(Path(got['output_path']).exists())
        # Original prepared snapshot is still protected even after export release.
        self.assertTrue(self.db("SELECT 1 FROM pins WHERE kind='PREPARATION'"))

    @suite("AT-25")
    def test_dry_run_no_deletion_and_decimal_units(self):
        put=self.put(b'data')
        before=self.db('SELECT g,state FROM generations')
        plan=self.e.prune(max_size_gb='0',dry_run=True)
        self.assertFalse(plan['target_would_be_met'])
        self.assertEqual(before,self.db('SELECT g,state FROM generations'))
        self.assertEqual(cas.parse_gb('1.001'),1001000000)
        for value in ('-1','1e3','01','1.0001','nan'):
            self.assert_reason('INVALID_SIZE',cas.parse_gb,value)
        self.assertTrue(Path(put['submission_dir']).is_dir())

    @suite("AT-28")
    def test_missing_authority_not_automatically_recreated(self):
        db=self.private/'state.sqlite3'; db.rename(self.private/'old.sqlite3')
        self.assert_reason('AUTHORITY_RECOVERY_REQUIRED',cas.DriveEngine,self.config)
        self.assertFalse(db.exists())

    @suite("AT-28")
    def test_replaced_valid_database_requires_recovery(self):
        db=self.private/'state.sqlite3'; old=db.read_bytes()
        db.rename(self.private/'old.sqlite3'); db.write_bytes(old)
        self.assert_reason('AUTHORITY_RECOVERY_REQUIRED',cas.DriveEngine,self.config)

    @suite("AT-32")
    def test_cli_all_five_verbs_and_zero_hidden_acceptance(self):
        source=self.base/'cli.bin'; source.write_bytes(b'CLI payload')
        code,p=self.cli('put',str(source)); self.assertEqual(code,0)
        r=p['result']['root_hash']; leaf=p['result']['submission_dir']
        self.assertEqual(self.db('SELECT COUNT(*) FROM acceptances')[0][0],0)
        code,v=self.cli('verify',leaf); self.assertEqual(code,0)
        self.assertEqual(self.db('SELECT COUNT(*) FROM acceptances')[0][0],0)
        code,g=self.cli('get',r,'--output',str(self.outputs/'cli-out')); self.assertEqual(code,0)
        self.assertEqual((self.outputs/'cli-out').read_bytes(),b'CLI payload')
        code,c=self.cli('commit',leaf); self.assertEqual(code,0)
        self.assertEqual(self.db('SELECT COUNT(*) FROM acceptances')[0][0],1)
        code,pr=self.cli('prune','--max-size-gb','0','--dry-run'); self.assertEqual(code,0)
        self.assertEqual(pr['result']['cloud_deletions'],0)
        self.assertEqual(c['qualification'],'NOT_GRANTED')

    @suite("AT-32")
    def test_cli_rejects_abbreviations_duplicate_flags_and_old_hash_namespace(self):
        code,r=self.cli('prune','--max-size','1'); self.assertEqual(code,2)
        code,r=self.cli('prune','--max-size-gb','1','--max-size-gb','2'); self.assertEqual(code,2)
        put=self.put(b'content')
        self.assert_reason('FILE_MAP_UNAVAILABLE',self.e.get,put['content_sha256'])

    @suite("AT-32")
    def test_offline_get_uses_private_bytes_but_verify_holds(self):
        put=self.put(b'offline'); offline=cas.DriveEngine(self.config,offline=True)
        self.assert_reason('OFFLINE_HOLD',offline.verify,put['submission_dir'])
        got=offline.get(put['root_hash']); self.assertEqual(Path(got['output_path']).read_bytes(),b'offline')

    @suite("AT-15")
    def test_negative_control_oracle_catches_overwrite(self):
        a,b=self.base/'bad-a',self.base/'bad-b'; a.write_bytes(b'new'); b.write_bytes(b'old')
        os.replace(a,b)  # deliberate defective primitive, only this owned fixture
        with self.assertRaises(AssertionError): self.assertEqual(b.read_bytes(),b'old')

    @suite("AT-07")
    def test_negative_control_oracle_catches_sorted_or_dropped_references(self):
        expected=[b'B',b'A',b'B']
        defective=b''.join(sorted(set(expected)))
        with self.assertRaises(AssertionError): self.assertEqual(defective,b''.join(expected))

    @suite("AT-14")
    def test_isolated_child_sigbus_does_not_kill_parent(self):
        real = cas.subprocess.Popen
        def fault_child(argv, **kwargs):
            return real([sys.executable, '-c',
                         'import os,signal,resource; resource.setrlimit(resource.RLIMIT_CORE,(0,0)); os.kill(os.getpid(),signal.SIGBUS)'], **kwargs)
        with mock.patch.object(cas.subprocess, 'Popen', side_effect=fault_child):
            self.assert_reason('WORKER_SIGNAL', self.e.supervisor.run, 'bind', {'path': str(self.exchange)})
        self.assertEqual(self.db('SELECT COUNT(*) FROM acceptances')[0][0],0)

    @suite("AT-14")
    def test_worker_timeout_releases_no_unverified_output(self):
        real = cas.subprocess.Popen
        def sleeping_child(argv, **kwargs):
            return real([sys.executable, '-c', 'import time; time.sleep(30)'], **kwargs)
        started=time.monotonic()
        with mock.patch.object(cas.subprocess,'Popen',side_effect=sleeping_child):
            self.assert_reason('WAIT_BUDGET_EXHAUSTED',self.e.supervisor.run,'bind',
                               {'path':str(self.exchange)},timeout=0.2)
        self.assertLess(time.monotonic()-started,3)
        self.assertEqual(self.db('SELECT COUNT(*) FROM acceptances')[0][0],0)
        # A reaped child permits the next job. A live inherited slot would not.
        result=self.e.supervisor.run('bind',{'path':str(self.exchange)})
        self.assertTrue(result['identity'])

    @suite("AT-14")
    def test_slot_cap_is_shared_between_controllers(self):
        import fcntl
        descriptors=[]
        try:
            for i in range(2):
                fd=os.open(self.private/'slots'/str(i),os.O_RDONLY)
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); descriptors.append(fd)
            self.assert_reason('WORKER_CIRCUIT_OPEN',cas.WorkerSupervisor(self.private).run,
                               'bind',{'path':str(self.exchange)})
        finally:
            for fd in descriptors: os.close(fd)

    @suite("AT-19")
    def test_readonly_status_does_not_rehydrate_or_mutate(self):
        put=self.put(b'old observation'); before=h((self.private/'state.sqlite3').read_bytes())
        code,out=self.cli('--operation-id',put['operation_id'],'--status-only',
                          'put',str(self.base/'source.bin'))
        self.assertEqual(code,0); self.assertEqual(out['observation'],'STORED_STATUS')
        self.assertEqual(before,h((self.private/'state.sqlite3').read_bytes()))

    @suite("AT-18")
    def test_blocked_first_request_has_recorded_disposition(self):
        a=self.put(b'A'); b=self.put(b'B'); row=self.e.reg.task()
        for item in (a,b):
            o=str(uuid.uuid4()); self.e.reg.bind_operation(o,'commit',{'root':item['root_hash'],'k':row['k']})
            self.e.broker.request_admission(o,row,item['root_hash'],item['generation_id'])
        with self.e.reg.transaction() as con: con.execute('UPDATE requests SET fence=0 WHERE q=1')
        self.e.broker.advance_admission_queue()
        self.assertEqual(self.db('SELECT root FROM acceptances'),[(b['root_hash'],)])
        self.assertEqual(self.db('SELECT state,reason FROM requests WHERE q=1'),[('BLOCKED','STALE_FENCE')])

    @suite("AT-22")
    def test_get_explicitly_approved_external_root_without_admission(self):
        leaf=self.make(b'external approved bytes'); cas.approve_candidate(self.config,leaf.name)
        got=self.e.get(leaf.name)
        self.assertEqual(Path(got['output_path']).read_bytes(),b'external approved bytes')
        self.assertEqual(self.db('SELECT COUNT(*) FROM acceptances')[0][0],0)


    @suite("AT-02")
    def test_empty_dataset_can_be_admitted_under_its_own_contract(self):
        intake=self.exchange/'empty-task'; intake.mkdir()
        contract=cas.enroll_task(self.config,campaign='fixture',task_id='empty',artifacts=[],
                                 intake=str(intake),selection='ANY_VALID_ENROLLED')
        stage=self.base/'empty-source'
        built=cas.CASChunkManager.build({},contract,stage,'fixture',self.e.c['installation_id'],str(uuid.uuid4()))
        leaf=intake/'chunks'/built['root_hash']; stage.rename(leaf)
        result=self.e.commit(str(leaf))
        self.assertEqual(result['acceptance_receipt']['task_id'],'empty')
        self.assertEqual(self.db('SELECT COUNT(*) FROM acceptances')[0][0],1)

    @suite("AT-18")
    def test_cross_task_cached_root_cannot_satisfy_other_contract(self):
        put=self.put(b'task A payload')
        intake=self.exchange/'task-b'; intake.mkdir()
        cas.enroll_task(self.config,campaign='fixture',task_id='B',
                        artifacts=[cas.artifact_slot('artifact.bin',allow_empty=True)],
                        intake=str(intake),selection='ANY_VALID_ENROLLED')
        forged=intake/'chunks'/put['root_hash']
        shutil.copytree(put['submission_dir'],forged)
        self.assert_reason('CONTRACT_MISMATCH',self.e.commit,str(forged))
        self.assertEqual(self.db('SELECT COUNT(*) FROM acceptances')[0][0],0)

    @suite("AT-18")
    def test_broker_rejects_root_different_from_operation_intent(self):
        a=self.put(b'A'); b=self.put(b'B'); row=self.e.reg.task(); o=str(uuid.uuid4())
        self.e.reg.bind_operation(o,'commit',{'root':a['root_hash'],'k':row['k']})
        self.assert_reason('INTENT_CONFLICT',self.e.broker.request_admission,
                           o,row,b['root_hash'],b['generation_id'])
        self.assertEqual(self.db('SELECT COUNT(*) FROM requests')[0][0],0)


class RecordingResult(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs); self.records=[]; self.started={}
    def startTest(self,test):
        self.started[test.id()]=time.monotonic(); super().startTest(test)
    def _record(self,test,status,detail=''):
        method=getattr(test,test._testMethodName)
        self.records.append({'test':test.id(),'suite':getattr(method,'suite_id','UNMAPPED'),
                             'status':status,'seconds':round(time.monotonic()-self.started[test.id()],6),
                             'detail':detail})
        self.stream.write(' [%.3fs]' % self.records[-1]['seconds']); self.stream.flush()
    def addSuccess(self,test): self._record(test,'PASS'); super().addSuccess(test)
    def addFailure(self,test,err): self._record(test,'FAIL',self._exc_info_to_string(err,test)); super().addFailure(test,err)
    def addError(self,test,err): self._record(test,'ERROR',self._exc_info_to_string(err,test)); super().addError(test,err)
    def addSkip(self,test,reason): self._record(test,'SKIP',reason); super().addSkip(test,reason)


def run():
    parser=argparse.ArgumentParser()
    parser.add_argument('--suite',action='append',help='AT-02 etc; may repeat')
    parser.add_argument('--report',default='test_results.json')
    parser.add_argument('--batches',type=int,default=1)
    parser.add_argument('--batch-index',type=int,default=0)
    args=parser.parse_args()
    tests=unittest.defaultTestLoader.loadTestsFromTestCase(Fixture)
    if args.suite:
        tests=unittest.TestSuite(t for t in tests if getattr(getattr(t,t._testMethodName),'suite_id','') in args.suite)
    if not (1 <= args.batches <= 128 and 0 <= args.batch_index < args.batches): parser.error('Invalid batch selection')
    tests=unittest.TestSuite(t for i,t in enumerate(tests) if i % args.batches == args.batch_index)
    result=unittest.TextTestRunner(verbosity=2,resultclass=RecordingResult).run(tests)
    report={'protocol':'gdoe-test-results/1','engine_version':cas.VERSION,
            'engine_sha256':h(SCRIPT.read_bytes()),'test_sha256':h(Path(__file__).read_bytes()),
            'environment':{'platform':platform.platform(),'machine':platform.machine(),
                           'python':sys.version,'sqlite':sqlite3.sqlite_version},
            'batch_index':args.batch_index,'batches':args.batches,
            'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
            'skips':len(result.skipped),'cases':result.records,'suite_scope':SUITE_NOTES,
            'qualification':'NOT_GRANTED',
            'not_executed':['live Apple Silicon/FileProvider','actual cellular disconnect',
                            'independent-device replication','power-loss durability',
                            'complete 32-suite qualification and all negative controls']}
    Path(args.report).write_text(json.dumps(report,indent=2)+'\n')
    return 0 if result.wasSuccessful() and result.testsRun else 1


if __name__=='__main__': raise SystemExit(run())
