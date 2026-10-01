#!/usr/bin/env python3
"""Check that selected tests actually reject deliberately broken source copies.

Never modifies the delivered engine. Variants live only in owned temporary dirs.
A nonzero exit alone is NOT considered successful defect detection: an assertion
failure in the designated test is required; import errors/timeouts are failures.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile

BASE=Path(__file__).resolve().parent
flag_old="self.name, self.flag = 'renameatx_np', 0x00000004" if sys.platform=='darwin' else "self.name, self.flag = 'renameat2', 1"
flag_new="self.name, self.flag = 'renameatx_np', 0" if sys.platform=='darwin' else "self.name, self.flag = 'renameat2', 0"
MUTANTS=[
 ('SHORT_READ_IS_EOF',
  "if not b: break\n            require(len(b) <= size - len(buf)",
  "if len(b) < size - len(buf): break\n            require(len(b) <= size - len(buf)",
  'test_drive_cas.TestAT03.test_short_reads_are_not_eof'),
 ('NO_EXACT_LENGTH_CHECK',
  "if expected_size is not None: require(n == expected_size, 'LENGTH_MISMATCH')",
  "if expected_size is not None: pass  # DELIBERATE NEGATIVE CONTROL",
  'test_drive_cas.TestAT06.test_read_exact_without_hash_is_still_exact'),
 ('PERMISSIVE_CANONICAL_ENCODING',
  "require(wire_bytes(v) == b, 'NONCANONICAL_ENCODING')",
  "pass  # DELIBERATE NEGATIVE CONTROL: canonical encoding unchecked",
  'test_drive_cas.TestRecoveryAndContainment.test_raw_canonical_only_guard'),
 ('RENAME_OVERWRITES',flag_old,flag_new,
  'test_drive_cas.TestAT15.test_file_no_clobber_native'),
 ('STALE_FENCE_ACCEPTED',
  "require(t['fence']==r['fence'],'STALE_FENCE',code=6)",
  "pass  # DELIBERATE NEGATIVE CONTROL: stale fence accepted",
  'test_drive_cas.TestAT18.test_stale_fence_blocks_request'),
 ('NO_DESTINATION_READBACK',
  "require(work.file_hash(output_rel, length) == (fm['content_sha256'], length), 'DESTINATION_MISMATCH')",
  "pass  # DELIBERATE NEGATIVE CONTROL: destination not checked",
  'test_drive_cas.TestAT22.test_destination_tamper_before_readback_detected'),
 ('UNOWNED_EQUAL_OUTPUT_REUSED',
  "require(proof is not None and identity(old) == proof['staging_identity'], 'OUTPUT_EXISTS', code=5)",
  "pass  # DELIBERATE NEGATIVE CONTROL: ownership not checked",
  'test_drive_cas.TestRecoveryAndContainment.test_unrelated_equal_output_stays_unowned_on_retry'),
 ('MERKLE_EDGE_ORDER_IGNORED',
  "                    output_rel = f'files/{index:08d}.bin'",
  "                    refs.reverse()  # DELIBERATE NEGATIVE CONTROL\n                    output_rel = f'files/{index:08d}.bin'",
  'test_drive_cas.TestAT07.test_reordered_leaves_rehashed_metadata_wrong_reconstruction'),
]

if __name__=='__main__':
    output=Path(sys.argv[1] if len(sys.argv)>1 else 'evidence/negative_controls')
    output.mkdir(parents=True,exist_ok=True)
    source=(BASE/'drive_cas.py').read_text(); source_hash=hashlib.sha256(source.encode()).hexdigest()
    records=[]
    for name,old,new,test in MUTANTS:
        if source.count(old)!=1:
            raise SystemExit(f'Mutation site for {name} is not unique; update the control, do not guess.')
        variant=source.replace(old,new,1)
        with tempfile.TemporaryDirectory(prefix='drive-cas-negative-') as tmp:
            root=Path(tmp); engine=root/'drive_cas.py'; engine.write_text(variant)
            shutil.copyfile(BASE/'test_drive_cas.py',root/'test_drive_cas.py')
            py_compile.compile(str(engine),doraise=True)
            run=subprocess.run([sys.executable,'-m','unittest','-v',test],cwd=root,capture_output=True,timeout=120)
            log=run.stdout+run.stderr
            (output/(name+'.log')).write_bytes(log)
            expected_name=test.rsplit('.',1)[1]
            detected=(run.returncode==1 and ('FAIL: '+expected_name).encode() in log
                      and b'FAILED (failures=' in log and b'ERROR:' not in log)
            records.append(dict(control=name,test=test,detected=detected,returncode=run.returncode,
                                variant_sha256=hashlib.sha256(variant.encode()).hexdigest(),
                                log_sha256=hashlib.sha256(log).hexdigest()))
        print(name, 'DETECTED' if detected else 'NOT_DETECTED',flush=True)
    unchanged=hashlib.sha256((BASE/'drive_cas.py').read_bytes()).hexdigest()==source_hash
    result=dict(original_source_sha256=source_hash,original_unchanged=unchanged,controls=records,
                success=unchanged and all(x['detected'] for x in records),
                scope='Intentionally defective source copies; not a cryptographic break or production qualification')
    (output/'results.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    raise SystemExit(0 if result['success'] else 1)
