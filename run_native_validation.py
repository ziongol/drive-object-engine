#!/usr/bin/env python3
"""Run the exact original 54-test source under its original module name."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
BASE=Path(__file__).resolve().parent
if __name__=='__main__':
    out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=True)
    start=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='gdoe-native54-validation-') as tmp:
        root=Path(tmp); shutil.copyfile(BASE/'drive_cas_native.py',root/'drive_cas.py')
        shutil.copyfile(BASE/'history/native_turn05/test_drive_cas.py',root/'test_drive_cas.py')
        with (out/'unittest.log').open('wb') as log:
            run=subprocess.run([sys.executable,str(root/'test_drive_cas.py'),'--report',str(out/'original_results.json')],cwd=root,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,timeout=900)
    report=json.loads((out/'original_results.json').read_text()); report['elapsed_seconds']=time.monotonic()-start
    report['source_unchanged']=(report['engine_sha256']==hashlib.sha256((BASE/'drive_cas_native.py').read_bytes()).hexdigest() and
        report['test_sha256']==hashlib.sha256((BASE/'history/native_turn05/test_drive_cas.py').read_bytes()).hexdigest())
    report['success']=run.returncode==0 and report['source_unchanged'] and report['tests_run']==54 and report['failures']==0 and report['errors']==0 and report['skips']==0
    (out/'results.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:report[k] for k in ('tests_run','failures','errors','skips','success')}))
    raise SystemExit(0 if report['success'] else 1)
