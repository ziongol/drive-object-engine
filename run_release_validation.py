#!/usr/bin/env python3
"""All release tests on the caller's machine, each group uninterrupted.

Run from an immutable copy. No tests touch an existing store or live Drive mount.
At most two test-runner processes, each with separate disposable stores.
A machine losing dependencies records failure, not an invented pass.
"""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import datetime
import json
import platform
import subprocess
import sqlite3
import sys
import time
from run_extension_validation import sources
BASE=Path(__file__).resolve().parent

def execute(item):
    name,argv,out=item; t=time.monotonic()
    with (out/(name+'.launcher.log')).open('wb') as log:
        try:
            run=subprocess.run(argv,cwd=BASE,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,timeout=1800)
            code=run.returncode; error=None
        except subprocess.TimeoutExpired: code=124;error='RUNNER_TIMEOUT'
    resultpath=out/name/'results.json'
    report=json.loads(resultpath.read_text()) if resultpath.exists() else {'success':False,'error':'RESULT_MISSING'}
    return dict(group=name,returncode=code,error=error,elapsed_seconds=time.monotonic()-t,result=report)

if __name__=='__main__':
    out=Path(sys.argv[1] if len(sys.argv)>1 else 'evidence/release-validation').resolve();out.mkdir(parents=True,exist_ok=False)
    before=sources(); begin=time.monotonic(); at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    jobs=[('chat66',[sys.executable,str(BASE/'run_validation.py'),str(out/'chat66')],out),
          ('native54',[sys.executable,str(BASE/'run_native_validation.py'),str(out/'native54')],out),
          ('extension37',[sys.executable,str(BASE/'run_extension_validation.py'),str(out/'extension37'),'test_turn06'],out),
          ('native_extension23',[sys.executable,str(BASE/'run_extension_validation.py'),str(out/'native_extension23'),'test_native_turn06'],out)]
    with ThreadPoolExecutor(max_workers=2) as pool: records=list(pool.map(execute,jobs))
    negative=execute(('negative_controls',[sys.executable,str(BASE/'run_negative_controls.py'),str(out/'negative_controls')],out))
    after=sources()
    result=dict(protocol='gdoe-release-validation/1',started_utc=at,elapsed_seconds=time.monotonic()-begin,
        environment=dict(platform=platform.platform(),python=platform.python_version(),sqlite=sqlite3.sqlite_version),
        total_tests=sum(r['result'].get('tests_run',0) for r in records),groups=records,negative_controls=negative,
        source_hashes_before=before,source_hashes_after=after,source_unchanged=before==after,
        success=before==after and all(r['returncode']==0 and r['result'].get('success') for r in records+[negative]),
        production_qualification='NOT_GRANTED',live_fileprovider='NOT_EXECUTED',live_cellular='NOT_EXECUTED',physical_multi_device='NOT_EXECUTED')
    (out/'results.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'success':result['success'],'total_tests':result['total_tests'],'source_unchanged':result['source_unchanged']}))
    raise SystemExit(0 if result['success'] else 1)
