#!/usr/bin/env python3
"""Structured real executions; no automatic production qualification."""
from pathlib import Path
import datetime
import hashlib
import importlib
import json
import platform
import sqlite3
import sys
import time
import unittest
from run_validation import RecordedResult

BASE=Path(__file__).resolve().parent

def sources():
    paths=list(BASE.glob('*.py'))+list((BASE/'tools').glob('*.py'))+[BASE/'lab']
    return {p.relative_to(BASE).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}

if __name__=='__main__':
    out=Path(sys.argv[1]); module=sys.argv[2]; out.mkdir(parents=True,exist_ok=False)
    before=sources(); start=time.monotonic(); at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    suite=unittest.defaultTestLoader.loadTestsFromModule(importlib.import_module(module))
    with (out/'unittest.log').open('w') as log:
        result=unittest.TextTestRunner(stream=log,verbosity=2,resultclass=RecordedResult).run(suite)
    after=sources()
    record=dict(module=module,started_utc=at,elapsed_seconds=time.monotonic()-start,
        environment=dict(platform=platform.platform(),python=platform.python_version(),sqlite=sqlite3.sqlite_version),
        tests_run=result.testsRun,failures=len(result.failures),errors=len(result.errors),skips=len(result.skipped),
        records=result.records,source_hashes_before=before,source_hashes_after=after,source_unchanged=before==after,
        success=result.wasSuccessful() and result.testsRun>0 and before==after,production_qualification='NOT_GRANTED',
        fault_scope='Modeled FileProvider with real reads; injected signal and private-mmap fault are separately labeled.')
    (out/'results.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:record[k] for k in ('module','tests_run','failures','errors','skips','success')}))
    raise SystemExit(0 if record['success'] else 1)
