#!/usr/bin/env python3
"""Run the selected suite and retain machine-readable evidence. Not auto-qualification."""
from __future__ import annotations
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
import time
import unittest
import drive_cas
import test_drive_cas

class RecordedResult(unittest.TextTestResult):
    def __init__(self,*a,**kw):
        super().__init__(*a,**kw); self.records=[]; self.started={}
    def startTest(self,test):
        self.started[test.id()]=time.perf_counter(); super().startTest(test)
    def record(self,test,status,detail=None):
        self.records.append(dict(test=test.id(),status=status,elapsed_seconds=round(time.perf_counter()-self.started[test.id()],6),detail=detail))
    def addSuccess(self,test): self.record(test,'PASS'); super().addSuccess(test)
    def addFailure(self,test,err): self.record(test,'FAIL',self._exc_info_to_string(err,test)); super().addFailure(test,err)
    def addError(self,test,err): self.record(test,'ERROR',self._exc_info_to_string(err,test)); super().addError(test,err)
    def addSkip(self,test,reason): self.record(test,'SKIP',reason); super().addSkip(test,reason)

if __name__=='__main__':
    out=Path(sys.argv[1] if len(sys.argv)>1 else 'evidence/final_run')
    out.mkdir(parents=True,exist_ok=False)
    files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (Path(drive_cas.__file__),Path(test_drive_cas.__file__))}
    started=dt.datetime.now(dt.timezone.utc).isoformat(); clock=time.perf_counter()
    suite=unittest.defaultTestLoader.loadTestsFromModule(test_drive_cas)
    with (out/'unittest.log').open('w',encoding='utf-8') as log:
        result=unittest.TextTestRunner(stream=log,verbosity=2,resultclass=RecordedResult).run(suite)
    after={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (Path(drive_cas.__file__),Path(test_drive_cas.__file__))}
    record=dict(started_utc=started,finished_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                elapsed_seconds=time.perf_counter()-clock,environment=drive_cas.environment_record(),
                source_hashes_before=files,source_hashes_after=after,source_unchanged=files==after,
                tests_run=result.testsRun,failures=len(result.failures),errors=len(result.errors),skips=len(result.skipped),
                success=result.wasSuccessful() and files==after,records=result.records,
                scope='Selected tests on the recorded local host; no Apple/FileProvider inference',
                production_qualification='NOT_GRANTED')
    (out/'results.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:record[k] for k in ('tests_run','failures','errors','skips','success','production_qualification')}))
    raise SystemExit(0 if record['success'] else 1)
