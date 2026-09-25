#!/usr/bin/env python3
"""Test-only native54 worker adapter: modeled dataless state, real file reads.
Never imported by production dispatch or enabled by production configuration.
"""
from pathlib import Path
import contextlib
import errno
import hashlib
import json
import os
import signal
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import drive_cas_native as native
original_open=native.open_regular; original_action=native._worker_action
active={}

@contextlib.contextmanager
def read_with_fault(path,*args,**kwargs):
    with original_open(path,*args,**kwargs) as stream:
        if str(Path(path))!=active.get('target'):
            yield stream; return
        print('DATALESS_OBSERVED (MOCK, not OS metadata)',file=sys.stderr,flush=True)
        class Reader:
            first=True
            def __getattr__(self,name): return getattr(stream,name)
            def read(self,n=-1):
                data=stream.read(n)
                if self.first and data:
                    self.first=False
                    with open(active['event'],'ab',buffering=0) as event:
                        event.write((json.dumps({'phase':'AFTER_REAL_READ','size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'mode':active['mode']})+'\n').encode()); os.fsync(event.fileno())
                    if active['mode']=='SIGBUS': os.kill(os.getpid(),signal.SIGBUS)
                    if active['mode']=='EIO': raise OSError(errno.EIO,'INJECTED after actual file read')
                return data
        yield Reader()

def action(kind,args,work):
    spec=args.pop('_mock_fault',None)
    if not spec: return original_action(kind,args,work)
    active.update(spec); native.open_regular=read_with_fault
    try: return original_action(kind,args,work)
    finally: native.open_regular=original_open
native._worker_action=action
if __name__=='__main__':
    if len(sys.argv)!=3 or sys.argv[1]!='--_worker': raise SystemExit(2)
    raise SystemExit(native._worker_main(sys.argv[2]))
