#!/usr/bin/env python3
"""TEST-ONLY worker entry. Never referenced by production CLI/configuration.

Mock dataless classification with real binary reads, controlled EIO/short reads,
timeouts and injected SIGBUS. A separate owned mmap-truncation fixture produces
an actual backing-file SIGBUS; it never maps the user's FileProvider tree.
"""
from __future__ import annotations
import contextlib
import errno
import hashlib
import json
import mmap
import os
from pathlib import Path
import signal
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
import drive_cas as cas

def event(path,record):
    if path:
        with open(path,'ab',buffering=0) as f:
            f.write((json.dumps(record,sort_keys=True)+'\n').encode()); os.fsync(f.fileno())

def real_mapping_fault(path,event_path):
    # Fixture-only. Caller supplies a fresh file below its owned TemporaryDirectory.
    with open(path,'xb',buffering=0) as f: f.write(b'Q'*(mmap.PAGESIZE*2)); os.fsync(f.fileno())
    fd=os.open(path,os.O_RDWR)
    region=mmap.mmap(fd,mmap.PAGESIZE*2,access=mmap.ACCESS_READ)
    os.ftruncate(fd,0); os.fsync(fd)
    event(event_path,dict(fault='ACTUAL_PRIVATE_MMAP_TRUNCATION',size_after=0,page_size=mmap.PAGESIZE))
    byte=region[mmap.PAGESIZE]  # Expected OS-generated SIGBUS. No handler resumes.
    event(event_path,dict(unexpected_read_value=byte))
    return 90

def worker():
    original_dispatch=cas._worker_dispatch
    @contextlib.contextmanager
    def fault_open(tree,rel):
        spec=active['spec']; full=str(Path(tree.root)/rel)
        with original_open(tree,rel) as raw:
            if full!=spec.get('target'):
                yield raw; return
            mode=spec['mode']
            print('DATALESS_OBSERVED (INJECTED_MODEL, not OS flag)',file=sys.stderr,flush=True)
            class Reader:
                first=True
                def read(self,n=-1):
                    if mode=='SHORT_READ': return raw.read(min(n,7) if n>=0 else 7)
                    b=raw.read(n)
                    if self.first and b:
                        self.first=False
                        event(spec.get('event_path'),dict(mode=mode,phase='AFTER_REAL_READ',bytes_read=len(b),sha256=hashlib.sha256(b).hexdigest()))
                        if mode=='EIO': raise OSError(errno.EIO,'INJECTED provider read fault after real read')
                        if mode=='SIGBUS': os.kill(os.getpid(),signal.SIGBUS)
                        if mode=='STALL': time.sleep(30)
                    return b
            yield Reader()
    original_open=cas.SafeTree.open_read; active={'spec':{}}
    def dispatch(kind,args):
        spec=args.pop('_mock_fault',{})
        if not spec: return original_dispatch(kind,args)
        active['spec']=spec; cas.SafeTree.open_read=fault_open
        try: return original_dispatch(kind,args)
        finally: cas.SafeTree.open_read=original_open
    cas._worker_dispatch=dispatch
    return cas._worker_main()

if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--private-mmap-fault':
        raise SystemExit(real_mapping_fault(sys.argv[2],sys.argv[3]))
    raise SystemExit(worker())
