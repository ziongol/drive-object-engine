#!/usr/bin/env python3
"""Verify with explicitly enrolled public trust; never accepts a task."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import drive_cas as cas
from receipt_engine import verify_signed_receipt

def read(path,limit=65536):
    path=Path(cas.normalized_absolute(path))
    with cas.SafeTree(path.parent) as t: return t.read(path.name,limit)

def main():
    p=cas._Parser(allow_abbrev=False); p.add_argument('--trust',required=True); p.add_argument('--receipt',required=True)
    p.add_argument('--expected-sha256'); p.add_argument('--minimum-decision-sequence',type=int,default=0)
    try:
        a=p.parse_args(); result=verify_signed_receipt(read(a.receipt),cas.json_read(read(a.trust)),a.expected_sha256,a.minimum_decision_sequence)
        sys.stdout.buffer.write(cas.json_bytes(result)); return 0
    except Exception as e:
        sys.stdout.buffer.write(cas.json_bytes({'reason':getattr(e,'reason',type(e).__name__),'message':str(e)[:300]})); return getattr(e,'code',4)
if __name__=='__main__': raise SystemExit(main())
