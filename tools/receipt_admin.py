#!/usr/bin/env python3
"""Explicit local receipt administration. No downloaded code, tokens or cloud UI."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import drive_cas as cas
from release_profiles import profile
from receipt_crypto import CryptoError

def main(argv=None):
    p=cas._Parser(allow_abbrev=False)
    p.add_argument('--config',required=True)
    sub=p.add_subparsers(dest='command',required=True,parser_class=cas._Parser)
    sub.add_parser('install',allow_abbrev=False)
    sub.add_parser('initialize-signing',allow_abbrev=False)
    sub.add_parser('rotate-key',allow_abbrev=False)
    rev=sub.add_parser('revoke-key',allow_abbrev=False); rev.add_argument('key_id'); rev.add_argument('--reason',required=True)
    sub.add_parser('public-trust',allow_abbrev=False)
    sub.add_parser('environment',allow_abbrev=False)
    app=sub.add_parser('approve-qualification',allow_abbrev=False); app.add_argument('record')
    act=sub.add_parser('activate',allow_abbrev=False); act.add_argument('receipt_sha256'); act.add_argument('--qualification-id',required=True); act.add_argument('--operation-id',required=True)
    retire=sub.add_parser('retire',allow_abbrev=False); retire.add_argument('generation_id'); retire.add_argument('--reason',required=True)
    resume=sub.add_parser('reopen-window',allow_abbrev=False); resume.add_argument('job_id'); resume.add_argument('--reason',required=True)
    try:
        a=p.parse_args(argv)
        label,core,receipts=profile(a.config)
        if a.command=='install': result=receipts.install_extension(a.config)
        elif a.command in ('initialize-signing','rotate-key'): result=receipts.initialize_signing(a.config,a.command=='rotate-key')
        elif a.command=='revoke-key': receipts.revoke_key(a.config,a.key_id,a.reason); result={'state':'REVOKED'}
        elif a.command=='public-trust': result=receipts.public_trust(a.config)
        elif a.command=='environment': result=receipts.release_environment(core.load_config(a.config))
        elif a.command=='approve-qualification':
            with cas.SafeTree(Path(cas.normalized_absolute(a.record)).parent) as t: record=cas.json_read(t.read(Path(a.record).name,cas.MAX_FRAME))
            receipts.record_receipt_qualification(a.config,record); result={'state':'ENROLLED'}
        elif a.command=='activate': result=receipts.ReceiptService(a.config).activate_receipt(a.receipt_sha256,a.qualification_id,a.operation_id)
        elif a.command=='retire': result=(receipts.LocalCacheEvictor(a.config).retire_generation(a.generation_id,a.reason) if label=='NATIVE54' else core.DriveEngine(a.config).retire_generation(a.generation_id,a.reason))
        else: receipts.ReceiptService(a.config).reopen_drain_window(a.job_id,a.reason); result={'state':'WINDOW_REOPENED'}
        sys.stdout.buffer.write(cas.json_bytes(result)); return 0
    except SystemExit as e: return int(e.code or 0)
    except Exception as e:
        code=getattr(e,'code',7)
        sys.stdout.buffer.write(cas.json_bytes({'state':'REJECTED','reason':getattr(e,'reason',type(e).__name__),'message':str(e)[:300]})); return code
if __name__=='__main__': raise SystemExit(main())
