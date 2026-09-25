#!/usr/bin/env python3
"""Existing lab dispatcher calls main(args_after_drive). No implicit admission."""
from __future__ import annotations
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
import drive_cas as cas
from release_profiles import profile, config_argument, DEFAULT_CONFIG

def main(argv=None):
    args=list(sys.argv[1:] if argv is None else argv)
    if args and args[0]=='drive': args=args[1:]
    try:
        if args in (['--help'],['-h']):
            print('usage: ./lab drive [--config PATH] [--operation-id UUID] [--wait-ms N] [--offline] {put|get|verify|commit|status|prune|drain} ...')
            print('status is private-only; drain performs one bounded signed-receipt outbox iteration.'); return 0
        if args==['--version']:
            print('gdoe-lab-wrapper/1 0.6.0-rc1'); return 0
        allowed={'--config','--operation-id','--wait-ms','--offline','--status-only','--output','--dropzone','--max-size-gb','--dry-run','--maximum','--help','--version'}
        for token in args:
            if token=='--': break
            if token.startswith('--'): cas.require(token.split('=',1)[0] in allowed,'UNKNOWN_OPTION',code=2)
        label,core,receipts=profile(config_argument(args))
        value_options={'--config','--operation-id','--wait-ms'}; index=0
        while index<len(args):
            token=args[index]
            if token.split('=',1)[0] in value_options: index+=1 if '=' in token else 2
            elif token in ('--offline','--status-only'): index+=1
            else: break
        verb=args[index] if index<len(args) else None
        special=verb in ('status','drain') or (label=='NATIVE54' and verb=='prune')
        if not special: return core.main(args)
        parser=cas._Parser(prog='./lab drive',allow_abbrev=False)
        parser.add_argument('--config',default=str(DEFAULT_CONFIG))
        parser.add_argument('--operation-id'); parser.add_argument('--wait-ms',type=int,default=900000)
        parser.add_argument('--offline',action='store_true'); parser.add_argument('--status-only',action='store_true')
        sub=parser.add_subparsers(dest='command',required=True,parser_class=cas._Parser)
        sub.add_parser('status',allow_abbrev=False)
        d=sub.add_parser('drain',allow_abbrev=False); d.add_argument('--maximum',type=int,default=16)
        p=sub.add_parser('prune',allow_abbrev=False); p.add_argument('--max-size-gb',default='100'); p.add_argument('--dry-run',action='store_true')
        opts=[a.split('=',1)[0] for a in args if a.startswith('--')]
        cas.require(len(opts)==len(set(opts)),'DUPLICATE_OPTION',code=2)
        a=parser.parse_args(args); cas.require(1<=a.wait_ms<=900000,'INVALID_ARGUMENT',code=2)
        if a.operation_id: cas.uuid_value(a.operation_id)
        if verb in ('status','drain'): cas.require(not a.operation_id and not a.status_only,'INVALID_ARGUMENT',code=2)
        if verb=='status':
            if label=='CHAT66': result=core.DriveEngine(a.config,a.wait_ms).status()
            else:
                cfg=core.load_config(a.config); reg=core.AuthorityRegistry(cfg)
                result=dict(profile=label,mode=cfg['qualification_mode'],authority_health=reg.read('SELECT health FROM store_info')[0]['health'],
                    accepted_tasks=reg.read('SELECT COUNT(*) n FROM acceptances')[0]['n'],cache=receipts.LocalCacheEvictor(a.config).plan())
            try: result['receipts']=receipts.ReceiptService(a.config,a.wait_ms).status()
            except cas.CASError as e:
                if e.reason=='RECEIPTS_NOT_INITIALIZED': result['receipts']={'state':'NOT_INITIALIZED'}
                else: raise
            code=0; reason='STATUS_OBSERVED'
        elif verb=='drain':
            result=receipts.ReceiptService(a.config,a.wait_ms).drain_receipts(a.maximum,a.offline)
            code=0 if all(r['state']=='LOCAL_PUBLISHED' for r in result) else 3
            reason='LOCAL_DRAIN_COMPLETE' if code==0 else 'DRAIN_INCOMPLETE'
        else:
            target=core.parse_gb(a.max_size_gb); evictor=receipts.LocalCacheEvictor(a.config,a.wait_ms)
            if a.status_only:
                cas.require(a.operation_id and not a.dry_run,'STATUS_ID_REQUIRED',code=2)
                row=evictor.reg.bind_operation(a.operation_id,'t6-prune',dict(target_bytes=target,profile='t6-private-prune/1'),status_only=True)
                code=0 if row['state']=='DONE' else 8; reason=row['state']
                result=core.decode(row['result'],wire=False) if row['result'] else {'state':row['state']}
            else:
                result=evictor.prune(target,a.dry_run,a.operation_id); code=0; reason='PLAN_PRODUCED' if a.dry_run else 'CACHE_TARGET_MET'
    except SystemExit as e: return int(e.code or 0)
    except Exception as e:
        if hasattr(e,'reason') and hasattr(e,'code'):
            code=e.code; reason=e.reason; result=getattr(e,'detail',{}).get('result',{'message':str(e)[:300]})
        else:
            err=cas.map_exception(e); code=err.code; reason=err.reason; result={'message':err.message}
    raw=cas.json_bytes(dict(protocol='gdoe-lab-wrapper/1',profile=locals().get('label'),command=locals().get('verb'),
        result=result,exit_code=code,reason=reason,remote_evidence='NOT_ASSERTED'))
    sys.stdout.buffer.write(raw); sys.stdout.buffer.flush(); return code
if __name__=='__main__': raise SystemExit(main())
