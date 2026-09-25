#!/usr/bin/env python3
"""Explicit administrative convenience, separate from the five data-plane verbs.

create makes a NEW LAB_CANDIDATE store only. No automatic production qualification,
account login, overwrite of existing stores, credential copying or cloud cleanup.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import drive_cas as d


def main():
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    sub=parser.add_subparsers(dest='action',required=True)
    create=sub.add_parser('create',allow_abbrev=False)
    for name in ('private-root','exchange-root','source-root','export-root'):
        create.add_argument('--'+name,required=True)
    create.add_argument('--campaign',default='lab-transfer')
    create.add_argument('--task-id',default='artifact')
    create.add_argument('--logical-name',default='artifact.bin')
    create.add_argument('--allow-empty',action='store_true')
    create.add_argument('--confirm-unsynced-private',action='store_true',required=True)
    approve=sub.add_parser('approve',allow_abbrev=False)
    approve.add_argument('--config',required=True); approve.add_argument('--root',required=True)
    approve.add_argument('--lifetime-seconds',type=int,default=3600)
    release=sub.add_parser('release-export',allow_abbrev=False)
    release.add_argument('--config',required=True); release.add_argument('--operation-id',required=True)
    release.add_argument('--end-of-use-reason',required=True)
    abandon=sub.add_parser('release-prepared',allow_abbrev=False)
    abandon.add_argument('--config',required=True); abandon.add_argument('--root',required=True); abandon.add_argument('--reason',required=True)
    retry=sub.add_parser('open-retry-window',allow_abbrev=False)
    retry.add_argument('--config',required=True); retry.add_argument('--operation-id',required=True); retry.add_argument('--reason',required=True)
    a=parser.parse_args()
    if a.action=='create':
        d.label(a.campaign); d.label(a.task_id); d.logical_path(a.logical_name)
        private=Path(a.private_root).expanduser().resolve()
        for forbidden in ('/Library/CloudStorage/','/Library/Mobile Documents/'):
            d.require(forbidden not in str(private)+'/','PRIVATE_ROOT_IS_KNOWN_SYNC_LOCATION')
        private.parent.mkdir(parents=True,exist_ok=True)
        config=d.enroll_store(str(private),a.exchange_root,[a.source_root],[a.export_root],mode='LAB_CANDIDATE')
        cfg=d.load_config(config)
        contract=d.make_contract(cfg['store_id'],a.campaign,a.task_id)
        contract['slots'][0]['path']=a.logical_name; contract['slots'][0]['allow_empty']=int(a.allow_empty)
        intake=Path(cfg['exchange_root'])/a.campaign/(a.task_id+'-r1')
        d.enroll_task(config,str(intake),contract)
        result=dict(config=config,intake=str(intake),mode='LAB_CANDIDATE',production_qualification='NOT_GRANTED')
    elif a.action=='approve':
        cfg=d.load_config(a.config)
        with d.AuthorityRegistry(cfg) as reg:
            bindings=reg.db.execute('SELECT task_key FROM snapshots WHERE root=? ORDER BY rowid LIMIT 1',(a.root,)).fetchone()
            if bindings:
                contract=d.wire_read(reg.task(bindings[0])['contract'].encode())
            else:
                # For an external proposal, this helper uses the explicitly enrolled default task.
                binding=reg.binding(); contract=d.wire_read(reg.task(binding['task_key'])['contract'].encode())
        d.approve_candidate(a.config,a.root,contract,a.lifetime_seconds)
        result=dict(approved_root=a.root,task_key=d.task_key(contract))
    elif a.action=='release-export':
        d.release_export(a.config,a.operation_id,a.end_of_use_reason); result=dict(released_export=a.operation_id)
    elif a.action=='release-prepared':
        d.release_prepared(a.config,a.root,a.reason); result=dict(released_preparation=a.root)
    else:
        d.open_retry_window(a.config,a.operation_id,a.reason); result=dict(retry_window_opened=a.operation_id)
    print(json.dumps(result,sort_keys=True))
    return 0

if __name__=='__main__':
    try: raise SystemExit(main())
    except d.CASError as error:
        print(json.dumps(dict(reason=error.reason,message=error.message,exit_code=error.code)),file=sys.stderr)
        raise SystemExit(error.code)
