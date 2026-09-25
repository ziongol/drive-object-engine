#!/usr/bin/env python3
"""Exercise all five public verbs in an owned local fixture; no real Drive changes."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid
import drive_cas as d


def run(report_path: str | None = None) -> dict:
    records=[]
    with tempfile.TemporaryDirectory(prefix='drive-cas-workflow-') as td:
        base=Path(td).resolve()
        for folder in ('exchange','source','output'): (base/folder).mkdir()
        config=d.enroll_store(str(base/'private'),str(base/'exchange'),[str(base/'source')],[str(base/'output')],
                              mode='LAB_CANDIDATE')
        cfg=d.load_config(config)
        expected=bytes(range(256))*16385  # 4 MiB + 256 bytes, two blocks.
        source=base/'source/input.bin'; source.write_bytes(expected)
        contract=d.make_contract(cfg['store_id'],'example','artifact')
        contract['slots'][0]['expected_sha256']=hashlib.sha256(expected).hexdigest()
        intake=base/'exchange/intake'; d.enroll_task(config,str(intake),contract)
        def command(verb,*args,expect=0):
            argv=[sys.executable,str(Path(d.__file__).resolve()),'--config',config,'--operation-id',str(uuid.uuid4()),verb,*args]
            process=subprocess.run(argv,capture_output=True,timeout=120)
            value=json.loads(process.stdout)
            records.append(dict(command=verb,argv=argv,returncode=process.returncode,
                                stdout=value,stderr=process.stderr.decode('utf-8','replace')))
            if process.returncode!=expect:
                raise RuntimeError(f'{verb}: expected {expect}, got {process.returncode}: {value}')
            return value['result']
        put=command('put',str(source)); d.approve_candidate(config,put['root'],contract)
        command('verify',put['submission_dir'])
        command('commit',put['submission_dir'])
        get=command('get',put['root'],'--output',str(base/'output/recovered.bin'))
        assert Path(get['output_path']).read_bytes()==expected
        assert source.read_bytes()==expected
        command('prune','--max-size-gb','0','--dry-run')
        command('prune','--max-size-gb','0',expect=8)
        assert Path(get['output_path']).read_bytes()==expected
        result=dict(success=True,scope='LOCAL_LAB_CANDIDATE_ONLY',production_qualification='NOT_GRANTED',
                    environment=d.environment_record(),source_size=len(expected),
                    source_sha256=hashlib.sha256(expected).hexdigest(),records=records)
    if report_path:
        Path(report_path).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    return result


if __name__=='__main__':
    result=run(sys.argv[1] if len(sys.argv)>1 else None)
    print(json.dumps(dict(success=result['success'],scope=result['scope'],commands=len(result['records']))))
