"""Fixed native-profile receipt jobs. Not a dynamic/plugin worker endpoint."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import drive_cas as transport
import drive_cas_native as native
original=transport._worker_dispatch

def dispatch(kind, args):
    if kind == 'native_snapshot_check':
        try:
            evidence=native.decode(native.read_limited(args['evidence_path'],1024*1024),wire=False)
            native._check_outputs(args['snapshot'],evidence)
            # Reverify DAG + block bytes, not only previously reconstructed outputs.
            captured=native.MerkleVerifier(args['contract'],args['root']).capture(
                Path(args['snapshot'])/'tree', args['scratch'])
            native._check_outputs(args['scratch'],captured)
            return {'root':args['root'],'scope':'FULL_CLOSURE',
                    'totals':captured['totals'],'files':captured['files']}
        except native.CASError as exc:
            raise transport.CASError(exc.reason,str(exc),exc.code) from exc
    return original(kind,args)
transport._worker_dispatch=dispatch
if __name__=='__main__':
    if sys.argv[1:] != ['--_worker']: raise SystemExit(2)
    raise SystemExit(transport._worker_main())
