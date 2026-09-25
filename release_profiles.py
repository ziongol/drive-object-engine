"""Explicit config-format routing; never translate or initialize authority state."""
from pathlib import Path
import drive_cas as chat

DEFAULT_CONFIG=Path.home()/'Library/Application Support/SovereignDrive/drive-engine/config.json'

def profile(config_path):
    p=Path(chat.normalized_absolute(str(config_path)))
    with chat.SafeTree(p.parent) as t: raw=t.read(p.name,1024*1024)
    record=chat.json_read(raw,1024*1024)
    if record.get('protocol')=='gdoe-config/2':
        import drive_cas_native as core
        import native_receipts as receipts
        core.load_config(p)  # includes exact original source digest check
        return 'NATIVE54',core,receipts
    if record.get('version')==1:
        import receipt_engine as receipts
        chat.load_config(str(p))
        return 'CHAT66',chat,receipts
    raise chat.CASError('CONFIGURATION_UNSUPPORTED','No implicit schema conversion',7)

def config_argument(args):
    for i,a in enumerate(args):
        if a=='--config':
            chat.require(i+1<len(args),'INVALID_ARGUMENT',code=2); return args[i+1]
        if a.startswith('--config='): return a.split('=',1)[1]
    return str(DEFAULT_CONFIG)
