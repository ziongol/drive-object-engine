#!/usr/bin/env python3
"""Google Drive Object Engine 0.5.0-rc1. Standard library, explicit local authority.

CAS wire: gdoe-cas/1. CLI: gdoe-cli/2 (Turn 5 root-based get and 4 MiB default).
No provider-backed mmap, cloud lock, cloud deletion, token or network client.
Run the supplied tests; this source is NOT a claim of target qualification.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import datetime as dt
import decimal
import errno
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, BinaryIO, Callable, Iterator
import uuid

VERSION = '0.5.0-rc1'
CLI_PROTOCOL = 'gdoe-cli/2'
WORKER_PROTOCOL = 'gdoe-worker/2'
BLOCK_SIZE = 4 * 1024 * 1024
LAYOUTS = {'fixed-4m-v1': BLOCK_SIZE, 'fixed-16m-v1': 16 * 1024 * 1024}
MAX_JSON = 16 * 1024 * 1024
MAX_FRAME = 65536
MAX_UINT = 9007199254740991
EMPTY_SHA = hashlib.sha256(b'').hexdigest()
HEX = re.compile(r'[0-9a-f]{64}\Z')
LABEL = re.compile(r'[A-Za-z0-9_.-]{1,128}\Z')
MEDIA = re.compile(r'[a-z0-9][a-z0-9!#$&^_.+\-]*/[a-z0-9][a-z0-9!#$&^_.+\-]*\Z')
GOALS = {'put': 'LOCAL_PUBLICATION', 'get': 'FILE_MATERIALIZED',
         'commit': 'CANONICAL_ADMISSION', 'verify': 'FULL_CLOSURE_VERIFIED',
         'prune': 'CACHE_TARGET_MET'}
DEFAULT_LIMITS = dict(max_file_bytes=64*1024**3, max_task_bytes=128*1024**3,
                      max_members=100000, max_metadata_bytes=256*1024**2,
                      max_artifacts=1000, reserve_bytes=2*1024**3,
                      reserve_percent=5, job_timeout_ms=120000,
                      publish_timeout_ms=300000, max_dispatches=8,
                      retry_window_ms=900000, cache_target_bytes=100*1000**3)


class CASError(Exception):
    def __init__(self, reason: str, message: str = '', code: int = 4):
        self.reason, self.message, self.code = reason, message or reason, code
        self.details: dict | None = None
        super().__init__(self.message)


def require(ok: bool, reason: str, message: str = '', code: int = 4) -> None:
    if not ok:
        raise CASError(reason, message, code)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_id() -> str:
    return str(uuid.uuid4())


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def uint(v: Any, maximum: int = MAX_UINT, minimum: int = 0) -> int:
    require(type(v) is int and minimum <= v <= maximum, 'INVALID_INTEGER')
    return v


def digest(v: Any) -> str:
    require(isinstance(v, str) and HEX.fullmatch(v) is not None, 'INVALID_HASH')
    return v


def label(v: Any) -> str:
    require(isinstance(v, str) and LABEL.fullmatch(v) is not None and v not in ('.', '..'), 'INVALID_LABEL')
    return v


def uuid_value(v: Any) -> str:
    try:
        u = uuid.UUID(v)
        require(str(u) == v and u.variant == uuid.RFC_4122, 'INVALID_UUID')
    except (ValueError, AttributeError, TypeError):
        raise CASError('INVALID_UUID') from None
    return v


def utc_value(v: Any) -> str:
    require(isinstance(v, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z', v) is not None, 'INVALID_UTC')
    try:
        dt.datetime.strptime(v, '%Y-%m-%dT%H:%M:%S.%fZ')
    except ValueError:
        raise CASError('INVALID_UTC') from None
    return v


def fields(v: Any, expected: str | set[str]) -> dict:
    keys = set(expected.split()) if isinstance(expected, str) else expected
    require(type(v) is dict and set(v) == keys, 'INVALID_FIELDS', f'Expected fields: {sorted(keys)}')
    return v


def logical_path(v: Any) -> str:
    require(isinstance(v, str) and 1 <= len(v) <= 1024, 'INVALID_PATH')
    for p in v.split('/'):
        require(1 <= len(p) <= 200 and re.fullmatch(r'[A-Za-z0-9_.-]+', p) is not None and p not in ('.', '..'), 'INVALID_PATH')
    return v


def unique_paths(paths: list[str]) -> None:
    folded = [logical_path(p).lower() for p in paths]
    require(len(set(folded)) == len(folded), 'PATH_COLLISION')
    s = set(folded)
    for p in folded:
        parts = p.split('/')
        require(not any('/'.join(parts[:i]) in s for i in range(1, len(parts))), 'PATH_COLLISION')


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    d: dict = {}
    for k, v in pairs:
        require(k not in d, 'DUPLICATE_KEY')
        d[k] = v
    return d


def _depth_bytes(data: bytes, maximum: int) -> None:
    depth = 0
    inside = escape = False
    for c in data:
        if inside:
            if escape:
                escape = False
            elif c == 92:
                escape = True
            elif c == 34:
                inside = False
        elif c == 34:
            inside = True
        elif c in (91, 123):
            depth += 1
            require(depth <= maximum, 'JSON_DEPTH_LIMIT')
        elif c in (93, 125):
            depth -= 1


def json_read(data: bytes, maximum: int = MAX_JSON, depth: int = 16) -> Any:
    require(isinstance(data, bytes) and len(data) <= maximum, 'JSON_SIZE_LIMIT')
    _depth_bytes(data, depth)
    def no_number(_: str) -> None:
        raise CASError('INVALID_NUMBER')
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=_pairs,
                          parse_float=no_number, parse_constant=no_number)
    except (UnicodeError, ValueError, RecursionError) as e:
        raise CASError('INVALID_JSON', str(e)[:160]) from None


def json_bytes(v: Any) -> bytes:
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def _wire_values(v: Any) -> None:
    if v is None:
        return
    if type(v) is int:
        uint(v)
    elif type(v) is str:
        require(all(32 <= ord(c) <= 126 for c in v), 'NONCANONICAL_ENCODING')
    elif type(v) is list:
        for item in v:
            _wire_values(item)
    elif type(v) is dict:
        for k, item in v.items():
            _wire_values(k)
            _wire_values(item)
    else:
        raise CASError('INVALID_WIRE_VALUE')


def wire_bytes(v: Any) -> bytes:
    _wire_values(v)
    b = json_bytes(v)
    require(len(b) <= MAX_JSON, 'JSON_SIZE_LIMIT')
    _depth_bytes(b, 16)
    return b


def wire_read(b: bytes) -> dict:
    v = json_read(b)
    require(type(v) is dict, 'INVALID_FIELDS')
    _wire_values(v)
    require(wire_bytes(v) == b, 'NONCANONICAL_ENCODING')
    return v


def block_ref(v: Any) -> dict:
    fields(v, 'sha256 size_bytes')
    digest(v['sha256']); uint(v['size_bytes'], 16*1024**2, 1)
    return v


def node_ref(v: Any, kind: str | None = None) -> dict:
    fields(v, 'kind sha256 size_bytes')
    require(v['kind'] in ('dataset', 'file_map', 'chunk_page'), 'INVALID_NODE_KIND')
    if kind is not None:
        require(v['kind'] == kind, 'INVALID_NODE_KIND')
    digest(v['sha256']); uint(v['size_bytes'], MAX_JSON, 1)
    return v


def object_path(ref: dict, block: bool = False) -> str:
    h = digest(ref['sha256'])
    if block:
        block_ref(ref)
        return f'blocks/sha256/{h[:2]}/{h[2:4]}/{h}.bin'
    node_ref(ref)
    return f'nodes/{ref["kind"]}/sha256/{h[:2]}/{h[2:4]}/{h}.json'


def node(kind: str, **kw: Any) -> dict:
    return dict(kind=kind, schema_version=1, wire_profile='ascii-json-1', **kw)


def validate_node(v: dict, kind: str) -> None:
    expected = {
        'chunk_page': 'kind schema_version wire_profile chunks',
        'file_map': 'kind schema_version wire_profile layout_profile size_bytes content_sha256 chunk_count pages',
        'dataset': 'kind schema_version wire_profile artifacts',
        'submission': 'kind schema_version wire_profile protocol store_id campaign task_id task_revision contract_sha256 producer_agent producer_installation attempt_id created_at_utc dataset storage totals',
        'producer_commit': 'kind schema_version wire_profile submission_sha256 manifest_size_bytes attempt_id prepared_at_utc',
    }
    fields(v, expected[kind])
    require(v['kind'] == kind and type(v['schema_version']) is int and v['schema_version'] == 1 and v['wire_profile'] == 'ascii-json-1', 'UNSUPPORTED_PROTOCOL')
    if kind == 'chunk_page':
        require(type(v['chunks']) is list and 1 <= len(v['chunks']) <= 4096, 'INVALID_PAGE_PACKING')
        for r in v['chunks']: block_ref(r)
    elif kind == 'file_map':
        require(v['layout_profile'] in LAYOUTS, 'UNSUPPORTED_LAYOUT')
        uint(v['size_bytes']); digest(v['content_sha256']); uint(v['chunk_count'], 1048576)
        require(type(v['pages']) is list and len(v['pages']) <= 256, 'INVALID_PAGE_PACKING')
        for r in v['pages']: node_ref(r, 'chunk_page')
    elif kind == 'dataset':
        require(type(v['artifacts']) is list and len(v['artifacts']) <= 100000, 'ARTIFACT_LIMIT')
        paths = []
        for a in v['artifacts']:
            fields(a, 'path role media_type file_map')
            paths.append(logical_path(a['path'])); label(a['role'])
            require(isinstance(a['media_type'], str) and len(a['media_type']) <= 127 and MEDIA.fullmatch(a['media_type']) is not None, 'INVALID_MEDIA_TYPE')
            node_ref(a['file_map'], 'file_map')
        require(paths == sorted(paths), 'ARTIFACT_ORDER')
        unique_paths(paths)
    elif kind == 'submission':
        require(v['protocol'] == 'gdoe-cas/1', 'UNSUPPORTED_PROTOCOL')
        for k in ('store_id', 'producer_installation', 'attempt_id'): uuid_value(v[k])
        for k in ('campaign', 'task_id', 'producer_agent'): label(v[k])
        uint(v['task_revision'], minimum=1); digest(v['contract_sha256']); utc_value(v['created_at_utc'])
        node_ref(v['dataset'], 'dataset')
        fields(v['storage'], 'profile pool_id')
        require(v['storage'] == {'profile': 'self-contained-v1', 'pool_id': None}, 'POOLED_STORAGE_UNSUPPORTED', code=7)
        fields(v['totals'], 'artifact_count logical_bytes chunk_references unique_blocks unique_block_bytes unique_metadata_nodes unique_metadata_bytes')
        for value in v['totals'].values(): uint(value)
    else:
        digest(v['submission_sha256']); uint(v['manifest_size_bytes'], MAX_JSON, 1)
        uuid_value(v['attempt_id']); utc_value(v['prepared_at_utc'])


def normalized_absolute(path: str | Path) -> str:
    s = os.fspath(path)
    require(s not in ('', '-') and '\x00' not in s, 'INVALID_PATH')
    # This is lexical only. It deliberately does not follow symlinks.
    require('..' not in Path(s).parts, 'INVALID_PATH')
    return os.path.abspath(os.path.expanduser(s))


def relative_under(path: str, root: str) -> str:
    p, r = normalized_absolute(path), normalized_absolute(root)
    require(os.path.commonpath([p, r]) == r, 'PATH_OUTSIDE_ROOT', code=6)
    return os.path.relpath(p, r)


def identity(st: os.stat_result) -> dict:
    return {'dev': st.st_dev, 'ino': st.st_ino}


def sync_fd(fd: int, full: bool = False) -> None:
    os.fsync(fd)
    if full and sys.platform == 'darwin':
        fcntl.fcntl(fd, 51)  # F_FULLFSYNC, Darwin ABI; must be target-qualified.


class SafeTree:
    """Descriptor-relative no-follow traversal. Root identities are local enrollment.

    No path resolving is performed for untrusted input. Moving an already opened
    directory by a hostile same-privilege process is outside the local TCB model.
    """
    def __init__(self, root: str | Path, expected: dict | None = None):
        self.root = normalized_absolute(root)
        self.dataless_observed = 0
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open('/', flags)
        try:
            for part in Path(self.root).parts[1:]:
                nxt = os.open(part, flags, dir_fd=fd)
                os.close(fd); fd = nxt
            if expected is not None:
                require(identity(os.fstat(fd)) == expected, 'ROOT_IDENTITY_CHANGED', code=7)
            self.fd = fd
        except BaseException:
            os.close(fd); raise

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd); self.fd = -1

    def __enter__(self) -> 'SafeTree': return self
    def __exit__(self, *args: Any) -> None: self.close()

    @staticmethod
    def parts(rel: str) -> list[str]:
        require(isinstance(rel, str) and rel and not rel.startswith('/') and '\x00' not in rel, 'INVALID_PATH')
        parts = rel.split('/')
        require(all(p not in ('', '.', '..') for p in parts), 'INVALID_PATH')
        return parts

    @contextlib.contextmanager
    def parent(self, rel: str, create: bool = False) -> Iterator[tuple[int, str]]:
        parts = self.parts(rel)
        fd = os.dup(self.fd)
        try:
            for p in parts[:-1]:
                if create:
                    try:
                        os.mkdir(p, 0o700, dir_fd=fd)
                        sync_fd(fd)
                    except FileExistsError:
                        pass
                nfd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd); fd = nfd
            yield fd, parts[-1]
        finally:
            os.close(fd)

    def mkdir(self, rel: str) -> None:
        with self.parent(rel, True) as (fd, name):
            os.mkdir(name, 0o700, dir_fd=fd)
            sync_fd(fd)

    @contextlib.contextmanager
    def open_read(self, rel: str) -> Iterator[BinaryIO]:
        with self.parent(rel) as (fd, name):
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'UNSAFE_FILE_TYPE')
            flag = getattr(stat, 'SF_DATALESS', None) if sys.platform == 'darwin' else None
            if flag is not None and getattr(before, 'st_flags', 0) & flag:
                self.dataless_observed += 1
                # Worker stderr is drained and bounded by the supervisor.
                print('DATALESS_OBSERVED before ordinary byte acquisition', file=sys.stderr, flush=True)
            f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        try:
            st = os.fstat(f)
            require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, 'UNSAFE_FILE_TYPE')
            with os.fdopen(f, 'rb', buffering=0, closefd=False) as stream:
                yield stream
        finally:
            os.close(f)

    @contextlib.contextmanager
    def open_new(self, rel: str) -> Iterator[BinaryIO]:
        with self.parent(rel, True) as (fd, name):
            f = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
            try:
                with os.fdopen(f, 'wb', closefd=False) as stream:
                    yield stream
                    stream.flush(); sync_fd(f, True)
                sync_fd(fd)
            finally:
                os.close(f)

    def read(self, rel: str, limit: int, expected_size: int | None = None, expected_sha: str | None = None) -> bytes:
        pieces: list[bytes] = []; n = 0
        with self.open_read(rel) as stream:
            while True:
                b = stream.read(min(1024*1024, limit + 1 - n))
                if not b: break
                n += len(b)
                require(n <= limit, 'LENGTH_MISMATCH')
                pieces.append(b)
        b = b''.join(pieces)
        if expected_size is not None: require(n == expected_size, 'LENGTH_MISMATCH')
        if expected_sha is not None: require(sha(b) == expected_sha, 'DIGEST_MISMATCH')
        return b

    def write_once(self, rel: str, data: bytes, equal_existing: bool = False) -> None:
        try:
            with self.open_new(rel) as f: f.write(data)
        except FileExistsError:
            require(equal_existing, 'OUTPUT_EXISTS', code=5)
            existing = self.read(rel, len(data), len(data))
            require(existing == data, 'HASH_IDENTITY_INCIDENT', code=10)

    def list_files(self, maximum: int = 100000) -> set[str]:
        result: set[str] = set(); seen_dirs = 0
        def visit(fd: int, prefix: str, depth: int) -> None:
            nonlocal seen_dirs
            require(depth <= 16, 'DIRECTORY_DEPTH_LIMIT')
            with os.scandir(fd) as entries:
                for e in entries:
                    rel = prefix + e.name
                    st = e.stat(follow_symlinks=False)
                    if stat.S_ISDIR(st.st_mode):
                        seen_dirs += 1
                        require(seen_dirs <= maximum * 4 + 32, 'MEMBER_LIMIT')
                        child = os.open(e.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                        try: visit(child, rel + '/', depth + 1)
                        finally: os.close(child)
                    else:
                        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, 'UNSAFE_FILE_TYPE')
                        result.add(rel)
                        require(len(result) <= maximum, 'MEMBER_LIMIT')
        visit(self.fd, '', 0)
        return result

    def file_hash(self, rel: str, maximum: int) -> tuple[str, int]:
        h = hashlib.sha256(); size = 0
        with self.open_read(rel) as stream:
            while b := stream.read(1024*1024):
                size += len(b); require(size <= maximum, 'LENGTH_MISMATCH'); h.update(b)
        return h.hexdigest(), size


def fixed_chunks(stream: BinaryIO, size: int = BLOCK_SIZE) -> Iterator[bytes]:
    """A short non-EOF read is not a block boundary."""
    require(size in LAYOUTS.values(), 'UNSUPPORTED_LAYOUT')
    while True:
        buf = bytearray()
        while len(buf) < size:
            b = stream.read(size - len(buf))
            require(isinstance(b, bytes), 'INVALID_READ_RESULT')
            if not b: break
            require(len(b) <= size - len(buf), 'INVALID_READ_RESULT')
            buf.extend(b)
        if not buf: return
        yield bytes(buf)
        if len(buf) < size: return


class AtomicPublisher:
    """Native write-once rename, with NO replacing fallback."""
    def __init__(self) -> None:
        self.lib = ctypes.CDLL(None, use_errno=True)
        if sys.platform == 'darwin':
            self.name, self.flag = 'renameatx_np', 0x00000004
        elif sys.platform == 'linux':
            self.name, self.flag = 'renameat2', 1
        else:
            raise CASError('ATOMIC_PUBLISH_UNSUPPORTED', code=7)
        try: self.fn = getattr(self.lib, self.name)
        except AttributeError: raise CASError('ATOMIC_PUBLISH_UNSUPPORTED', code=7) from None
        self.fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        self.fn.restype = ctypes.c_int

    def rename(self, src: SafeTree, src_rel: str, dst: SafeTree, dst_rel: str) -> None:
        with src.parent(src_rel) as (sfd, sn), dst.parent(dst_rel) as (dfd, dn):
            ctypes.set_errno(0)
            rc = self.fn(sfd, os.fsencode(sn), dfd, os.fsencode(dn), self.flag)
            if rc:
                e = ctypes.get_errno()
                if e in (errno.EEXIST, errno.ENOTEMPTY): raise CASError('OUTPUT_EXISTS', code=5)
                if e in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP, errno.EXDEV):
                    raise CASError('ATOMIC_PUBLISH_UNSUPPORTED', os.strerror(e), 7)
                if e == errno.EIO: raise CASError('PUBLICATION_OUTCOME_UNKNOWN', os.strerror(e), 9)
                raise OSError(e, os.strerror(e))
            # The name may already be installed if a following flush fails.
            try:
                sync_fd(dfd); sync_fd(sfd)
            except OSError as e:
                raise CASError('PUBLICATION_OUTCOME_UNKNOWN', str(e), 9) from e


def make_contract(store_id: str, campaign: str, task_id: str, task_revision: int = 1,
                  slots: list[dict] | None = None, allow_empty_dataset: bool = False,
                  producer_agents: list[str] | None = None) -> dict:
    """Administrative helper. Returned bytes are separately enrolled, never trusted from Drive."""
    c = dict(kind='gdoe_task_contract', schema_version=1, store_id=store_id,
             campaign=campaign, task_id=task_id, task_revision=task_revision,
             slots=slots if slots is not None else [dict(path='artifact.bin', role='artifact',
                 media_type='application/octet-stream', allow_empty=0, max_bytes=64*1024**3,
                 expected_sha256=None, source_scope='CAPTURED_BYTES')],
             allow_empty_dataset=int(allow_empty_dataset), allowed_layouts=list(LAYOUTS),
             max_logical_bytes=128*1024**3, producer_agents=producer_agents or ['lab'])
    validate_contract(c)
    return c


def validate_contract(c: dict) -> None:
    fields(c, 'kind schema_version store_id campaign task_id task_revision slots allow_empty_dataset allowed_layouts max_logical_bytes producer_agents')
    require(c['kind'] == 'gdoe_task_contract' and c['schema_version'] == 1, 'INVALID_CONTRACT')
    uuid_value(c['store_id']); label(c['campaign']); label(c['task_id']); uint(c['task_revision'], minimum=1)
    uint(c['allow_empty_dataset'], 1); uint(c['max_logical_bytes'])
    require(type(c['allowed_layouts']) is list and c['allowed_layouts'] and len(set(c['allowed_layouts'])) == len(c['allowed_layouts']) and all(x in LAYOUTS for x in c['allowed_layouts']), 'INVALID_CONTRACT')
    require(type(c['producer_agents']) is list and c['producer_agents'], 'INVALID_CONTRACT')
    for p in c['producer_agents']: label(p)
    require(type(c['slots']) is list and len(c['slots']) <= 1000, 'INVALID_CONTRACT')
    paths = []
    for s in c['slots']:
        fields(s, 'path role media_type allow_empty max_bytes expected_sha256 source_scope')
        paths.append(logical_path(s['path'])); label(s['role']); uint(s['allow_empty'], 1); uint(s['max_bytes'])
        require(isinstance(s['media_type'], str) and len(s['media_type']) <= 127 and MEDIA.fullmatch(s['media_type']) is not None, 'INVALID_MEDIA_TYPE')
        if s['expected_sha256'] is not None: digest(s['expected_sha256'])
        require(s['source_scope'] in ('CAPTURED_BYTES', 'COHERENT_SNAPSHOT'), 'INVALID_CONTRACT')
    require(paths == sorted(paths), 'ARTIFACT_ORDER'); unique_paths(paths)
    wire_bytes(c)


def task_key(c: dict) -> dict:
    return {k: c[k] for k in ('store_id', 'campaign', 'task_id', 'task_revision')}


def key_text(c: dict) -> str:
    return wire_bytes(task_key(c)).decode('ascii')


def _capacity(path: str, additional: int, limits: dict) -> None:
    usage = shutil.disk_usage(path)
    floor = max(limits['reserve_bytes'], usage.total * limits['reserve_percent'] // 100)
    require(usage.free - additional >= floor, 'DISK_RESERVE_REQUIRED', code=8)


class CASChunkManager:
    """Closed, self-contained preparation. Reuse is exact within a candidate.

    Optional cross-project physical pool import is disabled in this release.
    Distinct submissions deliberately retain independent private generations.
    """
    def __init__(self, limits: dict | None = None):
        self.limits = dict(DEFAULT_LIMITS, **(limits or {}))

    @staticmethod
    def save_node(tree: SafeTree, value: dict) -> dict:
        data = wire_bytes(value)
        ref = dict(kind=value['kind'], sha256=sha(data), size_bytes=len(data))
        tree.write_once(object_path(ref), data, equal_existing=True)
        return ref

    def build_candidate(self, workspace: str, sources: dict[str, str], contract: dict,
                        producer_agent: str, installation_id: str, attempt_id: str,
                        created_at: str, layout: str = 'fixed-4m-v1') -> dict:
        validate_contract(contract)
        require(layout in contract['allowed_layouts'], 'UNSUPPORTED_LAYOUT')
        require(set(sources) == {s['path'] for s in contract['slots']}, 'CONTRACT_MISMATCH')
        require(producer_agent in contract['producer_agents'], 'PRODUCER_NOT_ENROLLED', code=6)
        require(sources or contract['allow_empty_dataset'] == 1, 'CONTRACT_MISMATCH')
        with SafeTree(workspace) as work:
            work.mkdir('tree'); work.mkdir('files')
        unique_blocks: dict[str, int] = {}; unique_nodes: dict[tuple[str, str], int] = {}
        logical_bytes = chunk_references = 0
        artifacts = []
        file_details = []
        def save(t: SafeTree, v: dict) -> dict:
            r = self.save_node(t, v); unique_nodes[(r['kind'], r['sha256'])] = r['size_bytes']; return r
        with SafeTree(Path(workspace)/'tree') as tree, SafeTree(workspace) as work:
            for index, slot in enumerate(contract['slots']):
                source = normalized_absolute(sources[slot['path']])
                require(not source.lower().endswith(('.gdoc', '.gsheet', '.gslides')), 'EXPORT_REQUIRED')
                refs = []; h = hashlib.sha256(); n = 0
                output_rel = f'files/{index:08d}.bin'
                with SafeTree(Path(source).parent) as stree, stree.open_read(Path(source).name) as stream, work.open_new(output_rel) as out:
                    for data in fixed_chunks(stream, LAYOUTS[layout]):
                        n += len(data)
                        require(n <= min(slot['max_bytes'], self.limits['max_file_bytes']), 'FILE_SIZE_LIMIT', code=8)
                        require(logical_bytes + n <= min(contract['max_logical_bytes'], self.limits['max_task_bytes']), 'LOGICAL_SIZE_LIMIT', code=8)
                        _capacity(workspace, len(data)*2, self.limits)
                        ref = dict(sha256=sha(data), size_bytes=len(data))
                        tree.write_once(object_path(ref, True), data, equal_existing=True)
                        prior = unique_blocks.setdefault(ref['sha256'], len(data))
                        require(prior == len(data), 'HASH_IDENTITY_INCIDENT', code=10)
                        refs.append(ref); h.update(data); out.write(data)
                        require(len(refs) <= 1048576, 'REFERENCE_LIMIT')
                require(n or slot['allow_empty'] == 1, 'CONTRACT_MISMATCH', 'Empty file forbidden by enrolled contract')
                content_sha = h.hexdigest()
                if slot['expected_sha256'] is not None:
                    require(content_sha == slot['expected_sha256'], 'CONTRACT_MISMATCH', 'Independent content digest mismatch')
                if slot['source_scope'] == 'COHERENT_SNAPSHOT':
                    require(slot['expected_sha256'] is not None, 'SOURCE_NOT_QUIESCENT', 'This build requires an independently pinned byte digest for coherent-source slots')
                require(work.file_hash(output_rel, n) == (content_sha, n), 'DESTINATION_MISMATCH')
                pages = [save(tree, node('chunk_page', chunks=refs[i:i+4096])) for i in range(0, len(refs), 4096)]
                fm = node('file_map', layout_profile=layout, size_bytes=n, content_sha256=content_sha, chunk_count=len(refs), pages=pages)
                fm_ref = save(tree, fm)
                artifacts.append({k: slot[k] for k in ('path', 'role', 'media_type')} | {'file_map': fm_ref})
                file_details.append(dict(path=slot['path'], content_sha256=content_sha, size_bytes=n, file_map=fm_ref, output_rel=output_rel))
                logical_bytes += n; chunk_references += len(refs)
            dataset = save(tree, node('dataset', artifacts=artifacts))
            totals = dict(artifact_count=len(artifacts), logical_bytes=logical_bytes, chunk_references=chunk_references,
                          unique_blocks=len(unique_blocks), unique_block_bytes=sum(unique_blocks.values()),
                          unique_metadata_nodes=len(unique_nodes), unique_metadata_bytes=sum(unique_nodes.values()))
            manifest = node('submission', protocol='gdoe-cas/1', **task_key(contract),
                            contract_sha256=sha(wire_bytes(contract)), producer_agent=producer_agent,
                            producer_installation=installation_id, attempt_id=attempt_id, created_at_utc=created_at,
                            dataset=dataset, storage={'profile': 'self-contained-v1', 'pool_id': None}, totals=totals)
            validate_node(manifest, 'submission')
            raw = wire_bytes(manifest); root = sha(raw)
            tree.write_once('manifest.json', raw)
            tree.write_once('COMMIT.json', wire_bytes(node('producer_commit', submission_sha256=root,
                manifest_size_bytes=len(raw), attempt_id=attempt_id, prepared_at_utc=created_at)))
        return MerkleVerifier(self.limits).verify_tree(str(Path(workspace)/'tree'), root, contract,
                expected_outputs=workspace, enforce_approval=False)


class MerkleVerifier:
    """Fresh exact closure validation. Never calls the admission broker.

    capture_to optionally receives an owned NEW private workspace. Source files
    are never changed. Whole-file hashes and retained output readback are checked.
    """
    def __init__(self, limits: dict | None = None, barrier: Callable[[str, dict], None] | None = None):
        self.limits = dict(DEFAULT_LIMITS, **(limits or {}))
        self.barrier = barrier or (lambda phase, evidence: None)

    def verify_tree(self, candidate: str, expected_root: str, contract: dict,
                    capture_to: str | None = None, expected_outputs: str | None = None,
                    approved_roots: list[str] | None = None, enforce_approval: bool = True,
                    expected_identity: dict | None = None) -> dict:
        digest(expected_root); validate_contract(contract)
        if enforce_approval and approved_roots is not None:
            require(expected_root in approved_roots, 'ROOT_NOT_APPROVED', code=6)
        if capture_to:
            with SafeTree(capture_to) as t: t.mkdir('tree'); t.mkdir('files')
        destination = SafeTree(Path(capture_to)/'tree') if capture_to else None
        work = SafeTree(capture_to or expected_outputs) if (capture_to or expected_outputs) else None
        expected_files: set[str] = {'manifest.json', 'COMMIT.json'}
        nodes: dict[tuple[str, str], tuple[dict, int]] = {}
        blocks: dict[str, int] = {}
        metadata_bytes = 0
        logical_bytes = chunk_occ = 0
        outputs = []
        try:
            with SafeTree(candidate, expected_identity) as src:
                root_bytes = src.read('manifest.json', MAX_JSON, expected_sha=expected_root)
                m = wire_read(root_bytes); validate_node(m, 'submission')
                require(task_key(m) == task_key(contract) and m['contract_sha256'] == sha(wire_bytes(contract)), 'CONTRACT_MISMATCH')
                require(m['producer_agent'] in contract['producer_agents'], 'PRODUCER_NOT_ENROLLED', code=6)
                require(m['totals']['logical_bytes'] <= min(contract['max_logical_bytes'], self.limits['max_task_bytes']), 'LOGICAL_SIZE_LIMIT', code=8)
                commit_bytes = src.read('COMMIT.json', MAX_JSON)
                marker = wire_read(commit_bytes); validate_node(marker, 'producer_commit')
                require(marker['submission_sha256'] == expected_root and marker['manifest_size_bytes'] == len(root_bytes)
                        and marker['attempt_id'] == m['attempt_id'], 'MARKER_MISMATCH')
                if destination:
                    destination.write_once('manifest.json', root_bytes)
                    destination.write_once('COMMIT.json', commit_bytes)
                self.barrier('root-captured', dict(root=expected_root))

                def load(ref: dict, kind: str) -> dict:
                    nonlocal metadata_bytes
                    node_ref(ref, kind); key = kind, ref['sha256']; rel = object_path(ref)
                    expected_files.add(rel)
                    if key in nodes:
                        v, size = nodes[key]; require(size == ref['size_bytes'], 'LENGTH_MISMATCH'); return v
                    b = src.read(rel, ref['size_bytes'], ref['size_bytes'], ref['sha256'])
                    value = wire_read(b); validate_node(value, kind)
                    metadata_bytes += len(b)
                    require(metadata_bytes <= self.limits['max_metadata_bytes'], 'METADATA_LIMIT', code=8)
                    require(len(nodes) < min(1048576, self.limits['max_members']), 'MEMBER_LIMIT')
                    if destination: destination.write_once(rel, b)
                    nodes[key] = value, len(b)
                    return value

                dataset = load(m['dataset'], 'dataset')
                require(len(dataset['artifacts']) <= self.limits['max_artifacts'], 'ARTIFACT_LIMIT', code=8)
                require(dataset['artifacts'] or contract['allow_empty_dataset'] == 1, 'CONTRACT_MISMATCH')
                require(len(dataset['artifacts']) == len(contract['slots']), 'CONTRACT_MISMATCH')
                for index, (artifact, slot) in enumerate(zip(dataset['artifacts'], contract['slots'])):
                    require(all(artifact[k] == slot[k] for k in ('path', 'role', 'media_type')), 'CONTRACT_MISMATCH')
                    require(not artifact['path'].lower().endswith(('.gdoc', '.gsheet', '.gslides')), 'EXPORT_REQUIRED')
                    fm = load(artifact['file_map'], 'file_map')
                    require(fm['layout_profile'] in contract['allowed_layouts'], 'UNSUPPORTED_LAYOUT')
                    length = fm['size_bytes']; block_size = LAYOUTS[fm['layout_profile']]
                    require(length <= min(slot['max_bytes'], self.limits['max_file_bytes']), 'FILE_SIZE_LIMIT', code=8)
                    require(length or slot['allow_empty'] == 1, 'CONTRACT_MISMATCH')
                    logical_bytes += length
                    require(logical_bytes <= min(contract['max_logical_bytes'], self.limits['max_task_bytes'], m['totals']['logical_bytes']), 'LOGICAL_SIZE_LIMIT', code=8)
                    expected_count = (length + block_size - 1)//block_size
                    require(fm['chunk_count'] == expected_count and len(fm['pages']) == (expected_count+4095)//4096, 'INVALID_PAGE_PACKING')
                    refs = []
                    for pi, page_ref in enumerate(fm['pages']):
                        page = load(page_ref, 'chunk_page')
                        n = min(4096, expected_count - pi*4096)
                        require(len(page['chunks']) == n, 'INVALID_PAGE_PACKING')
                        refs.extend(page['chunks'])
                    require(len(refs) == expected_count, 'REFERENCE_COUNT_MISMATCH')
                    for bi, ref in enumerate(refs):
                        n = min(block_size, length - bi*block_size)
                        require(ref['size_bytes'] == n, 'LENGTH_MISMATCH')
                        prior = blocks.setdefault(ref['sha256'], n)
                        require(prior == n, 'LENGTH_MISMATCH')
                        require(len(blocks) <= min(1048576, self.limits['max_members']), 'MEMBER_LIMIT')
                        expected_files.add(object_path(ref, True))
                    output_rel = f'files/{index:08d}.bin'
                    context = work.open_new(output_rel) if capture_to and work else contextlib.nullcontext(None)
                    whole = hashlib.sha256(); observed_size = 0
                    with context as outfile:
                        for ref in refs:
                            rel = object_path(ref, True)
                            # Source membership is always observed. A private cache cannot hide missing delivery.
                            b = src.read(rel, ref['size_bytes'], ref['size_bytes'], ref['sha256'])
                            self.barrier('block-captured', dict(path=rel, size=len(b)))
                            if destination:
                                _capacity(capture_to, len(b)*2, self.limits)
                                destination.write_once(rel, b, equal_existing=True)
                                b = destination.read(rel, len(b), len(b), ref['sha256'])
                            whole.update(b); observed_size += len(b)
                            if outfile is not None: outfile.write(b)
                    require(observed_size == length, 'LENGTH_MISMATCH')
                    require(whole.hexdigest() == fm['content_sha256'], 'WHOLE_FILE_MISMATCH')
                    if slot['expected_sha256'] is not None:
                        require(fm['content_sha256'] == slot['expected_sha256'], 'CONTRACT_MISMATCH')
                    if slot['source_scope'] == 'COHERENT_SNAPSHOT':
                        require(slot['expected_sha256'] is not None, 'SOURCE_NOT_QUIESCENT')
                    if work:
                        self.barrier('before-destination-readback', dict(workspace=work.root, path=output_rel))
                        require(work.file_hash(output_rel, length) == (fm['content_sha256'], length), 'DESTINATION_MISMATCH')
                    chunk_occ += len(refs)
                    outputs.append(dict(path=artifact['path'], content_sha256=fm['content_sha256'], size_bytes=length,
                                        file_map=artifact['file_map'], output_rel=output_rel))
                totals = dict(artifact_count=len(outputs), logical_bytes=logical_bytes, chunk_references=chunk_occ,
                              unique_blocks=len(blocks), unique_block_bytes=sum(blocks.values()),
                              unique_metadata_nodes=len(nodes), unique_metadata_bytes=metadata_bytes)
                require(totals == m['totals'], 'TOTALS_MISMATCH')
                actual_files = src.list_files(self.limits['max_members'])
                require(actual_files == expected_files, 'INVENTORY_MISMATCH',
                        f'Unexpected: {sorted(actual_files-expected_files)[:3]}; missing: {sorted(expected_files-actual_files)[:3]}')
                tree_bytes = len(root_bytes) + len(commit_bytes) + totals['unique_block_bytes'] + metadata_bytes
                self.barrier('closure-verified', dict(root=expected_root, totals=totals))
                return dict(root=expected_root, manifest=m, manifest_size_bytes=len(root_bytes),
                            files=outputs, tree_bytes=tree_bytes, snapshot_bytes=tree_bytes + logical_bytes,
                            scope='FULL_CLOSURE', membership='OBSERVED_SELF_CONTAINED',
                            dataless_observed=src.dataless_observed,
                            dataless_flag_supported=(sys.platform=='darwin' and hasattr(stat,'SF_DATALESS')),
                            verified_at_utc=utc_now(), remote_evidence='NOT_ASSERTED')
        except FileNotFoundError as e:
            raise CASError('PENDING_CONTENT', str(e)[:300], 3) from e
        finally:
            if destination: destination.close()
            if work: work.close()


def copy_tree_exact(source: str, target: str, maximum: int) -> None:
    with SafeTree(source) as src, SafeTree(target) as dst:
        for rel in sorted(src.list_files(maximum)):
            # Every stored member is <= 16 MiB. No arbitrary recursive copying.
            b = src.read(rel, MAX_JSON)
            dst.write_once(rel, b)
            require(dst.read(rel, len(b), len(b)) == b, 'DESTINATION_MISMATCH')


def identical_trees(left: str, right: str, maximum: int) -> bool:
    with SafeTree(left) as a, SafeTree(right) as b:
        names = a.list_files(maximum)
        if names != b.list_files(maximum): return False
        for rel in sorted(names):
            if a.read(rel, MAX_JSON) != b.read(rel, MAX_JSON): return False
    return True


def remove_private_tree(private_root: str, relative: str) -> None:
    """Owned, unique generation/scratch deletion. Never follows a symlink."""
    require(relative.startswith(('generations/', 'scratch/', 'exports/')) and len(relative.split('/')) == 2, 'INVALID_RECLAIM_PATH')
    with SafeTree(private_root) as base, base.parent(relative) as (parent, name):
        def erase(fd: int) -> None:
            with os.scandir(fd) as it:
                entries = list(it)
            for entry in entries:
                st = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    cfd = os.open(entry.name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=fd)
                    try: erase(cfd)
                    finally: os.close(cfd)
                    os.rmdir(entry.name, dir_fd=fd)
                else:
                    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, 'UNSAFE_FILE_TYPE')
                    os.unlink(entry.name, dir_fd=fd)
            sync_fd(fd)
        try: fd = os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=parent)
        except FileNotFoundError: return
        try: erase(fd)
        finally: os.close(fd)
        os.rmdir(name, dir_fd=parent); sync_fd(parent)


class ClockPolicy:
    @staticmethod
    def snapshot() -> dict:
        if sys.platform == 'darwin':
            lib = ctypes.CDLL(None, use_errno=True)
            class Timebase(ctypes.Structure):
                _fields_ = [('numer', ctypes.c_uint32), ('denom', ctypes.c_uint32)]
            try:
                continuous = lib.mach_continuous_time
                continuous.argtypes = []; continuous.restype = ctypes.c_uint64
                timebase = lib.mach_timebase_info
                timebase.argtypes = [ctypes.POINTER(Timebase)]; timebase.restype = ctypes.c_int
                tb = Timebase()
                require(timebase(ctypes.byref(tb)) == 0 and tb.denom != 0, 'CLOCK_UNQUALIFIED', code=7)
                sysctl = lib.sysctlbyname
                sysctl.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
                sysctl.restype = ctypes.c_int
                buf = ctypes.create_string_buffer(128); n = ctypes.c_size_t(128)
                require(sysctl(b'kern.bootsessionuuid', buf, ctypes.byref(n), None, 0) == 0, 'CLOCK_UNQUALIFIED', code=7)
                boot = buf.value.decode('ascii').lower()
                require(bool(re.fullmatch(r'[0-9a-f-]{36}', boot)), 'CLOCK_UNQUALIFIED', code=7)
                ns = continuous() * tb.numer // tb.denom
            except (AttributeError, UnicodeError):
                raise CASError('CLOCK_UNQUALIFIED', code=7) from None
        elif sys.platform == 'linux' and hasattr(time, 'CLOCK_BOOTTIME'):
            boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        else:
            raise CASError('CLOCK_UNQUALIFIED', code=7)
        return dict(boot=boot, ns=ns, utc=utc_now())


def environment_record() -> dict:
    return dict(platform=sys.platform, architecture=platform.machine(), release=platform.release(),
                python=platform.python_version(), sqlite=sqlite3.sqlite_version,
                source_sha256=sha(Path(__file__).read_bytes()))


def map_exception(e: BaseException) -> CASError:
    if isinstance(e, CASError): return e
    if isinstance(e, FileNotFoundError): return CASError('PENDING_CONTENT', str(e)[:300], 3)
    if isinstance(e, PermissionError): return CASError('PERMISSION_DENIED', str(e)[:300], 6)
    if isinstance(e, OSError):
        if e.errno in (errno.ENOTSUP, errno.ENOSYS): return CASError('FILESYSTEM_CAPABILITY_UNSUPPORTED', str(e)[:300], 7)
        if e.errno in (errno.ENOSPC, errno.EDQUOT): return CASError('HOLD_RESOURCE', str(e)[:300], 8)
        if e.errno in (errno.ELOOP, errno.ENOTDIR): return CASError('UNSAFE_FILE_TYPE', str(e)[:300], 4)
        if e.errno == errno.EIO: return CASError('IO_FAILURE', str(e)[:300], 3)
        if e.errno in (errno.ETIMEDOUT, errno.EAGAIN, errno.ENETDOWN, errno.ENETUNREACH):
            return CASError('ACQUISITION_UNAVAILABLE', str(e)[:300], 3)
    return CASError('INTERNAL_CONTRACT_BREACH', type(e).__name__ + ': ' + str(e)[:300], 11)


def _worker_dispatch(kind: str, a: dict) -> dict:
    if a.get('binding') and a['binding'].get('exchange'):
        outer = a['binding']['exchange']
        with SafeTree(outer['path'], outer['identity']):
            pass  # Root continuity is separate from the nested intake inode.
    if kind == 'probe':
        with SafeTree(a['path']) as tree:
            return dict(identity=identity(os.fstat(tree.fd)), platform=sys.platform)
    if kind == 'prepare':
        return CASChunkManager(a['limits']).build_candidate(a['workspace'], a['sources'], a['contract'],
            a['producer_agent'], a['installation_id'], a['attempt_id'], a['created_at'], a['layout'])
    if kind in ('capture', 'verify', 'check'):
        v = MerkleVerifier(a['limits'])
        if a.get('binding'):
            b = a['binding']
            with SafeTree(b['path'], b['identity']) as intake:
                # The exact final leaf is resolved beneath the enrolled intake descriptor.
                with intake.parent('chunks/' + a['root']) as (fd, name):
                    leaf = os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=fd)
                    try: leaf_identity = identity(os.fstat(leaf))
                    finally: os.close(leaf)
            # verify_tree independently reopens and checks the observed identity.
            expected = leaf_identity
        else:
            expected = None
        return v.verify_tree(a['candidate'], a['root'], a['contract'],
            capture_to=a.get('workspace') if kind == 'capture' else None,
            expected_outputs=a.get('workspace') if kind == 'check' else None,
            approved_roots=a.get('approved_roots'), enforce_approval=a.get('enforce_approval', True),
            expected_identity=expected)
    if kind == 'publish':
        source = a['source']; root = a['root']; binding = a['binding']
        MerkleVerifier(a['limits']).verify_tree(source, root, a['contract'], enforce_approval=False)
        with SafeTree(binding['path'], binding['identity']) as intake:
            # chunks is created by enrollment, never recreated after mount disappearance.
            with SafeTree(Path(binding['path'])/'chunks', binding['chunks_identity']) as chunks:
                staging = '.staging.' + a['invocation_id']
                chunks.mkdir(staging)
                target = str(Path(chunks.root)/staging)
                copy_tree_exact(source, target, a['limits']['max_members'])
                MerkleVerifier(a['limits']).verify_tree(target, root, a['contract'], enforce_approval=False)
                try:
                    AtomicPublisher().rename(chunks, staging, chunks, root)
                except CASError as e:
                    if e.reason != 'OUTPUT_EXISTS': raise
                    final = str(Path(chunks.root)/root)
                    MerkleVerifier(a['limits']).verify_tree(final, root, a['contract'], enforce_approval=False)
                    require(identical_trees(source, final, a['limits']['max_members']), 'HASH_IDENTITY_INCIDENT', code=10)
                    # Staging inside Drive is deliberately not deleted as a "repair".
                    return dict(submission_dir=final, local_publication='EXISTING_IDENTICAL', staging_retained=staging)
                return dict(submission_dir=str(Path(chunks.root)/root), local_publication='LOCAL_PUBLISHED', staging_retained=None)
    if kind == 'export':
        source = a['source']; h = a['sha256']; length = a['size_bytes']
        root = a['output_root']; rel = a['output_rel']
        proof_path = a['proof_path']
        with SafeTree(root['path'], root['identity']) as dst, SafeTree(Path(source).parent) as src, SafeTree(Path(proof_path).parent) as proofs:
            proof = None
            try:
                proof = json_read(proofs.read(Path(proof_path).name, MAX_FRAME))
            except FileNotFoundError:
                pass
            if proof is not None:
                fields(proof, 'operation_id root_identity output_rel sha256 size_bytes staging_rel staging_identity')
                require(proof['operation_id'] == a['operation_id'] and proof['root_identity'] == root['identity']
                        and proof['output_rel'] == rel and proof['sha256'] == h and proof['size_bytes'] == length,
                        'INTENT_CONFLICT', code=5)
            with dst.parent(rel) as (fd, name):
                try: old = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError: old = None
            if old is not None:
                # Hash equality alone cannot claim an unrelated occupied output.
                require(proof is not None and identity(old) == proof['staging_identity'], 'OUTPUT_EXISTS', code=5)
                require(dst.file_hash(rel, length) == (h, length), 'OUTPUT_EXISTS', code=5)
                return dict(output_path=str(Path(root['path'])/rel), size_bytes=length,
                            content_sha256=h, observation='RECONCILED_OWN_INODE')
            if proof is None:
                temp_rel = rel + '.partial.' + a['invocation_id']
                total = 0; hasher = hashlib.sha256()
                with src.open_read(Path(source).name) as reader, dst.open_new(temp_rel) as writer:
                    while b := reader.read(1024*1024):
                        total += len(b); require(total <= length, 'LENGTH_MISMATCH')
                        hasher.update(b); writer.write(b)
                require(total == length and hasher.hexdigest() == h, 'DESTINATION_MISMATCH')
                require(dst.file_hash(temp_rel, length) == (h, length), 'DESTINATION_MISMATCH')
                with dst.open_read(temp_rel) as f: staged_identity = identity(os.fstat(f.fileno()))
                proof = dict(operation_id=a['operation_id'], root_identity=root['identity'], output_rel=rel,
                             sha256=h, size_bytes=length, staging_rel=temp_rel, staging_identity=staged_identity)
                # Persist the local pre-rename identity before exposing the final name.
                proofs.write_once(Path(proof_path).name, json_bytes(proof))
            else:
                temp_rel = proof['staging_rel']
                try:
                    with dst.open_read(temp_rel) as f:
                        require(identity(os.fstat(f.fileno())) == proof['staging_identity'], 'PUBLICATION_OUTCOME_UNKNOWN', code=9)
                except FileNotFoundError as e:
                    raise CASError('PUBLICATION_OUTCOME_UNKNOWN', 'Neither the owned staged inode nor final output is present', 9) from e
                require(dst.file_hash(temp_rel, length) == (h, length), 'DESTINATION_MISMATCH')
            AtomicPublisher().rename(dst, temp_rel, dst, rel)
            return dict(output_path=str(Path(root['path'])/rel), size_bytes=length, content_sha256=h, observation='CURRENT_BYTES')
    if kind == 'receipt_export':
        b = a['binding']; data = a['receipt'].encode('ascii'); h = sha(data)
        with SafeTree(b['path'], b['identity']) as intake:
            rel = 'receipts/' + h + '.json'; stage = 'receipts/.staging.' + a['invocation_id']
            intake.write_once(stage, data)
            require(intake.read(stage, len(data), len(data)) == data, 'DESTINATION_MISMATCH')
            try: AtomicPublisher().rename(intake, stage, intake, rel)
            except CASError as e:
                if e.reason != 'OUTPUT_EXISTS': raise
                require(intake.read(rel, len(data), len(data)) == data, 'SOURCE_CONFLICT', code=5)
            return dict(path=str(Path(b['path'])/rel), sha256=h)
    if kind == 'remove':
        remove_private_tree(a['private_root'], a['relative'])
        return {'removed': a['relative']}
    raise CASError('INVALID_WORKER_JOB')


def _worker_main() -> int:
    """Internal fixed-function subprocess endpoint; no executable names or pickle."""
    try:
        header = sys.stdin.buffer.readline(8)
        require(re.fullmatch(rb'[1-9][0-9]{0,5}\n', header) is not None, 'WORKER_PROTOCOL_ERROR')
        n = int(header); require(n <= MAX_FRAME, 'WORKER_PROTOCOL_ERROR')
        raw = sys.stdin.buffer.read(n)
        require(len(raw) == n and sys.stdin.buffer.read(1) == b'', 'WORKER_PROTOCOL_ERROR')
        request = json_read(raw, MAX_FRAME, 16)
        fields(request, 'protocol operation_id invocation_id operation_generation job_kind args')
        require(request['protocol'] == WORKER_PROTOCOL, 'WORKER_PROTOCOL_ERROR')
        uuid_value(request['operation_id']); uuid_value(request['invocation_id']); uint(request['operation_generation'])
        result = _worker_dispatch(request['job_kind'], request['args'])
        # Large reports are private owned files, not unbounded pipe output.
        report_path = request['args'].get('report_path')
        if report_path:
            data = json_bytes(result); require(len(data) <= MAX_JSON, 'REPORT_LIMIT')
            with SafeTree(Path(report_path).parent) as parent:
                parent.write_once(Path(report_path).name, data)
            result = dict(report_path=report_path, sha256=sha(data), size_bytes=len(data))
        response = dict(protocol=WORKER_PROTOCOL, operation_id=request['operation_id'],
            invocation_id=request['invocation_id'], operation_generation=request['operation_generation'],
            outcome='COMPLETE', result=result, error=None)
    except BaseException as e:
        error = map_exception(e)
        response = dict(protocol=WORKER_PROTOCOL, operation_id=locals().get('request', {}).get('operation_id'),
            invocation_id=locals().get('request', {}).get('invocation_id'),
            operation_generation=locals().get('request', {}).get('operation_generation'),
            outcome='FAILED', result=None, error=dict(reason=error.reason, message=error.message, code=error.code))
    data = json_bytes(response)
    if len(data) > MAX_FRAME: return 12
    sys.stdout.buffer.write(str(len(data)).encode('ascii') + b'\n' + data)
    sys.stdout.buffer.flush()
    return 0


@contextlib.contextmanager
def file_guard(path: str, timeout: float = 5.0, create: bool = False) -> Iterator[int]:
    flags = os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC
    if create: flags |= os.O_CREAT
    fd = os.open(path, flags, 0o600)
    end = time.monotonic() + timeout
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_nlink == 1, 'UNSAFE_LOCK_ANCHOR', code=10)
        while True:
            try: fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB); break
            except BlockingIOError:
                require(time.monotonic() < end, 'REGISTRY_CONTENDED', code=3)
                time.sleep(0.01)
        # No explicit LOCK_UN: inherited worker references must retain the lease
        # until the last actual holder closes, including after parent death.
        yield fd
    finally:
        os.close(fd)


class WorkerSupervisor:
    """Bounded fixed-function children; kernel-held capacity slots survive parent exit.

    A blocked/unreaped child retains its inherited capacity slot and operation
    guard. A replacement cannot bypass it by forgetting a PID. These are private
    local kernel locks, never synchronized locks or the authority DB guard.
    """
    def __init__(self, private_root: str, wait_ms: int = 900000):
        self.private_root = private_root
        self.wait_ms = wait_ms
        self.last_observation: dict = {}

    @contextlib.contextmanager
    def slot(self, kind: str) -> Iterator[int]:
        group = 'publication' if kind in ('publish', 'export', 'receipt_export') else 'acquisition'
        count = 1 if group == 'publication' else 2
        for i in range(count):
            try:
                ctx = file_guard(str(Path(self.private_root)/'locks'/f'{group}.{i}'), timeout=0)
                fd = ctx.__enter__()
            except CASError as e:
                if e.reason == 'REGISTRY_CONTENDED': continue
                raise
            try: yield fd
            finally: ctx.__exit__(None, None, None)
            return
        raise CASError('WORKER_CIRCUIT_OPEN', 'All bounded worker slots remain owned', 8)

    def run(self, kind: str, args: dict, operation_id: str | None = None,
            generation: int = 1, op_guard_fd: int | None = None,
            timeout_ms: int | None = None) -> dict:
        operation_id = operation_id or new_id(); invocation_id = new_id()
        args = dict(args, invocation_id=invocation_id)
        request = dict(protocol=WORKER_PROTOCOL, operation_id=operation_id,
                       invocation_id=invocation_id, operation_generation=generation, job_kind=kind, args=args)
        raw = json_bytes(request); require(len(raw) <= MAX_FRAME, 'WORKER_REQUEST_LIMIT', code=8)
        budget = min(self.wait_ms, timeout_ms or (300000 if kind in ('publish', 'export') else 120000)) / 1000
        with self.slot(kind) as slotfd:
            inherited = tuple(fd for fd in (slotfd, op_guard_fd) if fd is not None)
            child = subprocess.Popen([sys.executable, '-I', str(Path(__file__).resolve()), '--_worker'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True, pass_fds=inherited)
            assert child.stdin and child.stdout and child.stderr
            selector = selectors.DefaultSelector()
            payload = str(len(raw)).encode('ascii') + b'\n' + raw
            sent = 0; out = bytearray(); err = bytearray(); dropped = 0
            clock_start = ClockPolicy.snapshot()
            deadline_ns = clock_start['ns'] + int(budget * 1000000000)
            for f, event in ((child.stdin, selectors.EVENT_WRITE), (child.stdout, selectors.EVENT_READ), (child.stderr, selectors.EVENT_READ)):
                os.set_blocking(f.fileno(), False); selector.register(f, event)
            failure: CASError | None = None
            try:
                while selector.get_map() or child.poll() is None:
                    current_clock = ClockPolicy.snapshot()
                    if current_clock['boot'] != clock_start['boot'] or current_clock['ns'] >= deadline_ns:
                        failure = CASError('PUBLICATION_OUTCOME_UNKNOWN' if kind in ('publish','export','receipt_export') else 'ACQUISITION_TIMEOUT',
                                           'Worker deadline; output is not registered', 9 if kind in ('publish','export','receipt_export') else 3)
                        break
                    for key, _ in selector.select(min(0.05, max(0, (deadline_ns-current_clock['ns'])/1000000000))):
                        f = key.fileobj
                        if f is child.stdin:
                            try: n = os.write(f.fileno(), payload[sent:])
                            except BrokenPipeError: n = 0; sent = len(payload)
                            sent += n
                            if sent >= len(payload): selector.unregister(f); f.close()
                        else:
                            try: data = os.read(f.fileno(), 16384)
                            except BlockingIOError: continue
                            if not data: selector.unregister(f); f.close(); continue
                            if f is child.stdout:
                                out.extend(data)
                                require(len(out) <= MAX_FRAME+8, 'WORKER_OUTPUT_LIMIT')
                            else:
                                keep = min(len(data), 256*1024-len(err)); err.extend(data[:keep]); dropped += len(data)-keep
                if failure is None and ClockPolicy.snapshot()['ns'] >= deadline_ns:
                    failure = CASError('PUBLICATION_OUTCOME_UNKNOWN' if kind in ('publish','export','receipt_export') else 'ACQUISITION_TIMEOUT', 'Deadline elapsed before terminal worker validation', 9 if kind in ('publish','export','receipt_export') else 3)
                if failure:
                    if b'DATALESS_OBSERVED' in err:
                        failure.message += '; worker observed SF_DATALESS before acquisition'
                    raise failure
                require(child.returncode == 0, 'WORKER_SIGNAL' if child.returncode is not None and child.returncode < 0 else 'WORKER_FAILED',
                        f'Child return code {child.returncode}', 3)
                require(b'\n' in out, 'WORKER_PROTOCOL_ERROR')
                head, data = bytes(out).split(b'\n', 1)
                require(re.fullmatch(rb'[1-9][0-9]{0,5}', head) is not None and int(head) == len(data), 'WORKER_PROTOCOL_ERROR')
                result = json_read(data, MAX_FRAME)
                fields(result, 'protocol operation_id invocation_id operation_generation outcome result error')
                require(result['protocol'] == WORKER_PROTOCOL and result['operation_id'] == operation_id and result['invocation_id'] == invocation_id and result['operation_generation'] == generation, 'WORKER_PROTOCOL_ERROR')
                if result['outcome'] != 'COMPLETE':
                    e = result['error']; fields(e, 'reason message code')
                    raise CASError(e['reason'], e['message'], e['code'])
                value = result['result']
                if args.get('report_path'):
                    require(value['report_path'] == args['report_path'], 'WORKER_PROTOCOL_ERROR')
                    with SafeTree(Path(value['report_path']).parent) as t:
                        data = t.read(Path(value['report_path']).name, MAX_JSON, value['size_bytes'], value['sha256'])
                    value = json_read(data)
                return value
            finally:
                selector.close()
                if child.poll() is None:
                    child.kill()
                    try: child.wait(timeout=0.25)
                    except subprocess.TimeoutExpired: pass
                for stream in (child.stdin, child.stdout, child.stderr):
                    if not stream.closed: stream.close()
                self.last_observation = dict(invocation_id=invocation_id, pid=child.pid, returncode=child.poll(),
                    stderr=err.decode('utf-8', 'replace'), stderr_dropped=dropped, reaped=child.poll() is not None)


DDL = r'''
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE tasks (
 task_key TEXT PRIMARY KEY, contract TEXT NOT NULL, contract_sha256 TEXT NOT NULL,
 selection_policy TEXT NOT NULL CHECK(selection_policy IN ('EXACT_ROOT','ENROLLED_CANDIDATE')),
 lifecycle TEXT NOT NULL DEFAULT 'OPEN' CHECK(lifecycle IN ('OPEN','CLOSED','ACCEPTED')),
 fence INTEGER NOT NULL DEFAULT 1 CHECK(fence>0));
CREATE TABLE bindings (
 binding_id TEXT PRIMARY KEY, task_key TEXT NOT NULL REFERENCES tasks(task_key),
 path TEXT NOT NULL UNIQUE, identity_json TEXT NOT NULL, chunks_identity_json TEXT NOT NULL);
CREATE TABLE approvals (
 task_key TEXT NOT NULL REFERENCES tasks(task_key), root TEXT NOT NULL,
 version INTEGER NOT NULL CHECK(version>0), boot TEXT NOT NULL,
 deadline_ns INTEGER NOT NULL, expires_utc TEXT NOT NULL,
 PRIMARY KEY(task_key,root));
CREATE TABLE operations (
 operation_id TEXT PRIMARY KEY, command TEXT NOT NULL, intent TEXT NOT NULL,
 intent_sha256 TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'PENDING',
 phase TEXT NOT NULL DEFAULT 'NEW', generation INTEGER NOT NULL DEFAULT 0,
 attempts INTEGER NOT NULL DEFAULT 0, window_boot TEXT NOT NULL,
 window_start_ns INTEGER NOT NULL, root TEXT, generation_id TEXT,
 attempt_id TEXT NOT NULL, created_at_utc TEXT NOT NULL,
 result_json TEXT, error_json TEXT);
CREATE TABLE generations (
 generation_id TEXT PRIMARY KEY, relative_path TEXT NOT NULL UNIQUE,
 owner_operation TEXT NOT NULL REFERENCES operations(operation_id),
 root TEXT, state TEXT NOT NULL CHECK(state IN ('WRITING','AVAILABLE','CORRUPT','RETIRING','ABSENT')),
 accounted_bytes INTEGER NOT NULL DEFAULT 0 CHECK(accounted_bytes>=0),
 ordinal INTEGER NOT NULL UNIQUE);
CREATE TABLE pins (
 generation_id TEXT NOT NULL REFERENCES generations(generation_id),
 owner TEXT NOT NULL, kind TEXT NOT NULL,
 PRIMARY KEY(generation_id,owner,kind));
CREATE TABLE snapshots (
 generation_id TEXT PRIMARY KEY REFERENCES generations(generation_id),
 root TEXT NOT NULL, task_key TEXT NOT NULL REFERENCES tasks(task_key),
 summary_json TEXT NOT NULL, verification_json TEXT NOT NULL);
CREATE INDEX snapshots_root ON snapshots(root);
CREATE TABLE admission_requests (
 request_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 operation_id TEXT NOT NULL UNIQUE REFERENCES operations(operation_id),
 task_key TEXT NOT NULL REFERENCES tasks(task_key), root TEXT NOT NULL,
 generation_id TEXT NOT NULL REFERENCES snapshots(generation_id),
 fence INTEGER NOT NULL, approval_root TEXT NOT NULL, approval_version INTEGER NOT NULL,
 grant_boot TEXT NOT NULL, grant_deadline_ns INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('QUEUED','BLOCKED','REJECTED','DECIDED','UNKNOWN')),
 reason TEXT);
CREATE TABLE acceptances (
 decision_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 task_key TEXT NOT NULL UNIQUE REFERENCES tasks(task_key), root TEXT NOT NULL,
 operation_id TEXT NOT NULL UNIQUE REFERENCES operations(operation_id),
 generation_id TEXT NOT NULL REFERENCES snapshots(generation_id),
 request_sequence INTEGER NOT NULL REFERENCES admission_requests(request_sequence),
 receipt_bytes BLOB NOT NULL, receipt_sha256 TEXT NOT NULL UNIQUE,
 verification_bytes BLOB NOT NULL, qualified INTEGER NOT NULL CHECK(qualified IN (0,1)));
CREATE TABLE receipt_outbox (
 receipt_sha256 TEXT PRIMARY KEY REFERENCES acceptances(receipt_sha256),
 receipt_bytes BLOB NOT NULL, binding_id TEXT NOT NULL REFERENCES bindings(binding_id),
 state TEXT NOT NULL DEFAULT 'PENDING', attempts INTEGER NOT NULL DEFAULT 0);
CREATE TABLE exports (
 operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
 generation_id TEXT NOT NULL REFERENCES generations(generation_id),
 path TEXT NOT NULL, managed INTEGER NOT NULL, released INTEGER NOT NULL DEFAULT 0);
CREATE TABLE incidents (
 incident_id TEXT PRIMARY KEY, reason TEXT NOT NULL, root TEXT,
 generation_id TEXT, detail_json TEXT NOT NULL, created_at_utc TEXT NOT NULL);
CREATE TABLE qualifications (
 qualification_id TEXT PRIMARY KEY, record_json TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE audit (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL,
 detail_json TEXT NOT NULL, at_utc TEXT NOT NULL);
'''


class AuthorityRegistry:
    def __init__(self, config: dict, readonly: bool = False):
        self.cfg = config; self.private_root = config['private_root']; self.readonly = readonly
        self.db_path = str(Path(self.private_root)/'state.sqlite3')
        self.guard_path = str(Path(self.private_root)/'locks/authority.guard')
        try:
            with SafeTree(self.private_root, config['private_identity']) as p:
                for name, expected in (('state.sqlite3', config['database_identity']), ('locks/authority.guard', config['guard_identity'])):
                    with p.open_read(name) as f:
                        require(identity(os.fstat(f.fileno())) == expected, 'AUTHORITY_RECOVERY_REQUIRED', code=10)
            self.db = sqlite3.connect(Path(self.db_path).as_uri() + ('?mode=ro' if readonly else '?mode=rw'),
                uri=True, timeout=0.1, autocommit=True)
            self.db.row_factory = sqlite3.Row
            self.db.execute('PRAGMA foreign_keys=ON'); self.db.execute('PRAGMA mmap_size=0')
            self.db.execute('PRAGMA synchronous=EXTRA'); self.db.execute('PRAGMA fullfsync=ON')
            require(self.db.execute('PRAGMA journal_mode').fetchone()[0] == 'delete', 'DATABASE_PROFILE_MISMATCH', code=10)
            require(self.db.execute('PRAGMA foreign_keys').fetchone()[0] == 1 and self.db.execute('PRAGMA synchronous').fetchone()[0] == 3
                    and self.db.execute('PRAGMA mmap_size').fetchone()[0] == 0, 'DATABASE_PROFILE_MISMATCH', code=10)
            require(self.meta('store_id') == config['store_id'], 'AUTHORITY_RECOVERY_REQUIRED', code=10)
            require(self.meta('installation_id') == config['installation_id'], 'AUTHORITY_RECOVERY_REQUIRED', code=10)
        except (OSError, sqlite3.DatabaseError) as e:
            raise CASError('AUTHORITY_RECOVERY_REQUIRED', str(e)[:300], 10) from e

    def close(self) -> None: self.db.close()
    def __enter__(self) -> 'AuthorityRegistry': return self
    def __exit__(self, *args: Any) -> None: self.close()

    def meta(self, key: str) -> Any:
        r = self.db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
        require(r is not None, 'AUTHORITY_RECOVERY_REQUIRED', code=10)
        return json_read(r[0].encode())

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        require(not self.readonly, 'READ_ONLY_REGISTRY', code=6)
        require(self.meta('health') == 'HEALTHY', 'AUTHORITY_RECOVERY_REQUIRED', code=10)
        with file_guard(self.guard_path, timeout=5):
            end = time.monotonic()+5
            while True:
                try: self.db.execute('BEGIN IMMEDIATE'); break
                except sqlite3.OperationalError as e:
                    if 'locked' not in str(e).lower(): raise
                    require(time.monotonic() < end, 'REGISTRY_CONTENDED', code=3)
                    time.sleep(0.02)
            try:
                yield self.db
            except BaseException:
                if self.db.in_transaction: self.db.execute('ROLLBACK')
                raise
            else:
                try: self.db.execute('COMMIT')
                except sqlite3.DatabaseError as e:
                    # Never turn a possible commit into a fresh operation.
                    if self.db.in_transaction: self.db.execute('ROLLBACK')
                    raise CASError('COMMIT_OUTCOME_UNKNOWN', str(e)[:300], 9) from e

    def log(self, conn: sqlite3.Connection, action: str, detail: dict) -> None:
        conn.execute('INSERT INTO audit(action,detail_json,at_utc) VALUES(?,?,?)', (action,json_bytes(detail).decode(),utc_now()))

    def task(self, key: str) -> sqlite3.Row:
        r = self.db.execute('SELECT * FROM tasks WHERE task_key=?', (key,)).fetchone()
        require(r is not None, 'TASK_BINDING_REQUIRED', code=7)
        return r

    def binding(self, path: str | None = None, key: str | None = None) -> dict:
        if path:
            rows = self.db.execute('SELECT * FROM bindings WHERE path=?', (normalized_absolute(path),)).fetchall()
        elif key:
            rows = self.db.execute('SELECT * FROM bindings WHERE task_key=?', (key,)).fetchall()
        else:
            rows = self.db.execute('SELECT * FROM bindings WHERE binding_id=?', (self.meta('default_binding'),)).fetchall()
        require(len(rows) == 1, 'TASK_BINDING_REQUIRED' if not rows else 'TASK_BINDING_AMBIGUOUS', code=7)
        r = rows[0]
        return dict(binding_id=r['binding_id'], task_key=r['task_key'], path=r['path'],
                    identity=json_read(r['identity_json'].encode()), chunks_identity=json_read(r['chunks_identity_json'].encode()),
                    exchange=dict(path=self.cfg['exchange_root'], identity=self.cfg['exchange_identity']))

    def for_leaf(self, leaf: str) -> tuple[dict, str]:
        leaf = normalized_absolute(leaf)
        root = digest(Path(leaf).name)
        require(Path(leaf).parent.name == 'chunks', 'INVALID_DROPZONE_LEAF')
        return self.binding(str(Path(leaf).parent.parent)), root

    def approved_roots(self, key: str) -> list[str] | None:
        task = self.task(key)
        if task['selection_policy'] == 'ENROLLED_CANDIDATE': return None
        return [r[0] for r in self.db.execute('SELECT root FROM approvals WHERE task_key=? AND root<>?', (key,'*'))]

    def approval(self, conn: sqlite3.Connection, key: str, root: str, now: dict) -> sqlite3.Row:
        t = conn.execute('SELECT * FROM tasks WHERE task_key=?', (key,)).fetchone()
        require(t is not None, 'TASK_BINDING_REQUIRED', code=7)
        target = root if t['selection_policy'] == 'EXACT_ROOT' else '*'
        r = conn.execute('SELECT * FROM approvals WHERE task_key=? AND root=?', (key,target)).fetchone()
        require(r is not None, 'APPROVAL_REQUIRED', code=6)
        require(r['boot'] == now['boot'] and now['ns'] < r['deadline_ns'] and now['utc'] < r['expires_utc'], 'APPROVAL_EXPIRED', code=6)
        return r

    def qualified(self) -> bool:
        if self.cfg['mode'] == 'LAB_CANDIDATE': return False
        require(sys.platform == 'darwin' and platform.machine() == 'arm64', 'VERIFICATION_UNQUALIFIED', code=7)
        active = self.db.execute('SELECT record_json FROM qualifications WHERE active=1 ORDER BY rowid DESC LIMIT 1').fetchone()
        require(active is not None, 'VERIFICATION_UNQUALIFIED', code=7)
        record = json_read(active[0].encode())
        env = environment_record() | {'config_sha256': sha(json_bytes(self.cfg))}
        require(record['environment'] == env, 'VERIFICATION_UNQUALIFIED', 'Qualification does not match this code/configuration/runtime', 7)
        return True

    def open_operation(self, operation_id: str, command: str, intent: dict) -> sqlite3.Row:
        uuid_value(operation_id); now = ClockPolicy.snapshot(); raw = json_bytes(intent).decode()
        with self.transaction() as c:
            old = c.execute('SELECT * FROM operations WHERE operation_id=?', (operation_id,)).fetchone()
            if old:
                require(old['command'] == command and old['intent'] == raw, 'INTENT_CONFLICT', code=5)
            else:
                c.execute('INSERT INTO operations(operation_id,command,intent,intent_sha256,window_boot,window_start_ns,attempt_id,created_at_utc) VALUES(?,?,?,?,?,?,?,?)',
                    (operation_id,command,raw,sha(raw.encode()),now['boot'],now['ns'],new_id(),utc_now()))
        return self.operation(operation_id)

    def operation(self, operation_id: str) -> sqlite3.Row:
        r = self.db.execute('SELECT * FROM operations WHERE operation_id=?', (operation_id,)).fetchone()
        require(r is not None, 'OPERATION_NOT_FOUND', code=7)
        return r

    def dispatch(self, operation_id: str) -> int:
        now = ClockPolicy.snapshot()
        blocked = False
        with self.transaction() as c:
            r = c.execute('SELECT * FROM operations WHERE operation_id=?', (operation_id,)).fetchone()
            limits = self.cfg['limits']
            blocked = (r['window_boot'] != now['boot'] or r['attempts'] >= limits['max_dispatches']
                or now['ns'] - r['window_start_ns'] >= limits['retry_window_ms']*1000000)
            if blocked:
                c.execute("UPDATE operations SET state='HOLD_RETRY' WHERE operation_id=?", (operation_id,))
            else:
                c.execute("UPDATE operations SET generation=generation+1,attempts=attempts+1,state='PENDING' WHERE operation_id=?", (operation_id,))
        require(not blocked, 'HOLD_RETRY', 'Explicitly authorize a new retry window; restart does not reset it', 3)
        return self.operation(operation_id)['generation']

    def reserve_generation(self, operation_id: str) -> str:
        gid = new_id(); rel = 'generations/' + gid
        with self.transaction() as c:
            ordinal = c.execute('SELECT COALESCE(MAX(ordinal),0)+1 FROM generations').fetchone()[0]
            c.execute('INSERT INTO generations(generation_id,relative_path,owner_operation,state,ordinal) VALUES(?,?,?,?,?)',
                      (gid,rel,operation_id,'WRITING',ordinal))
            c.execute('INSERT INTO pins VALUES(?,?,?)', (gid,operation_id,'CONSTRUCTION'))
        with SafeTree(self.private_root) as t: t.mkdir(rel)
        return gid

    def register_snapshot(self, operation_id: str, gid: str, summary: dict, qualified: bool) -> dict:
        m = summary['manifest']; key = key_text(m)
        vr = node('verification_receipt' if qualified else 'qualification_verification',
            receipt_id=new_id(), store_id=m['store_id'], submission_sha256=summary['root'],
            manifest_size_bytes=summary['manifest_size_bytes'], dataset=m['dataset'],
            contract_sha256=m['contract_sha256'], observer_id=self.cfg['installation_id'],
            policy_id='gdoe-verify-0.5.0', verified_at_utc=summary['verified_at_utc'], snapshot_id=gid,
            totals=m['totals'], scope='FULL_CLOSURE', contract_result='MATCH',
            durability_profile='PROCESS_CRASH_QUALIFIED' if qualified else 'UNQUALIFIED',
            remote_evidence='NOT_ASSERTED', semantic_review='NOT_ASSESSED')
        with self.transaction() as c:
            require(c.execute('SELECT state FROM generations WHERE generation_id=?',(gid,)).fetchone()[0] == 'WRITING', 'GENERATION_STATE_CONFLICT', code=10)
            c.execute("UPDATE generations SET root=?,state='AVAILABLE',accounted_bytes=? WHERE generation_id=?", (summary['root'],summary['snapshot_bytes'],gid))
            c.execute('INSERT INTO snapshots VALUES(?,?,?,?,?)', (gid,summary['root'],key,json_bytes(summary).decode(),wire_bytes(vr).decode()))
            c.execute("UPDATE pins SET kind='PREPARATION' WHERE generation_id=? AND owner=? AND kind='CONSTRUCTION'", (gid,operation_id))
            c.execute("UPDATE operations SET generation_id=?,root=?,phase='CAPTURED' WHERE operation_id=?", (gid,summary['root'],operation_id))
        return vr

    def finish(self, operation_id: str, result: dict, phase: str = 'COMPLETE') -> None:
        with self.transaction() as c:
            c.execute("UPDATE operations SET state='DONE',phase=?,result_json=?,error_json=NULL WHERE operation_id=?", (phase,json_bytes(result).decode(),operation_id))

    def record_error(self, operation_id: str, e: CASError) -> None:
        state = 'UNKNOWN' if e.code == 9 else 'HOLD_RESOURCE' if e.code == 8 else 'HOLD_RETRY' if e.code == 3 else 'BLOCKED' if e.code in (6,7,10) else 'REJECTED'
        with self.transaction() as c:
            # An error delivering a committed decision cannot undo that decision.
            c.execute("UPDATE operations SET state=?,error_json=? WHERE operation_id=? AND state<>'DONE'", (state,json_bytes(dict(reason=e.reason,message=e.message,code=e.code)).decode(),operation_id))
            if e.code == 10:
                c.execute('INSERT INTO incidents VALUES(?,?,?,?,?,?)', (new_id(),e.reason,None,None,json_bytes(dict(operation_id=operation_id,message=e.message)).decode(),utc_now()))

    def active_snapshot(self, root: str) -> sqlite3.Row:
        r = self.db.execute("SELECT s.*,g.relative_path,g.state,g.accounted_bytes FROM snapshots s JOIN generations g USING(generation_id) WHERE s.root=? AND g.state='AVAILABLE' AND (EXISTS(SELECT 1 FROM operations o WHERE o.operation_id=g.owner_operation AND o.command='put') OR EXISTS(SELECT 1 FROM acceptances a WHERE a.root=s.root)) ORDER BY g.ordinal LIMIT 1", (root,)).fetchone()
        require(r is not None, 'ROOT_NOT_REGISTERED', 'get requires an own-prepared or accepted registered root', 7)
        # This build enrolls one read domain per store; no cross-store lookup.
        require(self.db.execute('SELECT 1 FROM pins WHERE generation_id=?', (r['generation_id'],)).fetchone() is not None, 'SNAPSHOT_NOT_PROTECTED', code=10)
        return r


def load_config(path: str | Path) -> dict:
    path = normalized_absolute(path)
    try:
        with SafeTree(Path(path).parent) as p:
            data = p.read(Path(path).name, 1024*1024)
    except OSError as e:
        raise CASError('CONFIGURATION_REQUIRED', str(e)[:200], 7) from e
    c = json_read(data, 1024*1024, 12)
    fields(c, 'version store_id installation_id authority_id role mode private_root private_identity database_identity guard_identity exchange_root exchange_identity source_roots export_roots limits')
    require(c['version'] == 1 and c['role'] in ('authority','producer') and c['mode'] in ('LAB_CANDIDATE','PRODUCTION'), 'INVALID_CONFIGURATION', code=7)
    for k in ('store_id','installation_id','authority_id'): uuid_value(c[k])
    require(set(c['limits']) == set(DEFAULT_LIMITS), 'INVALID_CONFIGURATION', code=7)
    for v in c['limits'].values(): uint(v)
    require(c['limits']['reserve_percent'] <= 100 and 1 <= c['limits']['job_timeout_ms'] <= 900000 and 1 <= c['limits']['publish_timeout_ms'] <= 900000
            and c['limits']['max_dispatches'] >= 1, 'INVALID_CONFIGURATION', code=7)
    for k in ('private_root','exchange_root'): require(normalized_absolute(c[k]) == c[k], 'INVALID_CONFIGURATION', code=7)
    for k in ('private_identity','database_identity','guard_identity','exchange_identity'):
        fields(c[k], 'dev ino')
        for v in c[k].values(): uint(v)
    for k in ('source_roots','export_roots'):
        require(type(c[k]) is list, 'INVALID_CONFIGURATION', code=7)
        for root in c[k]:
            fields(root, 'path identity'); fields(root['identity'], 'dev ino')
            require(normalized_absolute(root['path']) == root['path'], 'INVALID_CONFIGURATION', code=7)
    return c


def enroll_store(private_root: str, exchange_root: str, source_roots: list[str],
                 export_roots: list[str] | None = None, mode: str = 'LAB_CANDIDATE',
                 role: str = 'authority', limits: dict | None = None) -> str:
    """EXPLICIT administrative creation of a NEW store. Never called by a data verb.

    Use disposable roots for LAB_CANDIDATE. PRODUCTION remains closed until an
    independent qualification record is installed. Resolving trusted admin paths
    here handles macOS /var -> /private/var; data operands never auto-resolve links.
    """
    require(mode in ('LAB_CANDIDATE','PRODUCTION') and role in ('authority','producer'), 'INVALID_CONFIGURATION')
    private = str(Path(private_root).expanduser().resolve())
    require(not any(x in (private+'/').lower() for x in ('/library/cloudstorage/','/library/mobile documents/')), 'PRIVATE_ROOT_IS_KNOWN_SYNC_LOCATION', code=7)
    exchange = str(Path(exchange_root).expanduser().resolve(strict=True))
    require(os.path.commonpath([private,exchange]) not in (private,exchange), 'ROOTS_OVERLAP')
    def enrolled(path: str) -> dict:
        p = str(Path(path).expanduser().resolve(strict=True))
        with SafeTree(p) as tree: return dict(path=p, identity=identity(os.fstat(tree.fd)))
    sources = [enrolled(x) for x in source_roots]
    exports = [enrolled(x) for x in (export_roots or [])]
    for e in exports:
        require(os.path.commonpath([e['path'],exchange]) not in (exchange,e['path']), 'ROOTS_OVERLAP')
        require(os.path.commonpath([e['path'],private]) not in (private,e['path']), 'ROOTS_OVERLAP')
    require(not Path(private).exists(), 'AUTHORITY_ALREADY_EXISTS', code=5)
    Path(private).mkdir(mode=0o700, parents=False)
    for name in ('locks','generations','scratch','exports'):
        Path(private,name).mkdir(mode=0o700)
    for name in ('authority.guard','acquisition.0','acquisition.1','publication.0'):
        with open(Path(private,'locks',name), 'xb'): pass
    sid, iid, aid = new_id(),new_id(),new_id()
    db = sqlite3.connect(str(Path(private,'state.sqlite3')),autocommit=True)
    try:
        db.execute('PRAGMA journal_mode=DELETE'); db.execute('PRAGMA synchronous=EXTRA')
        db.execute('PRAGMA foreign_keys=ON'); db.execute('PRAGMA fullfsync=ON'); db.execute('PRAGMA mmap_size=0')
        db.executescript('BEGIN IMMEDIATE;\n' + DDL + '\nCOMMIT;')
        db.execute('BEGIN IMMEDIATE')
        for k,v in dict(store_id=sid,installation_id=iid,authority_id=aid,authority_epoch=1,health='HEALTHY',default_binding=None).items():
            db.execute('INSERT INTO meta VALUES(?,?)',(k,json_bytes(v).decode()))
        db.execute('COMMIT')
    finally: db.close()
    with SafeTree(private) as p: sync_fd(p.fd)
    cfg = dict(version=1,store_id=sid,installation_id=iid,authority_id=aid,role=role,mode=mode,
        private_root=private,private_identity=identity(os.stat(private)),
        database_identity=identity(os.stat(Path(private,'state.sqlite3'))),
        guard_identity=identity(os.stat(Path(private,'locks/authority.guard'))),
        exchange_root=exchange,exchange_identity=enrolled(exchange)['identity'],
        source_roots=sources,export_roots=exports,limits=dict(DEFAULT_LIMITS,**(limits or {})))
    with SafeTree(private) as p: p.write_once('config.json',json_bytes(cfg))
    return str(Path(private,'config.json'))


def enroll_task(config_path: str, intake: str, contract: dict, selection_policy: str = 'EXACT_ROOT') -> str:
    """Administrative intake creation is intentional; public commands never do it."""
    cfg = load_config(config_path); validate_contract(contract)
    require(contract['store_id'] == cfg['store_id'] and selection_policy in ('EXACT_ROOT','ENROLLED_CANDIDATE'), 'INVALID_CONTRACT')
    intake = normalized_absolute(intake); relative_under(intake,cfg['exchange_root'])
    with SafeTree(cfg['exchange_root'],cfg['exchange_identity']) as exchange:
        rel = relative_under(intake,exchange.root)
        require(rel != '.', 'INTAKE_MUST_BE_CHILD')
        exchange.mkdir(rel)
    with SafeTree(intake) as t:
        t.mkdir('chunks'); t.mkdir('receipts'); root_id=identity(os.fstat(t.fd))
    with SafeTree(Path(intake)/'chunks') as t: chunks_id=identity(os.fstat(t.fd))
    binding_id=new_id(); raw=wire_bytes(contract).decode(); key=key_text(contract)
    with AuthorityRegistry(cfg) as reg, reg.transaction() as c:
        c.execute('INSERT INTO tasks(task_key,contract,contract_sha256,selection_policy) VALUES(?,?,?,?)',(key,raw,sha(raw.encode()),selection_policy))
        c.execute('INSERT INTO bindings VALUES(?,?,?,?,?)',(binding_id,key,intake,json_bytes(root_id).decode(),json_bytes(chunks_id).decode()))
        if reg.meta('default_binding') is None:
            c.execute('UPDATE meta SET value=? WHERE key=?',(json_bytes(binding_id).decode(),'default_binding'))
        reg.log(c,'ENROLL_TASK',dict(task_key=task_key(contract),binding_id=binding_id))
    return binding_id


def approve_candidate(config_path: str, root: str, contract: dict, lifetime_seconds: int = 3600) -> None:
    cfg=load_config(config_path); key=key_text(contract); now=ClockPolicy.snapshot()
    require(root == '*' or HEX.fullmatch(root) is not None,'INVALID_HASH'); uint(lifetime_seconds,86400*30,1)
    expiry=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=lifetime_seconds)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    with AuthorityRegistry(cfg) as reg, reg.transaction() as c:
        t=reg.task(key)
        require((root == '*') == (t['selection_policy']=='ENROLLED_CANDIDATE'),'APPROVAL_POLICY_MISMATCH',code=6)
        old=c.execute('SELECT version FROM approvals WHERE task_key=? AND root=?',(key,root)).fetchone()
        c.execute('INSERT OR REPLACE INTO approvals VALUES(?,?,?,?,?,?)',(key,root,(old[0]+1 if old else 1),now['boot'],now['ns']+lifetime_seconds*10**9,expiry))
        reg.log(c,'APPROVE',dict(task_key=task_key(contract),root=root,expires_utc=expiry))


def record_qualification(config_path: str, evidence_record: dict) -> None:
    """Trusted administrative act, never called by tests or the public data plane.

    This does not execute or independently validate claimed tests. The operator
    must verify the externally controlled evidence before installing the record.
    """
    cfg=load_config(config_path)
    fields(evidence_record,'qualification_id environment evidence_sha256 approved_by mandatory_suites')
    uuid_value(evidence_record['qualification_id']); digest(evidence_record['evidence_sha256']); label(evidence_record['approved_by'])
    require(sys.platform == 'darwin' and platform.machine() == 'arm64','VERIFICATION_UNQUALIFIED',code=7)
    require(evidence_record['environment'] == environment_record() | {'config_sha256':sha(json_bytes(cfg))},'VERIFICATION_UNQUALIFIED',code=7)
    require(evidence_record['mandatory_suites'] == {f'AT-{i:02d}':'PASS' for i in range(1,33)},'VERIFICATION_UNQUALIFIED',
            'Full qualification is deliberately unavailable from the selected subset tests',7)
    with AuthorityRegistry(cfg) as reg, reg.transaction() as c:
        c.execute('UPDATE qualifications SET active=0')
        c.execute('INSERT INTO qualifications VALUES(?,?,1)',(evidence_record['qualification_id'],json_bytes(evidence_record).decode()))
        reg.log(c,'INSTALL_EXTERNAL_QUALIFICATION',dict(qualification_id=evidence_record['qualification_id']))


def open_retry_window(config_path: str, operation_id: str, reason: str) -> None:
    cfg=load_config(config_path); uuid_value(operation_id); require(bool(reason),'REASON_REQUIRED')
    now=ClockPolicy.snapshot()
    with AuthorityRegistry(cfg) as reg, reg.transaction() as c:
        reg.operation(operation_id)
        c.execute("UPDATE operations SET attempts=0,window_boot=?,window_start_ns=?,state='PENDING' WHERE operation_id=? AND state<>'DONE'",(now['boot'],now['ns'],operation_id))
        reg.log(c,'OPEN_RETRY_WINDOW',dict(operation_id=operation_id,reason=reason[:300]))


def enter_recovery(config_path: str, reason: str) -> None:
    cfg=load_config(config_path)
    with AuthorityRegistry(cfg) as reg, reg.transaction() as c:
        c.execute("UPDATE meta SET value=? WHERE key='health'",(json_bytes('RECOVERY_REQUIRED').decode(),))
        reg.log(c,'ENTER_RECOVERY',dict(reason=reason[:300]))


class DropzoneAdmissionBroker:
    def __init__(self, registry: AuthorityRegistry, barrier: Callable[[str, dict], None] | None = None):
        self.reg = registry
        self.barrier = barrier or (lambda event, detail: None)

    def _result(self, acceptance: sqlite3.Row, request_sequence: int | None = None) -> dict:
        receipt = wire_read(bytes(acceptance['receipt_bytes']))
        return dict(task_key=json_read(acceptance['task_key'].encode()), root=acceptance['root'],
                    request_sequence=request_sequence if request_sequence is not None else acceptance['request_sequence'],
                    decision_sequence=acceptance['decision_sequence'], acceptance_receipt=receipt,
                    acceptance_receipt_sha256=acceptance['receipt_sha256'],
                    original_operation_id=acceptance['operation_id'], receipt_export='PENDING',
                    qualification='PROCESS_CRASH_QUALIFIED' if acceptance['qualified'] else 'LAB_CANDIDATE_UNQUALIFIED',
                    remote_evidence='NOT_ASSERTED')

    def existing(self, key: str, root: str) -> dict | None:
        r = self.reg.db.execute('SELECT * FROM acceptances WHERE task_key=?',(key,)).fetchone()
        if r is None: return None
        require(r['root'] == root,'TASK_ALREADY_ACCEPTED',code=5)
        return self._result(r)

    def request_admission(self, operation_id: str, key: str, root: str, gid: str) -> int:
        require(self.reg.cfg['role'] == 'authority','AUTHORITY_LOCAL_ONLY',code=6)
        now=ClockPolicy.snapshot()
        with self.reg.transaction() as c:
            old=c.execute('SELECT * FROM admission_requests WHERE operation_id=?',(operation_id,)).fetchone()
            if old:
                require(old['task_key']==key and old['root']==root,'INTENT_CONFLICT',code=5)
                return old['request_sequence']
            op=c.execute('SELECT root FROM operations WHERE operation_id=?',(operation_id,)).fetchone()
            require(op and op['root']==root,'INTENT_CONFLICT',code=5)
            # A competitor may commit between the caller's optimistic lookup
            # and this serialized registration. Classify that race here as well.
            accepted=c.execute('SELECT * FROM acceptances WHERE task_key=?',(key,)).fetchone()
            if accepted is not None:
                require(accepted['root']==root,'TASK_ALREADY_ACCEPTED',code=5)
                result=self._result(accepted)
                c.execute("UPDATE operations SET state='DONE',result_json=?,error_json=NULL WHERE operation_id=?",(json_bytes(result).decode(),operation_id))
                return accepted['request_sequence']
            t=c.execute('SELECT * FROM tasks WHERE task_key=?',(key,)).fetchone()
            require(t and t['lifecycle']=='OPEN','TASK_NOT_OPEN',code=6)
            approval=self.reg.approval(c,key,root,now)
            snap=c.execute("SELECT s.root,s.task_key,g.state FROM snapshots s JOIN generations g USING(generation_id) WHERE s.generation_id=?",(gid,)).fetchone()
            require(snap and snap['root']==root and snap['task_key']==key and snap['state']=='AVAILABLE','SNAPSHOT_NOT_PROTECTED',code=10)
            require(c.execute('SELECT 1 FROM pins WHERE generation_id=?',(gid,)).fetchone() is not None,'SNAPSHOT_NOT_PROTECTED',code=10)
            require(c.execute('SELECT 1 FROM incidents WHERE root=? OR reason=?',(root,'HASH_IDENTITY_INCIDENT')).fetchone() is None,'HASH_IDENTITY_INCIDENT',code=10)
            q=c.execute("INSERT INTO admission_requests(operation_id,task_key,root,generation_id,fence,approval_root,approval_version,grant_boot,grant_deadline_ns,state) VALUES(?,?,?,?,?,?,?,?,?,'QUEUED')",
                (operation_id,key,root,gid,t['fence'],approval['root'],approval['version'],now['boot'],min(now['ns']+120*10**9,approval['deadline_ns']))).lastrowid
            self.reg.log(c,'REQUEST_ADMISSION',dict(operation_id=operation_id,request_sequence=q,root=root))
            return q

    def advance_admission_queue(self, maximum: int = 128) -> None:
        qualified=self.reg.qualified()
        for _ in range(maximum):
            now=ClockPolicy.snapshot()
            with self.reg.transaction() as c:
                r=c.execute("SELECT * FROM admission_requests WHERE state IN ('QUEUED','UNKNOWN') ORDER BY request_sequence LIMIT 1").fetchone()
                if r is None: return
                if r['state']=='UNKNOWN': raise CASError('COMMIT_OUTCOME_UNKNOWN','Earlier request is unresolved',9)
                q=r['request_sequence']; o=r['operation_id']; key=r['task_key']; root=r['root']; gid=r['generation_id']
                existing=c.execute('SELECT * FROM acceptances WHERE task_key=?',(key,)).fetchone()
                if existing:
                    if existing['root']==root:
                        result=self._result(existing,q)
                        c.execute("UPDATE operations SET state='DONE',result_json=?,error_json=NULL WHERE operation_id=?",(json_bytes(result).decode(),o))
                        c.execute("UPDATE admission_requests SET state='DECIDED',reason='EXISTING_DECISION' WHERE request_sequence=?",(q,))
                    else:
                        c.execute("UPDATE admission_requests SET state='REJECTED',reason='TASK_ALREADY_ACCEPTED' WHERE request_sequence=?",(q,))
                        c.execute("UPDATE operations SET state='REJECTED',error_json=? WHERE operation_id=?",(json_bytes(dict(reason='TASK_ALREADY_ACCEPTED',message='Another root owns unchanged task key',code=5)).decode(),o))
                    continue
                try:
                    t=c.execute('SELECT * FROM tasks WHERE task_key=?',(key,)).fetchone()
                    require(t['lifecycle']=='OPEN','TASK_NOT_OPEN',code=6)
                    require(t['fence']==r['fence'],'STALE_FENCE',code=6)
                    require(now['boot']==r['grant_boot'] and now['ns']<r['grant_deadline_ns'],'STALE_FENCE',code=6)
                    approval=self.reg.approval(c,key,root,now)
                    require(approval['version']==r['approval_version'] and approval['root']==r['approval_root'],'APPROVAL_CHANGED',code=6)
                    snap=c.execute('SELECT s.*,g.state FROM snapshots s JOIN generations g USING(generation_id) WHERE generation_id=?',(gid,)).fetchone()
                    require(snap and snap['state']=='AVAILABLE' and snap['root']==root,'SNAPSHOT_NOT_PROTECTED',code=10)
                    require(c.execute('SELECT 1 FROM pins WHERE generation_id=?',(gid,)).fetchone() is not None,'SNAPSHOT_NOT_PROTECTED',code=10)
                    require(c.execute('SELECT 1 FROM incidents WHERE root=? OR reason=?',(root,'HASH_IDENTITY_INCIDENT')).fetchone() is None,'HASH_IDENTITY_INCIDENT',code=10)
                    vr=wire_read(snap['verification_json'].encode())
                    require(vr['kind']==('verification_receipt' if qualified else 'qualification_verification'),'VERIFICATION_UNQUALIFIED',code=7)
                except CASError as e:
                    if e.code in (9,10): raise
                    c.execute("UPDATE admission_requests SET state='BLOCKED',reason=? WHERE request_sequence=?",(e.reason,q))
                    c.execute("UPDATE operations SET state='BLOCKED',error_json=? WHERE operation_id=?",(json_bytes(dict(reason=e.reason,message=e.message,code=e.code)).decode(),o))
                    continue
                vbytes=snap['verification_json'].encode('ascii')
                a=c.execute('INSERT INTO acceptances(task_key,root,operation_id,generation_id,request_sequence,receipt_bytes,receipt_sha256,verification_bytes,qualified) VALUES(?,?,?,?,?,?,?,?,?)',
                    (key,root,o,gid,q,b'',new_id(),vbytes,int(qualified))).lastrowid
                k=json_read(key.encode())
                receipt=node('acceptance_receipt' if qualified else 'qualification_acceptance', receipt_id=new_id(),operation_id=o,
                    **k,contract_sha256=t['contract_sha256'],submission_sha256=root,verification_receipt_sha256=sha(vbytes),
                    authority_id=self.reg.cfg['authority_id'],authority_epoch=self.reg.meta('authority_epoch'),
                    fence_epoch=t['fence'],decision_sequence=a,accepted_at_utc=now['utc'],
                    state='ACCEPTED_LOCAL' if qualified else 'ACCEPTED_LAB_CANDIDATE',semantic_review='NOT_ASSESSED')
                raw=wire_bytes(receipt); rh=sha(raw)
                c.execute('UPDATE acceptances SET receipt_bytes=?,receipt_sha256=? WHERE decision_sequence=?',(raw,rh,a))
                c.execute('INSERT OR IGNORE INTO pins VALUES(?,?,?)',(gid,key,'ACCEPTANCE_RETENTION'))
                c.execute("DELETE FROM pins WHERE generation_id=? AND owner=? AND kind='PREPARATION'",(gid,o))
                c.execute("UPDATE tasks SET lifecycle='ACCEPTED' WHERE task_key=?",(key,))
                c.execute("UPDATE admission_requests SET state='DECIDED',reason='ACCEPTED_LOCAL' WHERE request_sequence=?",(q,))
                binding=c.execute('SELECT binding_id FROM bindings WHERE task_key=?',(key,)).fetchone()
                c.execute('INSERT INTO receipt_outbox(receipt_sha256,receipt_bytes,binding_id) VALUES(?,?,?)',(rh,raw,binding[0]))
                accepted=c.execute('SELECT * FROM acceptances WHERE decision_sequence=?',(a,)).fetchone()
                result=self._result(accepted,q)
                c.execute("UPDATE operations SET state='DONE',phase='COMPLETE',result_json=?,error_json=NULL WHERE operation_id=?",(json_bytes(result).decode(),o))
                self.reg.log(c,'ACCEPT',dict(task_key=k,root=root,operation_id=o,request_sequence=q,decision_sequence=a))
            # Test-only Python callback; never reachable as a CLI/worker option.
            self.barrier('decision-committed-before-reply', dict(operation_id=o, decision_sequence=a))

    def result(self, operation_id: str) -> dict:
        op=self.reg.operation(operation_id)
        if op['state']=='DONE': return json_read(op['result_json'].encode())
        if op['error_json']:
            e=json_read(op['error_json'].encode()); raise CASError(e['reason'],e['message'],e['code'])
        raise CASError('PENDING_ADMISSION',code=3)


class LocalCacheEvictor:
    def __init__(self, registry: AuthorityRegistry, supervisor: WorkerSupervisor):
        self.reg=registry; self.supervisor=supervisor

    def plan(self, target_bytes: int) -> dict:
        uint(target_bytes)
        rows=self.reg.db.execute("SELECT g.*,EXISTS(SELECT 1 FROM pins p WHERE p.generation_id=g.generation_id) AS protected FROM generations g WHERE state<>'ABSENT' ORDER BY ordinal,generation_id").fetchall()
        before=sum(r['accounted_bytes'] for r in rows)
        floor=sum(r['accounted_bytes'] for r in rows if r['protected'] or r['state']!='AVAILABLE')
        candidates=[]; projected=before
        for r in rows:
            if projected<=target_bytes: break
            if not r['protected'] and r['state']=='AVAILABLE':
                candidates.append(dict(generation_id=r['generation_id'],relative_path=r['relative_path'],accounted_bytes=r['accounted_bytes']))
                projected-=r['accounted_bytes']
        unknown=sum(r['state'] in ('WRITING','RETIRING') for r in rows)
        return dict(target_bytes=target_bytes,accounted_before_bytes=before,protected_floor_bytes=floor,
                    candidates=candidates,target_met_now=before<=target_bytes and unknown==0,
                    target_would_be_met=projected<=target_bytes and unknown==0,unresolved_count=unknown)

    def prune(self, target_bytes: int, operation_id: str, opfd: int, dry_run: bool = False) -> dict:
        plan=self.plan(target_bytes)
        if dry_run: return plan | dict(action='PLAN_ONLY',removed_count=0,removed_accounted_bytes=0)
        removed=removed_bytes=skipped=0
        for candidate in plan['candidates']:
            gid=candidate['generation_id']
            with self.reg.transaction() as c:
                row=c.execute('SELECT * FROM generations WHERE generation_id=?',(gid,)).fetchone()
                if row['state']!='AVAILABLE' or c.execute('SELECT 1 FROM pins WHERE generation_id=?',(gid,)).fetchone():
                    skipped+=1; continue
                c.execute("UPDATE generations SET state='RETIRING' WHERE generation_id=?",(gid,))
            # Private, unique pathname. A later generation can never occupy it.
            self.supervisor.run('remove',dict(private_root=self.reg.private_root,relative=candidate['relative_path']),
                operation_id=operation_id,op_guard_fd=opfd)
            with self.reg.transaction() as c:
                c.execute("UPDATE generations SET state='ABSENT' WHERE generation_id=? AND state='RETIRING'",(gid,))
            removed+=1; removed_bytes+=candidate['accounted_bytes']
        after=self.plan(target_bytes)
        return dict(action='RECLAIM',target_bytes=target_bytes,accounted_before_bytes=plan['accounted_before_bytes'],
                    accounted_after_bytes=after['accounted_before_bytes'],protected_floor_bytes=after['protected_floor_bytes'],
                    removed_count=removed,removed_accounted_bytes=removed_bytes,skipped_count=skipped,
                    unresolved_count=after['unresolved_count'],target_met_now=after['target_met_now'],
                    target_would_be_met=after['target_would_be_met'])


class DriveEngine:
    def __init__(self, config_path: str, wait_ms: int = 900000):
        self.config_path=normalized_absolute(config_path)
        self.cfg=load_config(config_path)
        self.supervisor=WorkerSupervisor(self.cfg['private_root'],wait_ms)

    @staticmethod
    def _contract(reg: AuthorityRegistry, binding: dict) -> dict:
        return wire_read(reg.task(binding['task_key'])['contract'].encode())

    def _qualify(self, reg: AuthorityRegistry) -> bool:
        return reg.qualified()

    def _source_permission(self, source: str) -> dict:
        for root in self.cfg['source_roots']:
            if os.path.commonpath([source,root['path']])==root['path']:
                return root
        raise CASError('SOURCE_SCOPE_DENIED',code=6)

    def _job(self, reg: AuthorityRegistry, operation_id: str, opfd: int, kind: str, args: dict) -> dict:
        generation=reg.dispatch(operation_id)
        result=self.supervisor.run(kind,args,operation_id,generation,opfd,
            self.cfg['limits']['publish_timeout_ms'] if kind in ('publish','export') else self.cfg['limits']['job_timeout_ms'])
        return result

    def _snapshot_check(self, reg: AuthorityRegistry, operation_id: str, opfd: int, snap: sqlite3.Row) -> dict:
        workspace=str(Path(self.cfg['private_root'])/snap['relative_path'])
        contract=wire_read(reg.task(snap['task_key'])['contract'].encode())
        try:
            return self._job(reg,operation_id,opfd,'check',dict(candidate=str(Path(workspace)/'tree'),workspace=workspace,
                root=snap['root'],contract=contract,limits=self.cfg['limits'],enforce_approval=False))
        except CASError as e:
            if e.code==4:
                with reg.transaction() as c:
                    c.execute("UPDATE generations SET state='CORRUPT' WHERE generation_id=?",(snap['generation_id'],))
            raise

    def verify(self, leaf: str, operation_id: str | None = None, offline: bool = False) -> dict:
        """Read-only authority and transport. Temporary private report only, no retention receipt."""
        require(not offline,'OFFLINE_HOLD','Fresh verify never probes provider paths offline',3)
        leaf=normalized_absolute(leaf)
        # No operations, pins, requests or reports are inserted into the registry.
        with AuthorityRegistry(self.cfg,readonly=True) as reg:
            binding,root=reg.for_leaf(leaf); contract=self._contract(reg,binding)
            scratch_id=new_id(); relative='scratch/'+scratch_id
            with SafeTree(self.cfg['private_root']) as t: t.mkdir(relative)
            scratch=str(Path(self.cfg['private_root'])/relative)
            completed=False
            try:
                result=self.supervisor.run('verify',dict(candidate=leaf,root=root,contract=contract,
                    approved_roots=reg.approved_roots(binding['task_key']),binding=binding,
                    limits=self.cfg['limits'],report_path=str(Path(scratch)/'report.json')),
                    operation_id=operation_id,timeout_ms=self.cfg['limits']['job_timeout_ms'])
                completed=True
                return dict(root=root,task_key=task_key(contract),integrity='MATCH',scope='OBSERVED_CLOSURE',
                    membership=result['membership'],totals=result['manifest']['totals'],
                    files=result['files'],admission='NOT_ASSERTED',retained_snapshot='NOT_CREATED',
                    qualification='UNQUALIFIED_OBSERVATION',remote_evidence='NOT_ASSERTED')
            finally:
                # On timeout a child may still own scratch: never delete under it.
                if completed or self.supervisor.last_observation.get('reaped'):
                    remove_private_tree(self.cfg['private_root'],relative)

    def put(self, file: str, dropzone: str | None = None, operation_id: str | None = None,
            offline: bool = False, status_only: bool = False) -> dict:
        o=operation_id or new_id(); uuid_value(o); source=normalized_absolute(file)
        with AuthorityRegistry(self.cfg,readonly=status_only) as reg:
            binding=reg.binding(dropzone); contract=self._contract(reg,binding)
            intent=dict(command='put',source=source,binding_id=binding['binding_id'],task_key=task_key(contract),
                        contract_sha256=sha(wire_bytes(contract)),layout='fixed-4m-v1',goal=GOALS['put'])
            if status_only: return self._stored(reg,o,'put',intent)
            with file_guard(str(Path(self.cfg['private_root'])/'locks'/('op.'+o)),create=True) as opfd:
                op=reg.open_operation(o,'put',intent)
                if op['state']=='DONE': return json_read(op['result_json'].encode()) | {'operation_id':o,'replayed':True,'observation':'STORED_LOCAL_PUBLICATION'}
                try:
                    qualified=self._qualify(reg)
                    require(len(contract['slots'])==1,'TASK_SHAPE_UNSUPPORTED',code=7)
                    if op['generation_id']:
                        snap=reg.db.execute('SELECT s.*,g.relative_path,g.state FROM snapshots s JOIN generations g USING(generation_id) WHERE s.generation_id=?',(op['generation_id'],)).fetchone()
                        require(snap is not None and snap['state']=='AVAILABLE','SNAPSHOT_NOT_PROTECTED',code=10)
                        summary=self._snapshot_check(reg,o,opfd,snap); gid=snap['generation_id']
                    else:
                        abandoned=reg.db.execute("SELECT * FROM generations WHERE owner_operation=? AND state='WRITING' ORDER BY ordinal",(o,)).fetchall()
                        if abandoned:
                            # Acquiring the operation guard proves no registered worker
                            # retains construction authority. Recover closed private bytes,
                            # never silently rebind O to a changed source pathname.
                            require(len(abandoned)==1,'SOURCE_CAPTURE_OUTCOME_UNKNOWN',code=9)
                            old=abandoned[0]; old_workspace=str(Path(self.cfg['private_root'])/old['relative_path'])
                            try:
                                with SafeTree(Path(old_workspace)/'tree') as tree:
                                    raw=tree.read('manifest.json',MAX_JSON)
                                recovered=wire_read(raw)
                                require(recovered['attempt_id']==op['attempt_id'] and recovered['created_at_utc']==op['created_at_utc'],'INTENT_CONFLICT',code=5)
                                summary=self._job(reg,o,opfd,'check',dict(candidate=str(Path(old_workspace)/'tree'),workspace=old_workspace,
                                    root=sha(raw),contract=contract,limits=self.cfg['limits'],enforce_approval=False))
                                reg.register_snapshot(o,old['generation_id'],summary,qualified)
                            except (CASError,OSError) as recovery_error:
                                raise CASError('SOURCE_CAPTURE_OUTCOME_UNKNOWN','Prior capture is not a recoverable closed source; preserve it and use explicit administrative reconciliation',9) from recovery_error
                            # This invocation now continues from the registered generation.
                            # Re-entering through a new call is required to avoid nested guards.
                            raise CASError('CAPTURE_RECOVERED_REPLAY_REQUIRED','Closed source recovered; replay this same operation to publish',3)
                        root_permission=self._source_permission(source)
                        require(not offline, 'OFFLINE_HOLD', 'Offline put replays retained sources only; it does not open a new source', 3)
                        gid=reg.reserve_generation(o); workspace=str(Path(self.cfg['private_root'])/'generations'/gid)
                        observed_root=self._job(reg,o,opfd,'probe',dict(path=root_permission['path']))
                        require(observed_root['identity']==root_permission['identity'],'ROOT_IDENTITY_CHANGED',code=7)
                        summary=self._job(reg,o,opfd,'prepare',dict(workspace=workspace,sources={contract['slots'][0]['path']:source},
                            contract=contract,producer_agent=contract['producer_agents'][0],installation_id=self.cfg['installation_id'],
                            attempt_id=op['attempt_id'],created_at=op['created_at_utc'],layout='fixed-4m-v1',
                            limits=self.cfg['limits'],report_path=str(Path(workspace)/'prepared.json')))
                        # A distinct child checks the closed retained destination again.
                        summary=self._job(reg,o,opfd,'check',dict(candidate=str(Path(workspace)/'tree'),workspace=workspace,
                            root=summary['root'],contract=contract,limits=self.cfg['limits'],enforce_approval=False))
                        reg.register_snapshot(o,gid,summary,qualified)
                    require(not offline,'OFFLINE_HOLD','Closed private source retained; publication not attempted',3)
                    workspace=str(Path(self.cfg['private_root'])/'generations'/gid)
                    published=self._job(reg,o,opfd,'publish',dict(source=str(Path(workspace)/'tree'),root=summary['root'],
                        contract=contract,binding=binding,limits=self.cfg['limits']))
                    f=summary['files'][0]
                    result=dict(operation_id=o,root=summary['root'],content_sha256=f['content_sha256'],size_bytes=f['size_bytes'],
                        file_map_sha256=f['file_map']['sha256'],dataset_sha256=summary['manifest']['dataset']['sha256'],
                        submission_dir=published['submission_dir'],local_publication=published['local_publication'],
                        staging_retained=published['staging_retained'],task_key=task_key(contract),
                        source_scope=contract['slots'][0]['source_scope'],remote_evidence='NOT_ASSERTED',admission='NOT_ASSERTED',
                        qualification='PROCESS_CRASH_QUALIFIED' if qualified else 'LAB_CANDIDATE_UNQUALIFIED')
                    with reg.transaction() as c:
                        c.execute("UPDATE pins SET kind='SOURCE_RETENTION' WHERE generation_id=? AND owner=? AND kind='PREPARATION'",(gid,o))
                    reg.finish(o,result)
                    return result
                except BaseException as raw:
                    e=map_exception(raw); reg.record_error(o,e); raise e

    def capture_for_admission(self, reg: AuthorityRegistry, o: str, opfd: int, leaf: str,
                              binding: dict, root: str, qualified: bool, offline: bool) -> str:
        # Preserve an existing complete own/private snapshot after later cloud degradation.
        candidate=reg.db.execute("SELECT s.*,g.relative_path,g.state FROM snapshots s JOIN generations g USING(generation_id) WHERE s.root=? AND g.state='AVAILABLE' ORDER BY g.ordinal LIMIT 1",(root,)).fetchone()
        if candidate:
            with reg.transaction() as c:
                require(c.execute("SELECT 1 FROM generations WHERE generation_id=? AND state='AVAILABLE'",(candidate['generation_id'],)).fetchone() is not None,'SNAPSHOT_NOT_PROTECTED',code=10)
                c.execute('INSERT OR IGNORE INTO pins VALUES(?,?,?)',(candidate['generation_id'],o,'PREPARATION'))
            self._snapshot_check(reg,o,opfd,candidate)
            with reg.transaction() as c:
                c.execute("UPDATE operations SET root=?,generation_id=?,phase='CAPTURED' WHERE operation_id=?",(root,candidate['generation_id'],o))
            return candidate['generation_id']
        require(not offline,'OFFLINE_HOLD',code=3)
        contract=self._contract(reg,binding)
        gid=reg.reserve_generation(o); workspace=str(Path(self.cfg['private_root'])/'generations'/gid)
        summary=self._job(reg,o,opfd,'capture',dict(candidate=leaf,root=root,contract=contract,
            workspace=workspace,approved_roots=reg.approved_roots(binding['task_key']),binding=binding,
            limits=self.cfg['limits'],report_path=str(Path(workspace)/'captured.json')))
        summary=self._job(reg,o,opfd,'check',dict(candidate=str(Path(workspace)/'tree'),workspace=workspace,root=root,
            contract=contract,limits=self.cfg['limits'],enforce_approval=False))
        reg.register_snapshot(o,gid,summary,qualified)
        return gid

    def commit(self, leaf: str, operation_id: str | None = None, offline: bool = False,
               status_only: bool = False, queue_only: bool = False) -> dict:
        o=operation_id or new_id(); uuid_value(o); leaf=normalized_absolute(leaf)
        with AuthorityRegistry(self.cfg,readonly=status_only) as reg:
            binding,root=reg.for_leaf(leaf)
            intent=dict(command='commit',leaf=leaf,root=root,task_key=json_read(binding['task_key'].encode()),goal=GOALS['commit'])
            if status_only: return self._stored(reg,o,'commit',intent)
            require(self.cfg['role']=='authority','AUTHORITY_LOCAL_ONLY',code=6)
            with file_guard(str(Path(self.cfg['private_root'])/'locks'/('op.'+o)),create=True) as opfd:
                op=reg.open_operation(o,'commit',intent); broker=DropzoneAdmissionBroker(reg)
                if op['state']=='DONE': return json_read(op['result_json'].encode()) | {'operation_id':o,'replayed':True,'observation':'HISTORICAL_DECISION'}
                try:
                    existing=broker.existing(binding['task_key'],root)
                    if existing:
                        reg.finish(o,existing)
                        return existing | dict(operation_id=o,replayed=True,observation='HISTORICAL_DECISION')
                    qualified=self._qualify(reg)
                    # Reject unauthorized roots before acquiring their payload.
                    reg.approval(reg.db,binding['task_key'],root,ClockPolicy.snapshot())
                    gid=self.capture_for_admission(reg,o,opfd,leaf,binding,root,qualified,offline)
                    q=broker.request_admission(o,binding['task_key'],root,gid)
                    if queue_only: return dict(operation_id=o,root=root,request_sequence=q,state='QUEUED')
                    broker.advance_admission_queue()
                    return broker.result(o) | dict(operation_id=o,replayed=False,observation='CURRENT_OPERATION')
                except BaseException as raw:
                    e=map_exception(raw); reg.record_error(o,e); raise e

    def get(self, root_hash: str, output: str | None = None, operation_id: str | None = None,
            offline: bool = False, status_only: bool = False) -> dict:
        root=digest(root_hash); o=operation_id or new_id(); uuid_value(o)
        dest=normalized_absolute(output) if output else None
        with AuthorityRegistry(self.cfg,readonly=status_only) as reg:
            intent=dict(command='get',root=root,output=dest,goal=GOALS['get'])
            if status_only: return self._stored(reg,o,'get',intent)
            with file_guard(str(Path(self.cfg['private_root'])/'locks'/('op.'+o)),create=True) as opfd:
                op=reg.open_operation(o,'get',intent)
                try:
                    self._qualify(reg)
                    snap=reg.active_snapshot(root)
                    with reg.transaction() as c:
                        require(c.execute("SELECT 1 FROM generations WHERE generation_id=? AND state='AVAILABLE'",(snap['generation_id'],)).fetchone() is not None,'SNAPSHOT_NOT_PROTECTED',code=10)
                        c.execute('INSERT OR IGNORE INTO pins VALUES(?,?,?)',(snap['generation_id'],o,'READER'))
                    summary=self._snapshot_check(reg,o,opfd,snap)
                    require(len(summary['files'])==1,'TASK_SHAPE_UNSUPPORTED','Root-based get requires exactly one logical file',7)
                    f=summary['files'][0]; h=f['content_sha256']; length=f['size_bytes']
                    source=str(Path(self.cfg['private_root'])/snap['relative_path']/f['output_rel'])
                    row=reg.db.execute('SELECT * FROM exports WHERE operation_id=?',(o,)).fetchone()
                    if row:
                        require(row['released']==0,'EXPORT_RELEASED',code=6)
                    if dest:
                        candidates=[r for r in self.cfg['export_roots'] if os.path.commonpath([dest,r['path']])==r['path']]
                        require(len(candidates)==1,'OUTPUT_SCOPE_DENIED',code=6)
                        target=candidates[0]; rel=relative_under(dest,target['path']); export_gid=snap['generation_id']
                    else:
                        if row is None:
                            export_gid=new_id(); relative='exports/'+o
                            with reg.transaction() as c:
                                ordinal=c.execute('SELECT COALESCE(MAX(ordinal),0)+1 FROM generations').fetchone()[0]
                                c.execute('INSERT INTO generations(generation_id,relative_path,owner_operation,state,ordinal) VALUES(?,?,?,?,?)',(export_gid,relative,o,'WRITING',ordinal))
                                c.execute('INSERT INTO pins VALUES(?,?,?)',(export_gid,o,'EXPORT'))
                                c.execute('INSERT INTO exports VALUES(?,?,?,?,0)',(o,export_gid,str(Path(self.cfg['private_root'])/relative/(h+'.bin')),1))
                            with SafeTree(self.cfg['private_root']) as t: t.mkdir(relative)
                            row=reg.db.execute('SELECT * FROM exports WHERE operation_id=?',(o,)).fetchone()
                        export_gid=row['generation_id']
                        exportroot=str(Path(self.cfg['private_root'])/'exports'/o)
                        with SafeTree(exportroot) as t: target=dict(path=exportroot,identity=identity(os.fstat(t.fd)))
                        rel=h+'.bin'
                    if dest and row is None:
                        with reg.transaction() as c:
                            c.execute('INSERT INTO exports VALUES(?,?,?,?,0)',(o,export_gid,dest,0))
                    # Only a prior attempt of this exact O may reconcile an occupied destination.
                    prior_phase=reg.operation(o)['phase']
                    with reg.transaction() as c:
                        c.execute("UPDATE operations SET phase='EXPORT_RESERVED' WHERE operation_id=?",(o,))
                    result=self._job(reg,o,opfd,'export',dict(source=source,sha256=h,size_bytes=length,
                        output_root=target,output_rel=rel,operation_id=o,proof_path=str(Path(self.cfg['private_root'])/'scratch'/(o+'.export-proof.json'))))
                    with reg.transaction() as c:
                        if not dest:
                            c.execute("UPDATE generations SET state='AVAILABLE',accounted_bytes=?,root=? WHERE generation_id=?",(length,root,export_gid))
                        c.execute("DELETE FROM pins WHERE generation_id=? AND owner=? AND kind='READER'",(snap['generation_id'],o))
                    result |= dict(operation_id=o,root=root,file_map_sha256=f['file_map']['sha256'],generation_id=export_gid,
                                   retention='USER_OWNED' if dest else 'EXPLICIT_RELEASE_REQUIRED',admission='NOT_ASSERTED',
                                   remote_evidence='NOT_ASSERTED',replayed=op['state']=='DONE')
                    reg.finish(o,result,phase='EXPORT_RESERVED')
                    return result
                except BaseException as raw:
                    e=map_exception(raw); reg.record_error(o,e); raise e

    def prune(self, max_size_gb: str | None = None, operation_id: str | None = None,
              dry_run: bool = False, status_only: bool = False) -> dict:
        target=parse_gb(max_size_gb) if max_size_gb is not None else self.cfg['limits']['cache_target_bytes']
        o=operation_id or new_id(); uuid_value(o)
        with AuthorityRegistry(self.cfg,readonly=dry_run or status_only) as reg:
            intent=dict(command='prune',target_bytes=target,goal='PRUNE_PLAN_PRODUCED' if dry_run else GOALS['prune'])
            evictor=LocalCacheEvictor(reg,self.supervisor)
            if status_only: return self._stored(reg,o,'prune',intent)
            if dry_run: return evictor.plan(target) | dict(action='PLAN_ONLY',operation_id=None)
            self._qualify(reg)
            with file_guard(str(Path(self.cfg['private_root'])/'locks'/('op.'+o)),create=True) as opfd:
                op=reg.open_operation(o,'prune',intent)
                if op['state']=='DONE': return json_read(op['result_json'].encode()) | dict(replayed=True,observation='STORED_RECLAMATION')
                try:
                    result=evictor.prune(target,o,opfd)
                    result['operation_id']=o
                    if not result['target_met_now']:
                        with reg.transaction() as c:
                            c.execute("UPDATE operations SET state='HOLD_RESOURCE',result_json=? WHERE operation_id=?",(json_bytes(result).decode(),o))
                        error=CASError('HOLD_RESOURCE','Protected or unresolved generations prevent the requested target',8)
                        error.details=result
                        raise error
                    reg.finish(o,result); return result
                except BaseException as raw:
                    e=map_exception(raw); reg.record_error(o,e); raise e

    @staticmethod
    def _stored(reg: AuthorityRegistry, o: str, command: str, intent: dict) -> dict:
        r=reg.operation(o)
        require(r['command']==command and r['intent']==json_bytes(intent).decode(),'INTENT_CONFLICT',code=5)
        if r['state']=='DONE': return json_read(r['result_json'].encode()) | dict(operation_id=o,observation='STORED_STATUS',replayed=True)
        if r['error_json']:
            e=json_read(r['error_json'].encode()); raise CASError(e['reason'],e['message'],e['code'])
        raise CASError('PENDING_CONTENT',code=3)

    def service_pending(self, maximum: int = 1) -> list[dict]:
        """Explicit local-controller iteration; does not install a background daemon."""
        results=[]
        with AuthorityRegistry(self.cfg) as reg:
            for row in reg.db.execute("SELECT * FROM receipt_outbox WHERE state<>'LOCAL_PUBLISHED' AND attempts<8 ORDER BY rowid LIMIT ?",(maximum,)).fetchall():
                with reg.transaction() as c:
                    c.execute('UPDATE receipt_outbox SET attempts=attempts+1 WHERE receipt_sha256=?',(row['receipt_sha256'],))
                binding_row=reg.db.execute('SELECT path FROM bindings WHERE binding_id=?',(row['binding_id'],)).fetchone()
                binding=reg.binding(binding_row[0])
                try:
                    result=self.supervisor.run('receipt_export',dict(binding=binding,receipt=bytes(row['receipt_bytes']).decode('ascii')))
                    state='LOCAL_PUBLISHED'; results.append(result | dict(state=state))
                except CASError as e:
                    state='UNKNOWN' if e.code==9 else 'BLOCKED'; results.append(dict(state=state,reason=e.reason))
                with reg.transaction() as c:
                    c.execute('UPDATE receipt_outbox SET state=? WHERE receipt_sha256=?',(state,row['receipt_sha256']))
        return results


def release_export(config_path: str, operation_id: str, end_of_use_reason: str) -> None:
    """Explicit administrative end-of-use; never inferred from a PID or elapsed time."""
    require(bool(end_of_use_reason),'REASON_REQUIRED')
    with AuthorityRegistry(load_config(config_path)) as reg, reg.transaction() as c:
        row=c.execute('SELECT * FROM exports WHERE operation_id=?',(operation_id,)).fetchone()
        require(row is not None,'EXPORT_NOT_FOUND',code=7)
        require(reg.operation(operation_id)['state']=='DONE','EXPORT_UNRESOLVED',code=9)
        c.execute('UPDATE exports SET released=1 WHERE operation_id=?',(operation_id,))
        c.execute("DELETE FROM pins WHERE generation_id=? AND owner=? AND kind='EXPORT'",(row['generation_id'],operation_id))
        reg.log(c,'RELEASE_EXPORT',dict(operation_id=operation_id,reason=end_of_use_reason[:300]))


def release_prepared(config_path: str, root: str, reason: str) -> None:
    """Explicitly abandon an unaccepted, resolved local proposal. No cloud deletion."""
    digest(root); require(bool(reason),'REASON_REQUIRED')
    with AuthorityRegistry(load_config(config_path)) as reg, reg.transaction() as c:
        require(c.execute('SELECT 1 FROM acceptances WHERE root=?',(root,)).fetchone() is None,'ACCEPTANCE_RETENTION_REQUIRED',code=6)
        rows=c.execute("SELECT g.generation_id,g.owner_operation,o.state FROM generations g JOIN operations o ON o.operation_id=g.owner_operation WHERE g.root=?",(root,)).fetchall()
        for row in rows:
            require(row['state']=='DONE','OPERATION_UNRESOLVED',code=9)
            c.execute("DELETE FROM pins WHERE generation_id=? AND owner=? AND kind IN ('PREPARATION','SOURCE_RETENTION')",(row['generation_id'],row['owner_operation']))
        reg.log(c,'RELEASE_PREPARED',dict(root=root,reason=reason[:300]))


def parse_gb(value: str) -> int:
    require(isinstance(value,str) and len(value)<=24 and re.fullmatch(r'(0|[1-9][0-9]*)(\.[0-9]{1,3})?',value) is not None,'INVALID_SIZE',code=2)
    n=int(decimal.Decimal(value)*1000000000)
    require(0<=n<=MAX_UINT,'INVALID_SIZE',code=2)
    return n


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None: raise CASError('INVALID_ARGUMENT',message,2)


def cli_parser() -> argparse.ArgumentParser:
    p=_Parser(prog='drive_cas.py',allow_abbrev=False,description=__doc__)
    p.add_argument('--version',action='version',version=VERSION)
    p.add_argument('--config',default=str(Path.home()/'Library/Application Support/SovereignDrive/drive-engine/config.json'))
    p.add_argument('--operation-id'); p.add_argument('--wait-ms',type=int,default=900000)
    p.add_argument('--offline',action='store_true'); p.add_argument('--status-only',action='store_true')
    sub=p.add_subparsers(dest='command',required=True,parser_class=_Parser)
    put=sub.add_parser('put',allow_abbrev=False); put.add_argument('file'); put.add_argument('--dropzone')
    get=sub.add_parser('get',allow_abbrev=False); get.add_argument('root_hash'); get.add_argument('--output')
    commit=sub.add_parser('commit',allow_abbrev=False); commit.add_argument('dropzone_dir')
    verify=sub.add_parser('verify',allow_abbrev=False); verify.add_argument('dropzone_dir')
    prune=sub.add_parser('prune',allow_abbrev=False); prune.add_argument('--max-size-gb'); prune.add_argument('--dry-run',action='store_true')
    return p


def main(argv: list[str] | None = None) -> int:
    argv=list(sys.argv[1:] if argv is None else argv)
    if argv == ['--_worker']: return _worker_main()
    command=None; o=None; result=None
    try:
        # argparse otherwise silently permits repeated options (last value wins).
        options=[]
        for token in argv:
            if token=='--': break
            if token.startswith('--'): options.append(token.split('=',1)[0])
        require(len(options)==len(set(options)),'DUPLICATE_OPTION',code=2)
        a=cli_parser().parse_args(argv); command=a.command
        require(1<=a.wait_ms<=900000,'INVALID_ARGUMENT',code=2)
        if a.operation_id:
            try: uuid_value(a.operation_id)
            except CASError: raise CASError('INVALID_ARGUMENT','Invalid operation UUID',2) from None
        if command=='get':
            try: digest(a.root_hash)
            except CASError: raise CASError('INVALID_HASH',code=2) from None
        require(not a.status_only or a.operation_id is not None,'STATUS_ID_REQUIRED',code=2)
        require(not (a.command=='verify' and a.status_only),'VERIFY_HAS_NO_PERSISTENT_STATUS',code=2)
        require(not (a.command=='prune' and a.dry_run and a.status_only),'INVALID_ARGUMENT',code=2)
        o=a.operation_id or new_id()
        engine=DriveEngine(a.config,a.wait_ms)
        if command=='put': result=engine.put(a.file,a.dropzone,o,a.offline,a.status_only)
        elif command=='get': result=engine.get(a.root_hash,a.output,o,a.offline,a.status_only)
        elif command=='commit': result=engine.commit(a.dropzone_dir,o,a.offline,a.status_only)
        elif command=='verify': result=engine.verify(a.dropzone_dir,o,a.offline)
        elif command=='prune': result=engine.prune(a.max_size_gb,o,a.dry_run,a.status_only)
        exit_code=0; reason='GOAL_ESTABLISHED'; state='DONE'
    except KeyboardInterrupt:
        exit_code=130; reason='CALLER_INTERRUPTED'; state='UNKNOWN'
    except BaseException as e:
        if isinstance(e,SystemExit): return int(e.code or 0)
        error=map_exception(e); exit_code=error.code; reason=error.reason
        state='UNKNOWN' if exit_code in (9,130) else 'HOLD_RESOURCE' if exit_code==8 else 'PENDING' if exit_code==3 else 'REJECTED'
        result=error.details if error.details is not None else {'message':error.message}
    envelope=dict(protocol=CLI_PROTOCOL,version=VERSION,command=command,operation_id=o,state=state,
                  goal=('PRUNE_PLAN_PRODUCED' if command=='prune' and locals().get('a') and getattr(a,'dry_run',False) else GOALS.get(command)),goal_met=exit_code==0,exit_code=exit_code,reason=reason,
                  result=result,remote_evidence='NOT_ASSERTED')
    raw=json_bytes(envelope)
    if len(raw)>MAX_FRAME:
        raw=json_bytes(dict(protocol=CLI_PROTOCOL,command=command,operation_id=o,state='UNKNOWN',goal_met=False,
                            exit_code=9,reason='RESULT_TOO_LARGE',message='Reconcile the original operation through the Python API'))
        exit_code=9
    try: sys.stdout.buffer.write(raw); sys.stdout.buffer.flush()
    except BrokenPipeError: return 9
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
