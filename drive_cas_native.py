#!/usr/bin/env python3
"""Drive CAS 0.5.0: stdlib-only, immutable candidates and one local authority.

Transport is an untrusted asynchronous filesystem. This module does not certify
Google upload completion. See README and the implementation report for the
candidate/qualification boundary and intentionally disabled capabilities.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import datetime as dt
import errno
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import random
import functools
import selectors
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, BinaryIO, Iterator
import uuid

VERSION = "0.5.0"
CLI_PROTOCOL = "gdoe-cli/2"
WIRE = "ascii-json-1"
BLOCK_SIZE = 4 * 1024 * 1024
LAYOUTS = {"fixed-4m-v1": BLOCK_SIZE, "fixed-16m-v1": 16 * 1024 * 1024}
MAX_JSON = 16 * 1024 * 1024
MAX_UINT = 9007199254740991
MAX_REFS = 1048576
MAX_ARTIFACTS = 100000
MAX_METADATA_BYTES = 64 * 1024 * 1024
PAGE_ENTRIES = 4096
IO_SIZE = 256 * 1024
MAX_CONTROL = 65536
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
TOTAL_FIELDS = ("artifact_count", "logical_bytes", "chunk_references", "unique_blocks",
                "unique_block_bytes", "unique_metadata_nodes", "unique_metadata_bytes")
HEX = re.compile(r"[0-9a-f]{64}\Z")
LABEL = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
MEDIA = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*\Z")
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
GOALS = {"put": "LOCAL_PUBLICATION", "get": "FILE_MATERIALIZED",
         "verify": "FULL_CLOSURE_VERIFIED", "commit": "CANONICAL_ADMISSION",
         "prune": "CACHE_TARGET_MET"}


class CASError(Exception):
    def __init__(self, reason: str, message: str = "", code: int = 4, **detail: Any):
        super().__init__(message or reason)
        self.reason, self.code, self.detail = reason, code, detail


def require(ok: bool, reason: str, message: str = "", code: int = 4) -> None:
    if not ok:
        raise CASError(reason, message, code)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_id() -> str:
    return str(uuid.uuid4())


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def uuid_value(value: Any) -> str:
    require(type(value) is str, "INVALID_UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise CASError("INVALID_UUID") from None
    require(str(parsed) == value and parsed.variant == uuid.RFC_4122, "INVALID_UUID")
    return value


def uint(value: Any, lower: int = 0, upper: int = MAX_UINT) -> int:
    require(type(value) is int and lower <= value <= upper, "INVALID_INTEGER")
    return value


def digest(value: Any) -> str:
    require(type(value) is str and HEX.fullmatch(value) is not None, "INVALID_HASH")
    return value


def label(value: Any) -> str:
    require(type(value) is str and LABEL.fullmatch(value) is not None
            and value not in (".", ".."), "INVALID_LABEL")
    return value


def timestamp(value: Any) -> str:
    require(type(value) is str and len(value) == 27, "INVALID_TIMESTAMP")
    try:
        dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        raise CASError("INVALID_TIMESTAMP") from None
    return value


def fields(value: Any, names: str | tuple | list) -> dict:
    expected = set(names.split() if isinstance(names, str) else names)
    require(type(value) is dict and set(value) == expected, "SCHEMA_MISMATCH",
            "Unexpected or missing record fields")
    return value


def _pairs(pairs: list) -> dict:
    out: dict = {}
    for k, v in pairs:
        require(k not in out, "DUPLICATE_KEY")
        out[k] = v
    return out


def _depth_scan(data: bytes, maximum: int) -> None:
    depth = 0
    quoted = escaped = False
    for c in data:
        if quoted:
            if escaped:
                escaped = False
            elif c == 92:
                escaped = True
            elif c == 34:
                quoted = False
        elif c == 34:
            quoted = True
        elif c in (91, 123):
            depth += 1
            require(depth <= maximum, "JSON_DEPTH_LIMIT")
        elif c in (93, 125):
            depth -= 1
            require(depth >= 0, "INVALID_JSON")


def _wire_values(value: Any, depth: int = 0) -> None:
    require(depth <= 16, "JSON_DEPTH_LIMIT")
    if value is None:
        return
    if type(value) is str:
        require(all(32 <= ord(c) <= 126 for c in value), "NONCANONICAL_ENCODING")
    elif type(value) is int:
        uint(value)
    elif type(value) is list:
        for v in value:
            _wire_values(v, depth + 1)
    elif type(value) is dict:
        for k, v in value.items():
            require(type(k) is str, "INVALID_JSON_KEY")
            _wire_values(k, depth + 1)
            _wire_values(v, depth + 1)
    else:
        raise CASError("NONCANONICAL_ENCODING", "Wire values cannot be bool/float")


def canonical(value: Any) -> bytes:
    _wire_values(value)
    data = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    require(len(data) <= MAX_JSON, "JSON_SIZE_LIMIT")
    return data


def decode(data: bytes, *, wire: bool = True, limit: int = MAX_JSON) -> Any:
    require(len(data) <= limit, "JSON_SIZE_LIMIT")
    _depth_scan(data, 16 if wire else 12)
    try:
        value = json.loads(data.decode("ascii" if wire else "utf-8"),
                           object_pairs_hook=_pairs,
                           parse_constant=lambda x: (_ for _ in ()).throw(CASError("INVALID_JSON")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise CASError("INVALID_JSON", str(exc)[:160]) from None
    if wire:
        require(canonical(value) == data, "NONCANONICAL_ENCODING")
    return value


def local_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode()


def logical_path(value: Any) -> str:
    require(type(value) is str and 1 <= len(value) <= 1024, "INVALID_PATH")
    parts = value.split("/")
    require(all(1 <= len(p) <= 200 and p not in (".", "..")
                and re.fullmatch(r"[A-Za-z0-9._-]+", p) for p in parts), "INVALID_PATH")
    return value


def absolute(path: str | Path) -> str:
    # Lexical only: never touch a provider path in the controller.
    value = os.fspath(path)
    require("\x00" not in value and value != "-", "INVALID_PATH")
    require(".." not in value.split(os.sep), "INVALID_PATH")
    return os.path.abspath(os.path.expanduser(value))


def within(path: str, root: str) -> bool:
    return os.path.commonpath([path, root]) == root


@contextlib.contextmanager
def directory(path: str | Path) -> Iterator[int]:
    """No-follow walk starting at /. A caller's open fd pins each ancestor."""
    path = absolute(path)
    fd = os.open("/", DIR_FLAGS)
    try:
        for part in Path(path).parts[1:]:
            new = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = new
        yield fd
    finally:
        os.close(fd)


@contextlib.contextmanager
def open_regular(path: str | Path, *, mode: str = "rb") -> Iterator[BinaryIO]:
    path = Path(absolute(path))
    with directory(path.parent) as fd:
        raw = os.open(path.name, READ_FLAGS, dir_fd=fd)
    try:
        info = os.fstat(raw)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "UNSAFE_FILE_TYPE")
        with os.fdopen(raw, mode, buffering=0) as stream:
            raw = -1
            yield stream
    finally:
        if raw != -1:
            os.close(raw)


def read_limited(path: str | Path, limit: int = MAX_JSON) -> bytes:
    with open_regular(path) as stream:
        result = bytearray()
        while True:
            b = stream.read(min(IO_SIZE, limit + 1 - len(result)))
            require(b is not None, "READ_WOULD_BLOCK", code=3)
            if not b:
                break
            result.extend(b)
            require(len(result) <= limit, "JSON_SIZE_LIMIT")
        return bytes(result)


def flush_file(stream: BinaryIO) -> None:
    stream.flush()
    os.fsync(stream.fileno())
    if sys.platform == "darwin":
        flag = getattr(fcntl, "F_FULLFSYNC", 51)
        fcntl.fcntl(stream.fileno(), flag)


def sync_dir(path: str | Path) -> None:
    with directory(path) as fd:
        os.fsync(fd)


def write_new(path: str | Path, data: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)  # trusted private construction only
    with directory(path.parent) as fd:
        raw = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                      os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    with os.fdopen(raw, "wb") as stream:
        stream.write(data)
        flush_file(stream)


def stream_digest(stream: BinaryIO, expected_size: int | None = None,
                  *, limit: int = 64 * 1024**3, output: BinaryIO | None = None) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    while True:
        size = IO_SIZE
        if expected_size is not None:
            size = min(size, max(1, expected_size + 1 - n))
        b = stream.read(size)
        require(b is not None, "READ_WOULD_BLOCK", code=3)
        if not b:
            break
        n += len(b)
        require(n <= limit and (expected_size is None or n <= expected_size), "LENGTH_MISMATCH")
        h.update(b)
        if output is not None:
            rem = memoryview(b)
            while rem:
                w = output.write(rem)
                if w is None:
                    require(False, "WRITE_WOULD_BLOCK", code=3)
                rem = rem[w:]
    if expected_size is not None:
        require(n == expected_size, "LENGTH_MISMATCH")
    return h.hexdigest(), n


def check_file(path: str | Path, expected: str, size: int) -> None:
    with open_regular(path) as stream:
        got, _ = stream_digest(stream, size)
    require(got == expected, "DIGEST_MISMATCH")


def copy_checked(src: str | Path, dst: str | Path, expected: str, size: int) -> None:
    dst = Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open_regular(src) as inp:
        with open(dst, "xb") as out:
            got, _ = stream_digest(inp, size, output=out)
            require(got == expected, "DIGEST_MISMATCH")
            flush_file(out)
    check_file(dst, expected, size)


def identical(a: str | Path, b: str | Path) -> bool:
    def read_exact(stream: BinaryIO, size: int) -> bytes:
        buf = bytearray()
        while len(buf) < size:
            chunk = stream.read(size - len(buf))
            require(chunk is not None, "READ_WOULD_BLOCK", code=3)
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)
    with open_regular(a) as x, open_regular(b) as y:
        while True:
            ax, by = read_exact(x, IO_SIZE), read_exact(y, IO_SIZE)
            if ax != by:
                return False
            if not ax:
                return True


class AtomicPublisher:
    """Native local no-replace only. Never falls back to os.replace/link/copy."""
    @staticmethod
    def rename(source: str | Path, destination: str | Path) -> None:
        source, destination = Path(source), Path(destination)
        libc = ctypes.CDLL(None, use_errno=True)
        if sys.platform == "darwin":
            symbol, flags = "renameatx_np", 0x00000004  # Apple's RENAME_EXCL
        elif sys.platform.startswith("linux"):
            symbol, flags = "renameat2", 1  # Linux RENAME_NOREPLACE, test/portable substrate
        else:
            raise CASError("ATOMIC_PUBLISH_UNSUPPORTED", code=7)
        fn = getattr(libc, symbol, None)
        require(fn is not None, "ATOMIC_PUBLISH_UNSUPPORTED", code=7)
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        with directory(source.parent) as sfd, directory(destination.parent) as dfd:
            require(os.fstat(sfd).st_dev == os.fstat(dfd).st_dev,
                    "ATOMIC_PUBLISH_UNSUPPORTED", "Cross-filesystem publication", 7)
            rc = fn(sfd, os.fsencode(source.name), dfd, os.fsencode(destination.name), flags)
            if rc:
                err = ctypes.get_errno()
                if err == errno.EEXIST:
                    raise FileExistsError(err, os.strerror(err), str(destination))
                if err in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP, errno.EXDEV):
                    raise CASError("ATOMIC_PUBLISH_UNSUPPORTED", os.strerror(err), 7)
                raise OSError(err, os.strerror(err), str(destination))
            try:
                os.fsync(dfd)
                os.fsync(sfd)
            except OSError as exc:
                raise CASError("PUBLICATION_OUTCOME_UNKNOWN", str(exc), 9) from exc

    @staticmethod
    def probe(parent: str | Path) -> dict:
        """Explicit administrative probe on owned scratch paths, not qualification."""
        parent = Path(parent)
        work = parent / (".cas-probe-" + new_id())
        work.mkdir(mode=0o700)
        try:
            for is_dir in (False, True):
                a, b = work / "a", work / "b"
                if is_dir:
                    a.mkdir(); b.mkdir()
                    write_new(a / "x", b"A"); write_new(b / "x", b"B")
                else:
                    write_new(a, b"A"); write_new(b, b"B")
                try:
                    AtomicPublisher.rename(a, b)
                except FileExistsError:
                    pass
                else:
                    raise CASError("ATOMIC_PUBLISH_UNSUPPORTED", "Occupied destination overwritten", 7)
                require(read_limited(b / "x" if is_dir else b) == b"B",
                        "ATOMIC_PUBLISH_UNSUPPORTED", code=7)
                c = work / "c"
                AtomicPublisher.rename(a, c)
                if is_dir:
                    shutil.rmtree(b); shutil.rmtree(c)
                else:
                    b.unlink(); c.unlink()
            return {"platform": sys.platform, "file_and_directory_no_replace": True,
                    "scope": "LOCAL_PRIMITIVE_PROBE_NOT_QUALIFICATION"}
        finally:
            shutil.rmtree(work)


def node_ref(kind: str, data: bytes) -> dict:
    return {"kind": kind, "sha256": sha(data), "size_bytes": len(data)}


def locator(ref: dict, *, block: bool = False) -> str:
    h = digest(ref["sha256"])
    if block:
        return f"blocks/sha256/{h[:2]}/{h[2:4]}/{h}.bin"
    kind = ref["kind"]
    require(kind in ("dataset", "file_map", "chunk_page"), "INVALID_NODE_KIND")
    return f"nodes/{kind}/sha256/{h[:2]}/{h[2:4]}/{h}.json"


def validate_ref(ref: Any, kind: str | None = None) -> dict:
    fields(ref, "sha256 size_bytes" if kind is None else "kind sha256 size_bytes")
    digest(ref["sha256"]); uint(ref["size_bytes"], 1, MAX_JSON)
    if kind is not None:
        require(ref["kind"] == kind, "INVALID_NODE_KIND")
    return ref


def base_node(value: dict, kind: str, names: str) -> None:
    fields(value, "kind schema_version wire_profile " + names)
    require(value["kind"] == kind and type(value["schema_version"]) is int
            and value["schema_version"] == 1 and value["wire_profile"] == WIRE,
            "UNSUPPORTED_WIRE")


def validate_contract(c: Any) -> dict:
    fields(c, "kind schema_version store_id campaign task_id task_revision artifacts max_logical_bytes layouts")
    require(c["kind"] == "task_contract" and type(c["schema_version"]) is int and c["schema_version"] == 1, "CONTRACT_MISMATCH")
    uuid_value(c["store_id"]); label(c["campaign"]); label(c["task_id"])
    uint(c["task_revision"], 1); uint(c["max_logical_bytes"])
    require(type(c["layouts"]) is list and c["layouts"] and
            all(x in LAYOUTS for x in c["layouts"]) and len(set(c["layouts"])) == len(c["layouts"]),
            "CONTRACT_MISMATCH")
    require(type(c["artifacts"]) is list and len(c["artifacts"]) <= MAX_ARTIFACTS, "CONTRACT_MISMATCH")
    names = []
    for a in c["artifacts"]:
        fields(a, "path role media_type allow_empty max_size_bytes expected_sha256 source_scope")
        names.append(logical_path(a["path"])); label(a["role"])
        require(type(a["media_type"]) is str and len(a["media_type"]) <= 127
                and MEDIA.fullmatch(a["media_type"]) is not None, "CONTRACT_MISMATCH")
        uint(a["allow_empty"], 0, 1); uint(a["max_size_bytes"])
        if a["expected_sha256"] is not None:
            digest(a["expected_sha256"])
        require(a["source_scope"] in ("CAPTURED_BYTES", "EXPECTED_DIGEST"), "SOURCE_NOT_QUIESCENT")
        require(a["source_scope"] != "EXPECTED_DIGEST" or a["expected_sha256"] is not None,
                "SOURCE_NOT_QUIESCENT")
    check_paths(names)
    return c


def check_paths(names: list[str]) -> None:
    require(names == sorted(names), "ARTIFACT_ORDER")
    lowered = set()
    for name in names:
        logical_path(name)
        low = name.lower()
        require(low not in lowered, "PATH_COLLISION")
        parts = low.split("/")
        require(all("/".join(parts[:i]) not in lowered for i in range(1, len(parts))), "PATH_COLLISION")
        lowered.add(low)
    # Case folding can alter sort order; check ancestors independently.
    for low in lowered:
        parts = low.split("/")
        require(all("/".join(parts[:i]) not in lowered for i in range(1, len(parts))), "PATH_COLLISION")


def contract_key(c: dict) -> tuple:
    return tuple(c[k] for k in ("store_id", "campaign", "task_id", "task_revision"))


def task_key(c: dict) -> dict:
    return dict(zip(("store_id", "campaign", "task_id", "task_revision"), contract_key(c)))


def inventory(root: str | Path, *, limit: int = 2100000) -> set[str]:
    """Descriptor-relative, incremental inventory; empty directories count too."""
    out: set[str] = set(); visited = 0
    with directory(root) as fd:
        def walk(cur: int, prefix: str, depth: int) -> None:
            nonlocal visited
            require(depth <= 10, "PATH_DEPTH_LIMIT")
            with os.scandir(cur) as entries:
                for entry in entries:
                    visited += 1
                    require(visited <= limit, "OBJECT_COUNT_LIMIT")
                    name = entry.name; rel = prefix + name
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        sub = os.open(name, DIR_FLAGS, dir_fd=cur)
                        try: walk(sub, rel + "/", depth + 1)
                        finally: os.close(sub)
                    else:
                        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "UNSAFE_FILE_TYPE")
                        out.add(rel)
        walk(fd, "", 0)
    return out


class CASChunkManager:
    """Produces T2 byte-compatible self-contained candidates; no cloud pool writes."""
    @staticmethod
    def chunks(stream: BinaryIO, block_size: int = BLOCK_SIZE) -> Iterator[bytes]:
        require(block_size in LAYOUTS.values(), "UNSUPPORTED_LAYOUT")
        while True:
            buf = bytearray()
            while len(buf) < block_size:
                b = stream.read(min(IO_SIZE, block_size - len(buf)))
                require(b is not None, "READ_WOULD_BLOCK", code=3)
                if not b:
                    break
                buf.extend(b)
            if not buf:
                return
            yield bytes(buf)
            if len(buf) < block_size:
                return

    @staticmethod
    def build(sources: dict[str, str], contract: dict, output: str | Path,
              producer: str, installation: str, attempt: str,
              layout: str = "fixed-4m-v1", capture_limit: int | None = None) -> dict:
        validate_contract(contract)
        require(layout in contract["layouts"], "UNSUPPORTED_LAYOUT")
        label(producer); uuid_value(installation); uuid_value(attempt)
        require(set(sources) == {a["path"] for a in contract["artifacts"]}, "CONTRACT_MISMATCH")
        out = Path(output)
        out.mkdir(mode=0o700, parents=False, exist_ok=False)
        blocks: dict[str, int] = {}; nodes: dict[tuple, int] = {}; artifacts = []
        logical = occurrences = 0

        def save_node(kind: str, record: dict) -> dict:
            data = canonical(record); ref = node_ref(kind, data)
            key = (kind, ref["sha256"])
            if key not in nodes:
                write_new(out / locator(ref), data); nodes[key] = len(data)
            return ref

        for slot in contract["artifacts"]:
            src = sources[slot["path"]]
            require(Path(src).suffix.lower() not in (".gdoc", ".gsheet", ".gslides"), "EXPORT_REQUIRED")
            page, pages = [], []
            h, length, count = hashlib.sha256(), 0, 0
            with open_regular(src) as stream:
                for b in CASChunkManager.chunks(stream, LAYOUTS[layout]):
                    length += len(b); logical += len(b); count += 1; occurrences += 1
                    require((capture_limit is None or logical <= capture_limit) and
                            length <= slot["max_size_bytes"] and logical <= contract["max_logical_bytes"],
                            "RESOURCE_LIMIT", code=8)
                    require(count <= MAX_REFS and occurrences <= MAX_REFS, "OBJECT_COUNT_LIMIT")
                    h.update(b); d = sha(b)
                    if d not in blocks:
                        write_new(out / locator({"sha256": d}, block=True), b); blocks[d] = len(b)
                    else:
                        existing = read_limited(out / locator({"sha256": d}, block=True), MAX_JSON)
                        if existing != b:
                            write_new(out.parent / ("identity-incident-" + new_id() + ".bin"), b)
                            raise CASError("HASH_IDENTITY_INCIDENT", "Distinct samples retained for investigation", 10)
                    page.append({"sha256": d, "size_bytes": len(b)})
                    if len(page) == PAGE_ENTRIES:
                        pages.append(save_node("chunk_page", {"kind": "chunk_page", "schema_version": 1,
                                     "wire_profile": WIRE, "chunks": page})); page = []
            if page:
                pages.append(save_node("chunk_page", {"kind": "chunk_page", "schema_version": 1,
                             "wire_profile": WIRE, "chunks": page}))
            require(length > 0 or slot["allow_empty"] == 1, "CONTRACT_MISMATCH", "Empty artifact forbidden")
            require(slot["expected_sha256"] in (None, h.hexdigest()), "DIGEST_MISMATCH")
            fmap = save_node("file_map", {"kind": "file_map", "schema_version": 1,
                "wire_profile": WIRE, "layout_profile": layout, "size_bytes": length,
                "content_sha256": h.hexdigest(), "chunk_count": count, "pages": pages})
            artifacts.append({k: slot[k] for k in ("path", "role", "media_type")} | {"file_map": fmap})
        dset = save_node("dataset", {"kind": "dataset", "schema_version": 1,
                                   "wire_profile": WIRE, "artifacts": artifacts})
        totals = dict(zip(TOTAL_FIELDS, (len(artifacts), logical, occurrences, len(blocks),
                                       sum(blocks.values()), len(nodes), sum(nodes.values()))))
        root = {"kind": "submission", "schema_version": 1, "wire_profile": WIRE,
                "protocol": "gdoe-cas/1", **task_key(contract), "contract_sha256": sha(canonical(contract)),
                "producer_agent": producer, "producer_installation": installation, "attempt_id": attempt,
                "created_at_utc": utc(), "dataset": dset,
                "storage": {"profile": "self-contained-v1", "pool_id": None}, "totals": totals}
        raw = canonical(root); r = sha(raw)
        write_new(out / "manifest.json", raw)
        write_new(out / "COMMIT.json", canonical({"kind": "producer_commit", "schema_version": 1,
                  "wire_profile": WIRE, "submission_sha256": r, "manifest_size_bytes": len(raw),
                  "attempt_id": attempt, "prepared_at_utc": utc()}))
        sync_dir(out)
        return {"root_hash": r, "manifest": root}


class MerkleVerifier:
    """Untrusted acquisition → exact typed closure → retained destination readback.

    No SQLite and no acceptance calls. `capture` writes only the caller's private
    output; it never mutates the source. Output is registered only after child exit.
    """
    def __init__(self, contract: dict, expected_root: str,
                 max_logical_bytes: int = 128 * 1024**3):
        self.contract = validate_contract(contract)
        self.expected_root = digest(expected_root)
        self.maximum = min(contract["max_logical_bytes"], max_logical_bytes)

    def capture(self, source: str | Path, destination: str | Path) -> dict:
        source, dest = Path(source), Path(destination)
        dest.mkdir(mode=0o700, exist_ok=False)
        tree, outputs = dest / "tree", dest / "files"
        tree.mkdir(); outputs.mkdir()
        raw = read_limited(source / "manifest.json")
        require(sha(raw) == self.expected_root, "ROOT_MISMATCH")
        root = decode(raw)
        base_node(root, "submission", "protocol store_id campaign task_id task_revision contract_sha256 "
                  "producer_agent producer_installation attempt_id created_at_utc dataset storage totals")
        require(root["protocol"] == "gdoe-cas/1", "UNSUPPORTED_WIRE")
        uuid_value(root["store_id"]); uuid_value(root["attempt_id"]); uuid_value(root["producer_installation"])
        label(root["campaign"]); label(root["task_id"]); label(root["producer_agent"])
        uint(root["task_revision"], 1); timestamp(root["created_at_utc"])
        require(contract_key(root) == contract_key(self.contract), "CONTRACT_MISMATCH")
        require(root["contract_sha256"] == sha(canonical(self.contract)), "CONTRACT_MISMATCH")
        fields(root["storage"], "profile pool_id")
        require(root["storage"] == {"profile": "self-contained-v1", "pool_id": None},
                "POOLED_STORAGE_UNSUPPORTED", code=7)
        fields(root["totals"], TOTAL_FIELDS)
        for x in root["totals"].values(): uint(x)
        require(root["totals"]["logical_bytes"] <= self.maximum, "RESOURCE_LIMIT", code=8)
        self.maximum = root["totals"]["logical_bytes"]
        require(root["totals"]["unique_metadata_bytes"] <= MAX_METADATA_BYTES, "RESOURCE_LIMIT", code=8)
        marker_raw = read_limited(source / "COMMIT.json")
        marker = decode(marker_raw)
        base_node(marker, "producer_commit", "submission_sha256 manifest_size_bytes attempt_id prepared_at_utc")
        timestamp(marker["prepared_at_utc"]); uuid_value(marker["attempt_id"])
        uint(marker["manifest_size_bytes"], 1, MAX_JSON)
        require(marker["submission_sha256"] == self.expected_root and marker["manifest_size_bytes"] == len(raw)
                and marker["attempt_id"] == root["attempt_id"], "COMMIT_MARKER_MISMATCH")
        write_new(tree / "manifest.json", raw); write_new(tree / "COMMIT.json", marker_raw)
        expected_paths = {"manifest.json", "COMMIT.json"}
        nodes: dict[tuple, tuple[dict, int]] = {}; blocks: dict[str, int] = {}

        def get_node(ref: dict, kind: str) -> dict:
            validate_ref(ref, kind)
            key = (kind, ref["sha256"]); rel = locator(ref)
            expected_paths.add(rel)
            if key in nodes:
                require(nodes[key][1] == ref["size_bytes"], "LENGTH_MISMATCH")
                return nodes[key][0]
            require(len(nodes) < MAX_REFS, "OBJECT_COUNT_LIMIT")
            data = read_limited(source / rel, ref["size_bytes"] + 1)
            require(len(data) == ref["size_bytes"], "LENGTH_MISMATCH")
            require(sha(data) == ref["sha256"], "DIGEST_MISMATCH")
            require(sum(v[1] for v in nodes.values()) + len(data) <=
                    root["totals"]["unique_metadata_bytes"], "TOTALS_MISMATCH")
            value = decode(data)
            require(type(value) is dict and value.get("kind") == kind, "INVALID_NODE_KIND")
            write_new(tree / rel, data); nodes[key] = (value, len(data))
            return value

        dataset = get_node(root["dataset"], "dataset")
        base_node(dataset, "dataset", "artifacts")
        require(type(dataset["artifacts"]) is list and len(dataset["artifacts"]) <= MAX_ARTIFACTS,
                "OBJECT_COUNT_LIMIT")
        names = []
        for a in dataset["artifacts"]:
            fields(a, "path role media_type file_map")
            names.append(logical_path(a["path"])); label(a["role"])
        check_paths(names)
        require(names == [s["path"] for s in self.contract["artifacts"]], "CONTRACT_MISMATCH")
        logical = occurrences = 0; files_out = []
        for art, slot in zip(dataset["artifacts"], self.contract["artifacts"]):
            require(all(art[k] == slot[k] for k in ("path", "role", "media_type")), "CONTRACT_MISMATCH")
            require(Path(art["path"]).suffix.lower() not in (".gdoc", ".gsheet", ".gslides"), "EXPORT_REQUIRED")
            fmap = get_node(art["file_map"], "file_map")
            base_node(fmap, "file_map", "layout_profile size_bytes content_sha256 chunk_count pages")
            require(fmap["layout_profile"] in self.contract["layouts"], "UNSUPPORTED_LAYOUT")
            bsize = LAYOUTS[fmap["layout_profile"]]
            size = uint(fmap["size_bytes"], 0, slot["max_size_bytes"])
            h = digest(fmap["content_sha256"])
            require(slot["expected_sha256"] in (None, h), "DIGEST_MISMATCH")
            require(size > 0 or slot["allow_empty"] == 1, "CONTRACT_MISMATCH")
            n = uint(fmap["chunk_count"], 0, MAX_REFS)
            require(n == (size + bsize - 1) // bsize, "CHUNK_PACKING_MISMATCH")
            require(type(fmap["pages"]) is list and len(fmap["pages"]) == (n + PAGE_ENTRIES - 1) // PAGE_ENTRIES,
                    "PAGE_PACKING_MISMATCH")
            logical += size; occurrences += n
            require(logical <= self.maximum and occurrences <= MAX_REFS, "RESOURCE_LIMIT", code=8)
            outpath = outputs / art["path"]
            outpath.parent.mkdir(parents=True, exist_ok=True)
            count = total = 0; file_hash = hashlib.sha256()
            with open(outpath, "xb") as out:
                for pi, pref in enumerate(fmap["pages"]):
                    page = get_node(pref, "chunk_page")
                    base_node(page, "chunk_page", "chunks")
                    require(type(page["chunks"]) is list, "SCHEMA_MISMATCH")
                    expected_n = min(PAGE_ENTRIES, n - pi * PAGE_ENTRIES)
                    require(len(page["chunks"]) == expected_n and expected_n > 0, "PAGE_PACKING_MISMATCH")
                    for ref in page["chunks"]:
                        validate_ref(ref)
                        length = bsize if count < n - 1 else size - bsize * (n - 1)
                        require(ref["size_bytes"] == length, "CHUNK_PACKING_MISMATCH")
                        d = ref["sha256"]; rel = locator(ref, block=True)
                        expected_paths.add(rel)
                        if d not in blocks:
                            require(len(blocks) < MAX_REFS, "OBJECT_COUNT_LIMIT")
                            require(sum(blocks.values()) + length <= root["totals"]["unique_block_bytes"],
                                    "TOTALS_MISMATCH")
                            copy_checked(source / rel, tree / rel, d, length)
                            blocks[d] = length
                        else:
                            require(blocks[d] == length, "LENGTH_MISMATCH")
                        # Recheck the exact buffer being consumed; don't hash one fd and reopen transport.
                        data = read_limited(tree / rel, length + 1)
                        require(len(data) == length and sha(data) == d, "DIGEST_MISMATCH")
                        out.write(data); file_hash.update(data)
                        count += 1; total += len(data)
                require(count == n and total == size, "LENGTH_MISMATCH")
                require(file_hash.hexdigest() == h, "DIGEST_MISMATCH")
                flush_file(out)
            check_file(outpath, h, size)
            files_out.append({"path": art["path"], "sha256": h, "size_bytes": size,
                              "file_map_sha256": art["file_map"]["sha256"]})
        got_totals = dict(zip(TOTAL_FIELDS, (len(files_out), logical, occurrences, len(blocks),
                        sum(blocks.values()), len(nodes), sum(v[1] for v in nodes.values()))))
        require(root["totals"] == got_totals, "TOTALS_MISMATCH")
        observed = inventory(source)
        require(expected_paths == observed, "INVENTORY_MISMATCH",
                "Missing or undeclared payload members")
        # Verify retained node bytes after construction closure, not just stream checks.
        for (kind, d), (_, size) in nodes.items():
            check_file(tree / locator({"kind": kind, "sha256": d}), d, size)
        check_file(tree / "manifest.json", self.expected_root, len(raw))
        sync_dir(tree); sync_dir(outputs); sync_dir(dest)
        return {"root_hash": self.expected_root, "manifest": root, "manifest_size_bytes": len(raw),
                "files": files_out, "totals": got_totals, "inventory_scope": "OBSERVED_SELF_CONTAINED",
                "bytes": got_totals["unique_block_bytes"] + got_totals["unique_metadata_bytes"] +
                         logical + len(raw) + len(marker_raw)}


DDL = """
CREATE TABLE store_info (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), store_id TEXT NOT NULL UNIQUE,
 authority_id TEXT NOT NULL, history_id TEXT NOT NULL, authority_epoch INTEGER NOT NULL CHECK(authority_epoch>0),
 health TEXT NOT NULL CHECK(health IN ('HEALTHY','RECOVERY_REQUIRED','INCIDENT')),
 qualification TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE tasks (
 k TEXT PRIMARY KEY, store_id TEXT NOT NULL, campaign TEXT NOT NULL, task_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0), contract BLOB NOT NULL, contract_hash TEXT NOT NULL,
 intake TEXT NOT NULL UNIQUE, intake_dev INTEGER NOT NULL, intake_ino INTEGER NOT NULL,
 selection TEXT NOT NULL CHECK(selection IN ('EXACT_ROOT','ANY_VALID_ENROLLED')),
 status TEXT NOT NULL CHECK(status IN ('OPEN','CLOSED','ACCEPTED')),
 fence INTEGER NOT NULL CHECK(fence>0), approval_boot TEXT NOT NULL,
 approval_until_ns INTEGER NOT NULL, approval_utc TEXT NOT NULL,
 UNIQUE(store_id,campaign,task_id,revision)
);
CREATE TABLE approved_roots (k TEXT NOT NULL REFERENCES tasks(k), root TEXT NOT NULL,
 PRIMARY KEY(k,root));
CREATE TABLE operations (
 o TEXT PRIMARY KEY, verb TEXT NOT NULL, intent BLOB NOT NULL, intent_hash TEXT NOT NULL,
 state TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
 active_ns INTEGER NOT NULL DEFAULT 0, result BLOB, error BLOB, created_at TEXT NOT NULL, checkpoint BLOB,
 active_boot TEXT, active_started INTEGER, next_attempt_ns INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE reservations (o TEXT PRIMARY KEY REFERENCES operations(o), bytes INTEGER NOT NULL CHECK(bytes>=0));
CREATE TABLE invocations (
 j TEXT PRIMARY KEY, o TEXT REFERENCES operations(o), generation INTEGER NOT NULL,
 phase TEXT NOT NULL, state TEXT NOT NULL, pid INTEGER, output_path TEXT NOT NULL,
 started_at TEXT NOT NULL, ended_at TEXT, exit_code INTEGER,
 UNIQUE(o,generation)
);
CREATE TABLE generations (
 g TEXT PRIMARY KEY, root TEXT, path TEXT NOT NULL UNIQUE,
 kind TEXT NOT NULL CHECK(kind IN ('SNAPSHOT','EXPORT')),
 size_bytes INTEGER NOT NULL CHECK(size_bytes>=0), evidence BLOB,
 state TEXT NOT NULL CHECK(state IN ('AVAILABLE','RETIRING','ABSENT','CORRUPT')),
 last_use INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX generations_root ON generations(root,state);
CREATE TABLE pins (
 g TEXT NOT NULL REFERENCES generations(g), owner TEXT NOT NULL, kind TEXT NOT NULL,
 created_at TEXT NOT NULL, PRIMARY KEY(g,owner,kind)
);
CREATE TABLE requests (
 q INTEGER PRIMARY KEY AUTOINCREMENT, o TEXT NOT NULL UNIQUE REFERENCES operations(o),
 k TEXT NOT NULL REFERENCES tasks(k), root TEXT NOT NULL,
 g TEXT NOT NULL REFERENCES generations(g), fence INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('QUEUED','BLOCKED','REJECTED','DECIDED','UNKNOWN')),
 reason TEXT, created_at TEXT NOT NULL
);
CREATE TABLE acceptances (
 a INTEGER PRIMARY KEY AUTOINCREMENT, k TEXT NOT NULL UNIQUE REFERENCES tasks(k),
 root TEXT NOT NULL, o TEXT NOT NULL UNIQUE REFERENCES operations(o),
 q INTEGER NOT NULL UNIQUE REFERENCES requests(q), g TEXT NOT NULL REFERENCES generations(g),
 verification BLOB NOT NULL, receipt BLOB NOT NULL, receipt_hash TEXT NOT NULL UNIQUE,
 created_at TEXT NOT NULL
);
CREATE TABLE receipt_outbox (
 receipt_hash TEXT PRIMARY KEY REFERENCES acceptances(receipt_hash), bytes BLOB NOT NULL,
 intake TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE publications (
 o TEXT PRIMARY KEY REFERENCES operations(o), destination TEXT NOT NULL UNIQUE,
 root TEXT NOT NULL, g TEXT NOT NULL REFERENCES generations(g), state TEXT NOT NULL
);
CREATE TABLE exports (
 o TEXT PRIMARY KEY REFERENCES operations(o), root TEXT NOT NULL,
 source_g TEXT NOT NULL REFERENCES generations(g), output_g TEXT REFERENCES generations(g),
 destination TEXT NOT NULL UNIQUE, state TEXT NOT NULL
);
CREATE TABLE audit (
 ordinal INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, detail BLOB NOT NULL,
 at_utc TEXT NOT NULL
);
"""


class Clock:
    """Boot-scoped sleep-inclusive deadlines; no cloud clock or lease server."""
    def __init__(self) -> None:
        if sys.platform == "darwin":
            self.lib = ctypes.CDLL(None, use_errno=True)
            class Timebase(ctypes.Structure):
                _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]
            tb = Timebase()
            self.lib.mach_timebase_info.argtypes = [ctypes.POINTER(Timebase)]
            self.lib.mach_timebase_info.restype = ctypes.c_int
            require(self.lib.mach_timebase_info(ctypes.byref(tb)) == 0 and tb.denom > 0,
                    "CLOCK_UNQUALIFIED", code=7)
            self.numer, self.denom = tb.numer, tb.denom
            self.lib.mach_continuous_time.argtypes = []
            self.lib.mach_continuous_time.restype = ctypes.c_uint64
            fn = self.lib.sysctlbyname
            fn.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                           ctypes.c_void_p, ctypes.c_size_t]
            fn.restype = ctypes.c_int
            buf = ctypes.create_string_buffer(128); length = ctypes.c_size_t(128)
            require(fn(b"kern.bootsessionuuid", buf, ctypes.byref(length), None, 0) == 0,
                    "CLOCK_UNQUALIFIED", code=7)
            self.boot = buf.value.decode("ascii")
        elif sys.platform.startswith("linux") and hasattr(time, "CLOCK_BOOTTIME"):
            self.boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        else:
            raise CASError("CLOCK_UNQUALIFIED", code=7)

    def ns(self) -> int:
        if sys.platform == "darwin":
            return self.lib.mach_continuous_time() * self.numer // self.denom
        return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


class AuthorityRegistry:
    def __init__(self, config: dict):
        self.config = config
        self.root = Path(config["private_root"])
        self.db_path = self.root / "state.sqlite3"
        self.guard_path = self.root / "locks" / "authority.guard"
        self.clock = Clock()
        try:
            with directory(self.root) as fd:
                st = os.stat("state.sqlite3", dir_fd=fd, follow_symlinks=False)
                require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                        [st.st_dev, st.st_ino] == config["database_identity"],
                        "AUTHORITY_RECOVERY_REQUIRED", code=10)
            with open_regular(self.guard_path) as f:
                st = os.fstat(f.fileno())
                require([st.st_dev, st.st_ino] == config["guard_identity"],
                        "AUTHORITY_RECOVERY_REQUIRED", code=10)
            with self.connection() as con:
                row = con.execute("SELECT * FROM store_info WHERE singleton=1").fetchone()
                require(row is not None and row["store_id"] == config["store_id"] and
                        row["history_id"] == config["history_id"], "AUTHORITY_RECOVERY_REQUIRED", code=10)
        except (OSError, sqlite3.DatabaseError) as exc:
            raise CASError("AUTHORITY_RECOVERY_REQUIRED", str(exc)[:240], 10) from exc

    @contextlib.contextmanager
    def connection(self, readonly: bool = False) -> Iterator[sqlite3.Connection]:
        uri = self.db_path.as_uri() + ("?mode=ro" if readonly else "?mode=rw")
        con = sqlite3.connect(uri, uri=True, autocommit=True, timeout=0.1)
        con.row_factory = sqlite3.Row
        try:
            con.execute("PRAGMA foreign_keys=ON")
            con.execute("PRAGMA mmap_size=0")
            if not readonly:
                con.execute("PRAGMA synchronous=EXTRA")
                con.execute("PRAGMA fullfsync=ON")
            require(con.execute("PRAGMA journal_mode").fetchone()[0] == "delete",
                    "AUTHORITY_RECOVERY_REQUIRED", code=10)
            require(con.execute("PRAGMA foreign_keys").fetchone()[0] == 1,
                    "AUTHORITY_RECOVERY_REQUIRED", code=10)
            require(con.execute("PRAGMA mmap_size").fetchone()[0] == 0,
                    "AUTHORITY_RECOVERY_REQUIRED", code=10)
            if not readonly:
                require(con.execute("PRAGMA fullfsync").fetchone()[0] == 1,
                        "AUTHORITY_RECOVERY_REQUIRED", code=10)
                require(con.execute("PRAGMA synchronous").fetchone()[0] == 3,
                        "AUTHORITY_RECOVERY_REQUIRED", code=10)
            yield con
        finally:
            con.close()

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with open_regular(self.guard_path) as guard:
            deadline = self.clock.ns() + 5000000000
            while True:
                try:
                    fcntl.flock(guard.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    require(self.clock.ns() < deadline, "REGISTRY_CONTENDED", code=3)
                    time.sleep(0.01)
            try:
                with self.connection() as con:
                    con.execute("BEGIN IMMEDIATE")
                    try:
                        health = con.execute("SELECT health FROM store_info").fetchone()[0]
                        require(health == "HEALTHY", "AUTHORITY_RECOVERY_REQUIRED", code=10)
                        yield con
                        try:
                            con.execute("COMMIT")
                        except sqlite3.Error as exc:
                            raise CASError("COMMIT_OUTCOME_UNKNOWN", str(exc)[:240], 9) from exc
                    except BaseException:
                        if con.in_transaction:
                            con.execute("ROLLBACK")
                        raise
            finally:
                fcntl.flock(guard.fileno(), fcntl.LOCK_UN)

    def read(self, sql: str, params: tuple = ()) -> list[dict]:
        with self.connection(readonly=True) as con:
            return [dict(row) for row in con.execute(sql, params)]

    @staticmethod
    def audit(con: sqlite3.Connection, event: str, detail: Any) -> int:
        return con.execute("INSERT INTO audit(event,detail,at_utc) VALUES(?,?,?)",
                           (event, local_json(detail), utc())).lastrowid

    def task(self, intake: str | None = None) -> dict:
        path = intake or self.config["default_intake"]
        rows = self.read("SELECT * FROM tasks WHERE intake=?", (absolute(path),))
        require(len(rows) == 1, "TASK_BINDING_REQUIRED", code=7)
        return rows[0]

    def task_for_leaf(self, leaf: str) -> dict:
        p = Path(absolute(leaf))
        digest(p.name)
        require(p.parent.name == "chunks", "TASK_BINDING_REQUIRED", code=7)
        return self.task(str(p.parent.parent))

    def authorize(self, row: dict | sqlite3.Row, root: str | None,
                  con: sqlite3.Connection | None = None, *, new_effect: bool = True) -> None:
        if new_effect:
            require(row["status"] != "CLOSED", "APPROVAL_REQUIRED", code=6)
            require(row["approval_boot"] == self.clock.boot, "CLOCK_UNQUALIFIED", code=7)
            require(self.clock.ns() < row["approval_until_ns"] and utc() < row["approval_utc"],
                    "APPROVAL_EXPIRED", code=6)
        if root is not None and row["selection"] == "EXACT_ROOT":
            if con is None:
                allowed = self.read("SELECT 1 FROM approved_roots WHERE k=? AND root=?", (row["k"], root))
            else:
                allowed = con.execute("SELECT 1 FROM approved_roots WHERE k=? AND root=?", (row["k"], root)).fetchall()
            require(bool(allowed), "APPROVAL_REQUIRED", "Root not independently approved", 6)

    def bind_operation(self, o: str, verb: str, intent: dict, *, status_only: bool = False) -> dict:
        raw = local_json(intent)
        if status_only:
            rows = self.read("SELECT * FROM operations WHERE o=?", (o,))
            require(bool(rows), "STATUS_ID_REQUIRED", code=2)
            require(rows[0]["intent"] == raw and rows[0]["verb"] == verb, "INTENT_CONFLICT", code=5)
            return rows[0]
        with self.transaction() as con:
            row = con.execute("SELECT * FROM operations WHERE o=?", (o,)).fetchone()
            if row:
                require(row["intent"] == raw and row["verb"] == verb, "INTENT_CONFLICT", code=5)
            else:
                con.execute("INSERT INTO operations(o,verb,intent,intent_hash,state,created_at) VALUES(?,?,?,?,?,?)",
                            (o, verb, raw, sha(raw), "PENDING", utc()))
                row = con.execute("SELECT * FROM operations WHERE o=?", (o,)).fetchone()
            return dict(row)

    def finish(self, o: str, result: dict) -> None:
        with self.transaction() as con:
            con.execute("UPDATE operations SET state='DONE',result=?,error=NULL WHERE o=?",
                        (local_json(result), o))

    def fail(self, o: str, exc: CASError) -> None:
        state = "UNKNOWN" if exc.code == 9 else "HOLD_RETRY" if exc.code == 3 else "REJECTED"
        if exc.code in (6, 7, 8, 10): state = "HOLD_AUTHORITY" if exc.code in (6, 7, 10) else "HOLD_RESOURCE"
        with self.transaction() as con:
            con.execute("UPDATE operations SET state=?,error=? WHERE o=? AND state!='DONE'",
                        (state, local_json({"reason": exc.reason, "code": exc.code, "message": str(exc)}), o))
            if state in ("REJECTED", "HOLD_AUTHORITY"):
                con.execute("DELETE FROM reservations WHERE o=?", (o,))
            if exc.reason == "HASH_IDENTITY_INCIDENT":
                self.audit(con, "HASH_IDENTITY_INCIDENT", {"o": o})
                con.execute("UPDATE store_info SET health='INCIDENT'")

    def save_checkpoint(self, o: str, checkpoint: dict) -> None:
        with self.transaction() as con:
            con.execute("UPDATE operations SET checkpoint=? WHERE o=?", (local_json(checkpoint), o))

    def reserve(self, o: str, needed: int) -> None:
        fs = os.statvfs(self.root)
        free = fs.f_bavail * fs.f_frsize; total = fs.f_blocks * fs.f_frsize
        floor = max(self.config["reserve_bytes"], total * self.config["reserve_fraction_milli"] // 1000)
        with self.transaction() as con:
            other = con.execute("SELECT COALESCE(SUM(bytes),0) FROM reservations WHERE o!=?", (o,)).fetchone()[0]
            require(needed + other + floor <= free, "DISK_RESERVE_REQUIRED", code=8)
            con.execute("INSERT INTO reservations VALUES(?,?) ON CONFLICT(o) DO UPDATE SET bytes=excluded.bytes",
                        (o, needed))

    def begin_transport(self, o: str) -> None:
        now = self.clock.ns()
        with self.transaction() as con:
            row = con.execute("SELECT * FROM operations WHERE o=?", (o,)).fetchone()
            used = row["active_ns"]
            if row["active_started"] is not None:
                require(row["active_boot"] == self.clock.boot, "HOLD_RETRY", "Interrupted retry clock epoch", 3)
                used += max(0, now - row["active_started"])
            require(row["attempts"] < 8 and used < 900000000000, "HOLD_RETRY", code=3)
            require(row["active_boot"] in (None, self.clock.boot), "HOLD_RETRY", code=3)
            require(now >= row["next_attempt_ns"], "RETRY_BACKOFF", code=3)
            con.execute("UPDATE operations SET attempts=attempts+1,active_ns=?,active_started=?,active_boot=? WHERE o=?",
                        (used, now, self.clock.boot, o))

    def end_transport(self, o: str, success: bool) -> None:
        now = self.clock.ns()
        with self.transaction() as con:
            row = con.execute("SELECT * FROM operations WHERE o=?", (o,)).fetchone()
            elapsed = max(0, now - (row["active_started"] or now))
            ceiling = min(64, 2 ** min(6, max(0, row["attempts"]-1)))
            delay = 0 if success else int(random.SystemRandom().uniform(ceiling/2, ceiling) * 1e9)
            con.execute("UPDATE operations SET active_ns=active_ns+?,active_started=NULL,next_attempt_ns=? WHERE o=?",
                        (elapsed, now+delay, o))

    def register_snapshot(self, g: str, path: str, evidence: dict, owner: str) -> None:
        with self.transaction() as con:
            ordinal = self.audit(con, "SNAPSHOT_VERIFIED", {"g": g, "root": evidence["root_hash"]})
            con.execute("INSERT INTO generations VALUES(?,?,?,?,?,?,?,?,?)",
                        (g, evidence["root_hash"], path, "SNAPSHOT", evidence["bytes"],
                         local_json(evidence), "AVAILABLE", ordinal, utc()))
            con.execute("INSERT INTO pins VALUES(?,?,?,?)", (g, owner, "PREPARATION", utc()))

    def pin_root(self, root: str, owner: str) -> dict:
        with self.transaction() as con:
            row = con.execute("SELECT * FROM generations WHERE root=? AND kind='SNAPSHOT' AND state='AVAILABLE' "
                              "ORDER BY last_use DESC,g LIMIT 1", (root,)).fetchone()
            require(row is not None, "FILE_MAP_UNAVAILABLE", "No enrolled private root layout", 7)
            con.execute("INSERT OR IGNORE INTO pins VALUES(?,?,?,?)", (row["g"], owner, "READER", utc()))
            ordinal = self.audit(con, "READER_PINNED", {"g": row["g"], "owner": owner})
            con.execute("UPDATE generations SET last_use=? WHERE g=?", (ordinal, row["g"]))
            return dict(row)


# ---- Worker side: no registry, no authority capability, no shell, no network API. ----
def _binding(path: str, expected: list | None = None) -> list:
    with directory(path) as fd:
        st = os.fstat(fd); value = [st.st_dev, st.st_ino]
        require(expected is None or value == expected, "TRANSPORT_UNQUALIFIED", code=7)
        return value


def _copy_tree(source: Path, target: Path) -> None:
    target.mkdir(mode=0o700)
    for rel in sorted(inventory(source)):
        with open_regular(source / rel) as inp:
            d, n = stream_digest(inp)
        copy_checked(source / rel, target / rel, d, n)
    # Bottom-up directory sync: reject failures; never call them cloud completion.
    for root, dirs, _ in os.walk(target, topdown=False):
        sync_dir(root)


def _check_outputs(snapshot: str, evidence: dict) -> None:
    for file in evidence["files"]:
        check_file(Path(snapshot) / "files" / file["path"], file["sha256"], file["size_bytes"])


def _worker_action(kind: str, a: dict, work: Path) -> dict:
    if kind == "enroll_intake":
        identity = _binding(a["path"], a.get("binding"))
        with directory(a["path"]) as fd:
            for name in ("chunks", "receipts"):
                try: os.mkdir(name, 0o700, dir_fd=fd)
                except FileExistsError: pass
                sub = os.open(name, DIR_FLAGS, dir_fd=fd); os.close(sub)
            os.fsync(fd)
        return {"identity": identity}
    if kind == "check_single":
        check_file(a["path"], a["sha256"], a["size_bytes"])
        return {"checked": True}
    if kind == "inspect_source":
        with open_regular(a["path"]) as inp:
            info = os.fstat(inp.fileno())
            return {"size_bytes": info.st_size, "dataless_observed": bool(
                getattr(info, "st_flags", 0) & getattr(stat, "SF_DATALESS", 0))}
    if kind == "inspect_manifest":
        _binding(a["intake"], a["binding"])
        raw = read_limited(Path(a["source"]) / "manifest.json")
        require(sha(raw) == a["root"], "ROOT_MISMATCH")
        value = decode(raw)
        totals = fields(value["totals"], TOTAL_FIELDS)
        for n in totals.values(): uint(n)
        require(totals["logical_bytes"] <= a["max_bytes"] and
                totals["unique_metadata_bytes"] <= MAX_METADATA_BYTES, "RESOURCE_LIMIT", code=8)
        return {"reserve_bytes": 8 * totals["logical_bytes"] + 4 * totals["unique_metadata_bytes"] + MAX_JSON}
    if kind == "bind":
        return {"identity": _binding(a["path"]), "probe": AtomicPublisher.probe(a["path"]) if a.get("probe") else None}
    if kind == "build":
        return CASChunkManager.build(a["sources"], a["contract"], a["output"],
                                     a["producer"], a["installation"], a["attempt"], a["layout"], a.get("capture_limit"))
    if kind == "capture":
        if a.get("binding"):
            _binding(a["intake"], a["binding"])
        return MerkleVerifier(a["contract"], a["root"]).capture(a["source"], a["output"])
    if kind == "check_outputs":
        _check_outputs(a["snapshot"], a["evidence"])
        return {"checked": True}
    if kind == "publish":
        _binding(a["intake"], a["binding"])
        source = Path(a["source"])
        parent = Path(a["intake"]) / "chunks"
        # Existing enrolled parent only. No recursive creation of a missing mount.
        with directory(parent):
            pass
        final = parent / a["root"]
        try:
            with directory(final): pass
        except FileNotFoundError:
            pass
        else:
            MerkleVerifier(a["contract"], a["root"]).capture(final, work / "existing_check")
            require(inventory(source) == inventory(final), "SOURCE_CONFLICT", code=5)
            for rel in sorted(inventory(source)):
                require(identical(source / rel, final / rel), "SOURCE_CONFLICT", code=5)
            return {"submission_dir": str(final), "local_publication": "IDENTICAL_EXISTING",
                    "remote_evidence": "NOT_ASSERTED"}
        stage = parent / (".staging-" + a["invocation"])
        _copy_tree(source, stage)
        MerkleVerifier(a["contract"], a["root"]).capture(stage, work / "stage_check")
        try:
            AtomicPublisher.rename(stage, final)
            disposition = "INSTALLED"
        except FileExistsError:
            MerkleVerifier(a["contract"], a["root"]).capture(final, work / "existing_check")
            require(inventory(source) == inventory(final), "SOURCE_CONFLICT", code=5)
            for rel in sorted(inventory(source)):
                require(identical(source / rel, final / rel), "SOURCE_CONFLICT", code=5)
            disposition = "IDENTICAL_EXISTING"
            # Do not delete anything from Drive, including abandoned staging.
        return {"submission_dir": str(final), "local_publication": disposition,
                "remote_evidence": "NOT_ASSERTED"}
    if kind == "export":
        src, target = Path(a["source"]), Path(a["destination"])
        with directory(target.parent):
            pass
        stage = target.parent / (".cas-export-" + a["invocation"])
        copy_checked(src, stage, a["sha256"], a["size_bytes"])
        try:
            AtomicPublisher.rename(stage, target)
        except FileExistsError:
            if not a["reconcile"]:
                raise CASError("OUTPUT_EXISTS", str(target), 5)
            check_file(target, a["sha256"], a["size_bytes"])
            require(identical(stage, target), "HASH_IDENTITY_INCIDENT", code=10)
            stage.unlink()  # approved private export root, never Drive
        check_file(target, a["sha256"], a["size_bytes"])
        return {"output_path": str(target)}
    if kind == "receipt":
        _binding(a["intake"], a["binding"])
        parent = Path(a["intake"]) / "receipts"
        with directory(parent):
            pass
        raw = a["receipt"].encode("ascii")
        require(sha(raw) == a["sha256"], "DIGEST_MISMATCH")
        stage = parent / (".receipt-" + a["invocation"])
        write_new(stage, raw)
        target = parent / (a["sha256"] + ".json")
        try:
            AtomicPublisher.rename(stage, target)
        except FileExistsError:
            require(read_limited(target) == raw, "SOURCE_CONFLICT", code=5)
        return {"receipt_export": "LOCAL_PUBLISHED"}
    if kind == "remove":
        path = Path(a["path"])
        private = absolute(a["private_root"])
        require(within(absolute(path), private) and path.parent.name in ("generations", "exports"),
                "UNSAFE_RECLAMATION", code=10)
        if not path.exists():
            return {"removed": True}
        # Never traverse a symlink while reclaiming. Tree was built only by this engine.
        inventory(path)
        shutil.rmtree(path)
        sync_dir(path.parent)
        return {"removed": True}
    raise CASError("INVALID_WORKER_JOB")


def _worker_main(job_file: str) -> int:
    try:
        raw = read_limited(job_file, MAX_CONTROL)
        job = decode(raw, wire=False, limit=MAX_CONTROL)
        fields(job, "protocol invocation kind args")
        require(job["protocol"] == "gdoe-worker-file/1", "INVALID_WORKER_JOB")
        uuid_value(job["invocation"])
        work = Path(job_file).parent
        result = _worker_action(job["kind"], job["args"], work)
        evidence = local_json(result)
        require(len(evidence) <= MAX_JSON, "RESULT_SIZE_LIMIT")
        write_new(work / "evidence.json", evidence)
        reply = {"invocation": job["invocation"], "ok": True,
                 "sha256": sha(evidence), "size_bytes": len(evidence)}
        sys.stdout.buffer.write(local_json(reply)); sys.stdout.buffer.flush()
        return 0
    except CASError as exc:
        reply = {"ok": False, "reason": exc.reason, "code": exc.code, "message": str(exc)[:800]}
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ENETDOWN, errno.ETIMEDOUT, errno.EAGAIN):
            reason, code = "PENDING_CONTENT", 3
        elif exc.errno in (errno.ENOSPC, errno.EDQUOT):
            reason, code = "HOLD_RESOURCE", 8
        elif exc.errno in (errno.ELOOP, errno.ENOTDIR):
            reason, code = "UNSAFE_FILE_TYPE", 4
        else:
            reason, code = "FILESYSTEM_ERROR", 3
        reply = {"ok": False, "reason": reason, "code": code, "message": str(exc)[:800]}
    except Exception as exc:
        reply = {"ok": False, "reason": "INTERNAL_CONTRACT_BREACH", "code": 11,
                 "message": type(exc).__name__ + ": " + str(exc)[:800]}
    sys.stdout.buffer.write(local_json(reply)); sys.stdout.buffer.flush()
    return reply["code"]


class WorkerSupervisor:
    """Two inherited kernel slot locks bound all workers, even after caller death.

    Slots are NOT authority locks. A hung child's inherited fd keeps its slot;
    closing the parent's fd must not issue LOCK_UN and unlock the child as well.
    """
    def __init__(self, root: str | Path, registry: AuthorityRegistry | None = None):
        self.root = Path(root); self.registry = registry
        self.clock = registry.clock if registry is not None else Clock()
        self.last_invocation: str | None = None
        self._op_guards: dict[str, int] = {}

    def run(self, kind: str, args: dict, *, timeout: float = 120,
            operation: str | None = None) -> dict:
        slot = None
        for index in range(2):
            fd = os.open(self.root / "slots" / str(index), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                slot = fd; break
            except BlockingIOError:
                os.close(fd)
        require(slot is not None, "WORKER_CIRCUIT_OPEN", code=8)
        try:
            return self._run_in_slot(slot, kind, args, timeout=timeout, operation=operation)
        finally:
            os.close(slot)  # closing is NOT LOCK_UN on the child's shared description

    def _run_in_slot(self, slot: int, kind: str, args: dict, *, timeout: float,
                     operation: str | None) -> dict:
        j = new_id(); self.last_invocation = j
        work = self.root / "jobs" / j; work.mkdir(mode=0o700)
        a = dict(args); a["invocation"] = j
        job = {"protocol": "gdoe-worker-file/1", "invocation": j, "kind": kind, "args": a}
        request = local_json(job)
        require(len(request) <= MAX_CONTROL, "WORKER_REQUEST_LIMIT")
        write_new(work / "request.json", request)
        generation = 0
        if operation is not None and self.registry:
            with self.registry.transaction() as con:
                op = con.execute("SELECT * FROM operations WHERE o=?", (operation,)).fetchone()
                require(op is not None, "INTERNAL_CONTRACT_BREACH", code=11)
                generation = op["generation"] + 1
                con.execute("UPDATE operations SET generation=? WHERE o=?", (generation, operation))
                con.execute("INSERT INTO invocations VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (j, operation, generation, kind, "RUNNING", None, str(work), utc(), None, None))
        process = None; out = bytearray(); err = bytearray(); dropped = 0
        started = self.clock.ns()
        op_guard = self._op_guards.get(operation) if operation is not None else None
        inherited = [slot]
        dup_op = None
        if op_guard is not None:
            dup_op = os.dup(op_guard)
            inherited.append(dup_op)
        try:
            try:
                process = subprocess.Popen([sys.executable, "-I", str(Path(__file__).absolute()),
                                            "--_worker", str(work / "request.json")],
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           close_fds=True, pass_fds=tuple(inherited))
            finally:
                if dup_op is not None:
                    os.close(dup_op)
            if operation is not None and self.registry:
                with self.registry.transaction() as con:
                    con.execute("UPDATE invocations SET pid=? WHERE j=?", (process.pid, j))
            with selectors.DefaultSelector() as selector:
                for stream, name in ((process.stdout, "out"), (process.stderr, "err")):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                while True:
                    require((self.clock.ns() - started) / 1e9 < timeout, "PUBLICATION_OUTCOME_UNKNOWN"
                            if kind in ("publish", "export", "receipt", "remove") else "WAIT_BUDGET_EXHAUSTED",
                            "Worker deadline reached; no result certified", 9 if kind in
                            ("publish", "export", "receipt", "remove") else 3)
                    for key, _ in selector.select(0.05):
                        data = os.read(key.fileobj.fileno(), 16384)
                        if not data:
                            selector.unregister(key.fileobj)
                        elif key.data == "out":
                            out.extend(data)
                            require(len(out) <= MAX_CONTROL, "WORKER_PROTOCOL_LIMIT")
                        else:
                            remaining = max(0, 256 * 1024 - len(err))
                            err.extend(data[:remaining]); dropped += max(0, len(data) - remaining)
                    # Poll even while a pipe remains registered. After direct-child exit,
                    # drain all immediately available bytes but never wait for another
                    # process to close an inherited pipe. Missing/invalid final data fails.
                    if process.poll() is not None and not selector.select(0):
                        break
                rc = process.wait(timeout=0.1)
            write_new(work / "stderr.bin", bytes(err))
            write_new(work / "exit.json", local_json({"returncode": rc, "stderr_dropped": dropped}))
            if rc < 0:
                raise CASError("WORKER_SIGNAL", signal.Signals(-rc).name, 3)
            reply = decode(bytes(out), wire=False, limit=MAX_CONTROL)
            require(type(reply) is dict and type(reply.get("ok")) is bool, "WORKER_PROTOCOL_LIMIT")
            if not reply["ok"]:
                raise CASError(reply.get("reason", "WORKER_FAILED"), reply.get("message", ""),
                               int(reply.get("code", 11)))
            require(rc == 0 and reply["invocation"] == j, "WORKER_PROTOCOL_LIMIT")
            evidence = read_limited(work / "evidence.json", MAX_JSON)
            require(len(evidence) == reply["size_bytes"] and sha(evidence) == reply["sha256"],
                    "WORKER_EVIDENCE_MISMATCH")
            result = decode(evidence, wire=False, limit=MAX_JSON)
            # These are closed, attempt-private checker copies, not provider objects.
            for scratch in (work / "stage_check", work / "existing_check"):
                if scratch.exists(): shutil.rmtree(scratch)
            if operation is not None and self.registry:
                with self.registry.transaction() as con:
                    con.execute("UPDATE invocations SET state='CLOSED',ended_at=?,exit_code=? WHERE j=?",
                                (utc(), rc, j))
            return result
        except BaseException:
            if process is not None and process.poll() is None:
                with contextlib.suppress(ProcessLookupError): process.kill()
                try:
                    process.wait(timeout=0.25)
                except subprocess.TimeoutExpired:
                    pass  # inherited slot remains occupied, output generation never reassigned
            if operation is not None and self.registry:
                with contextlib.suppress(CASError, sqlite3.Error):
                    with self.registry.transaction() as con:
                        con.execute("UPDATE invocations SET state=?,ended_at=?,exit_code=? WHERE j=?",
                                    ("CLOSED_FAILED" if process is None or process.poll() is not None else "UNREAPED",
                                     utc(), None if process is None else process.poll(), j))
            raise
        finally:
            if process is not None:
                for stream in (process.stdout, process.stderr):
                    if stream is not None: stream.close()


def load_config(path: str | Path) -> dict:
    c = decode(read_limited(path, 1024 * 1024), wire=False, limit=1024 * 1024)
    fields(c, "protocol store_id installation_id authority_id history_id role private_root exchange_root "
              "exchange_identity default_intake export_roots database_identity guard_identity engine_sha256 "
              "reserve_bytes reserve_fraction_milli max_file_bytes max_task_bytes qualification_mode")
    require(c["protocol"] == "gdoe-config/2", "CONFIGURATION_UNSUPPORTED", code=7)
    for key in ("store_id", "installation_id", "authority_id", "history_id"): uuid_value(c[key])
    require(c["role"] in ("authority", "producer"), "CONFIGURATION_UNSUPPORTED", code=7)
    require(c["engine_sha256"] == sha(Path(__file__).read_bytes()), "BUILD_REENROLLMENT_REQUIRED", code=7)
    require(not within(c["private_root"], c["exchange_root"]) and
            not within(c["exchange_root"], c["private_root"]), "UNSAFE_PRIVATE_ROOT", code=7)
    for name in ("reserve_bytes", "reserve_fraction_milli", "max_file_bytes", "max_task_bytes"): uint(c[name])
    return c


def enroll_store(config_path: str | Path, private_root: str | Path, exchange_root: str | Path,
                 *, export_roots: list[str] | None = None, role: str = "authority",
                 reserve_bytes: int = 2 * 1024**3, reserve_fraction_milli: int = 50) -> dict:
    """Explicit trusted administration, not a data-plane auto-bootstrap.

    The caller attests that private/config/export locations are unsynchronized.
    Creates a NEW private store only. Never repairs or overwrites an old store.
    All initial receipts are candidate evidence, not production qualification.
    """
    config_path = Path(absolute(config_path)); private_root = Path(absolute(private_root))
    exchange = absolute(exchange_root)
    require(not config_path.exists() and not private_root.exists(), "ENROLLMENT_EXISTS", code=5)
    require(not within(str(private_root), exchange) and not within(exchange, str(private_root))
            and not within(str(config_path), exchange), "UNSAFE_PRIVATE_ROOT", code=7)
    require(role in ("authority", "producer"), "INVALID_ROLE")
    uint(reserve_bytes); uint(reserve_fraction_milli, 0, 1000)
    private_root.mkdir(mode=0o700, parents=True)
    for sub in ("locks", "operation_locks", "slots", "jobs", "generations", "staging", "exports", "quarantine"):
        (private_root / sub).mkdir(mode=0o700)
    write_new(private_root / "locks" / "authority.guard", b"")
    for i in range(2): write_new(private_root / "slots" / str(i), b"")
    supervisor = WorkerSupervisor(private_root)
    bound = supervisor.run("bind", {"path": exchange, "probe": False}, timeout=30)
    # Root already exists. Administrative creation of children is in the worker.
    supervisor.run("enroll_intake", {"path": exchange, "binding": bound["identity"]}, timeout=30)
    c = {"protocol": "gdoe-config/2", "store_id": new_id(), "installation_id": new_id(),
         "authority_id": new_id(), "history_id": new_id(), "role": role,
         "private_root": str(private_root), "exchange_root": exchange,
         "exchange_identity": bound["identity"], "default_intake": exchange,
         "export_roots": [absolute(p) for p in (export_roots or [])],
         "database_identity": None, "guard_identity": None,
         "engine_sha256": sha(Path(__file__).read_bytes()),
         "reserve_bytes": reserve_bytes, "reserve_fraction_milli": reserve_fraction_milli,
         "max_file_bytes": 64 * 1024**3, "max_task_bytes": 128 * 1024**3,
         "qualification_mode": "CANDIDATE_ONLY"}
    for p in c["export_roots"]:
        require(not within(p, exchange) and not within(p, str(private_root)), "UNSAFE_EXPORT_ROOT", code=7)
        with directory(p): pass
    db_path = private_root / "state.sqlite3"
    with sqlite3.connect(db_path, autocommit=True) as con:
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("PRAGMA synchronous=EXTRA")
        con.execute("PRAGMA foreign_keys=ON")
        con.executescript(DDL)
        con.execute("INSERT INTO store_info VALUES(1,?,?,?,?,?,?,?)",
                    (c["store_id"], c["authority_id"], c["history_id"], 1, "HEALTHY", "CANDIDATE_ONLY", utc()))
    os.chmod(db_path, 0o600)
    for name, key in ((db_path, "database_identity"), (private_root / "locks" / "authority.guard", "guard_identity")):
        s = name.stat(); c[key] = [s.st_dev, s.st_ino]
    sync_dir(private_root)
    config_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    write_new(config_path, local_json(c)); sync_dir(config_path.parent)
    return c


def artifact_slot(path: str, *, allow_empty: bool = False, max_size_bytes: int = 64 * 1024**3,
                  expected_sha256: str | None = None, role: str = "artifact",
                  media_type: str = "application/octet-stream") -> dict:
    return {"path": logical_path(path), "role": role, "media_type": media_type,
            "allow_empty": int(allow_empty), "max_size_bytes": max_size_bytes,
            "expected_sha256": expected_sha256,
            "source_scope": "EXPECTED_DIGEST" if expected_sha256 is not None else "CAPTURED_BYTES"}


def enroll_task(config_path: str | Path, *, campaign: str, task_id: str, revision: int = 1,
                artifacts: list[dict], intake: str | None = None,
                selection: str = "EXACT_ROOT", approval_seconds: int = 3600,
                layouts: list[str] | None = None) -> dict:
    c = load_config(config_path); reg = AuthorityRegistry(c)
    intake = absolute(intake or c["default_intake"])
    require(within(intake, c["exchange_root"]), "READ_SCOPE_DENIED", code=6)
    require(selection in ("EXACT_ROOT", "ANY_VALID_ENROLLED"), "INVALID_POLICY")
    uint(approval_seconds, 1, 604800)
    result = WorkerSupervisor(reg.root).run("enroll_intake", {"path": intake}, timeout=30)
    contract = {"kind": "task_contract", "schema_version": 1, "store_id": c["store_id"],
                "campaign": campaign, "task_id": task_id, "task_revision": revision,
                "artifacts": sorted(artifacts, key=lambda x: x["path"]),
                "max_logical_bytes": c["max_task_bytes"], "layouts": layouts or list(LAYOUTS)}
    validate_contract(contract); raw = canonical(contract); k = canonical(list(contract_key(contract))).decode()
    expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=approval_seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    with reg.transaction() as con:
        con.execute("INSERT INTO tasks VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (k, c["store_id"], campaign, task_id, revision, raw, sha(raw), intake,
                     *result["identity"], selection, "OPEN", 1, reg.clock.boot,
                     reg.clock.ns() + approval_seconds * 1000000000, expiry))
        reg.audit(con, "TASK_ENROLLED", {"k": k, "contract_sha256": sha(raw), "selection": selection})
    return contract


def approve_candidate(config_path: str | Path, root_hash: str, *, intake: str | None = None) -> None:
    c = load_config(config_path); reg = AuthorityRegistry(c); row = reg.task(intake)
    digest(root_hash)
    with reg.transaction() as con:
        con.execute("INSERT OR IGNORE INTO approved_roots VALUES(?,?)", (row["k"], root_hash))
        reg.audit(con, "ROOT_APPROVED", {"k": row["k"], "root": root_hash})


def release_export(config_path: str | Path, operation_id: str, *, reason: str) -> None:
    require(bool(reason.strip()), "RELEASE_REASON_REQUIRED")
    reg = AuthorityRegistry(load_config(config_path))
    with reg.transaction() as con:
        row = con.execute("SELECT * FROM exports WHERE o=? AND state='DONE'", (operation_id,)).fetchone()
        require(row is not None, "EXPORT_NOT_COMPLETE", code=5)
        con.execute("DELETE FROM pins WHERE owner=? AND kind IN ('READER','EXPORT')", (operation_id,))
        con.execute("UPDATE exports SET state='RELEASED' WHERE o=?", (operation_id,))
        reg.audit(con, "EXPORT_RELEASED", {"o": operation_id, "reason": reason[:512]})


def enter_recovery(config_path: str | Path, reason: str) -> None:
    reg = AuthorityRegistry(load_config(config_path))
    with reg.transaction() as con:
        reg.audit(con, "RECOVERY_BARRIER", {"reason": reason[:512]})
        con.execute("UPDATE store_info SET health='RECOVERY_REQUIRED'")


def open_retry_window(config_path: str | Path, operation_id: str, *, reason: str) -> None:
    """Explicit operator action; does not change content, approval, K, source or O."""
    require(bool(reason.strip()), "RETRY_REASON_REQUIRED")
    reg = AuthorityRegistry(load_config(config_path))
    with reg.transaction() as con:
        row = con.execute("SELECT * FROM operations WHERE o=?", (operation_id,)).fetchone()
        require(row is not None and row["state"] != "DONE", "RETRY_NOT_APPLICABLE", code=5)
        require(not con.execute("SELECT 1 FROM invocations WHERE o=? AND state IN ('RUNNING','UNREAPED')",
                                (operation_id,)).fetchone(), "WORKER_OWNERSHIP_UNRESOLVED", code=9)
        con.execute("UPDATE operations SET attempts=0,active_ns=0,active_started=NULL,active_boot=?,next_attempt_ns=0 WHERE o=?",
                    (reg.clock.boot, operation_id))
        reg.audit(con, "RETRY_WINDOW_OPENED", {"o": operation_id, "reason": reason[:512]})


class DropzoneAdmissionBroker:
    def __init__(self, registry: AuthorityRegistry):
        self.reg = registry

    def request_admission(self, o: str, row: dict, root: str, g: str) -> int:
        require(self.reg.config["role"] == "authority", "AUTHORITY_LOCAL_ONLY", code=6)
        with self.reg.transaction() as con:
            intent_row = con.execute("SELECT verb,intent FROM operations WHERE o=?", (o,)).fetchone()
            require(intent_row is not None and intent_row["verb"] == "commit", "INTENT_CONFLICT", code=5)
            intent = decode(intent_row["intent"], wire=False)
            require(intent.get("root") == root and intent.get("k") == row["k"], "INTENT_CONFLICT", code=5)
            old = con.execute("SELECT * FROM requests WHERE o=?", (o,)).fetchone()
            if old:
                require(old["k"] == row["k"] and old["root"] == root, "INTENT_CONFLICT", code=5)
                return old["q"]
            task = con.execute("SELECT * FROM tasks WHERE k=?", (row["k"],)).fetchone()
            self.reg.authorize(task, root, con)
            gen = con.execute("SELECT * FROM generations WHERE g=?", (g,)).fetchone()
            require(gen is not None and gen["root"] == root and gen["state"] == "AVAILABLE",
                    "VERIFICATION_UNQUALIFIED", code=7)
            captured = decode(gen["evidence"], wire=False)
            require(captured["manifest"]["contract_sha256"] == task["contract_hash"] and
                    canonical(list(contract_key(captured["manifest"]))).decode() == task["k"],
                    "CONTRACT_MISMATCH", "A private snapshot cannot cross task bindings")
            require(con.execute("SELECT 1 FROM pins WHERE g=?", (g,)).fetchone() is not None,
                    "VERIFICATION_UNQUALIFIED", code=7)
            con.execute("INSERT OR IGNORE INTO pins VALUES(?,?,?,?)", (g, o, "ADMISSION", utc()))
            q = con.execute("INSERT INTO requests(o,k,root,g,fence,state,created_at) VALUES(?,?,?,?,?,'QUEUED',?)",
                            (o, task["k"], root, g, task["fence"], utc())).lastrowid
            return q

    def advance_admission_queue(self) -> list[dict]:
        decisions = []
        # Registry-only transaction: no provider access, hashing of payloads or IPC.
        with self.reg.transaction() as con:
            pending = con.execute("SELECT * FROM requests WHERE state IN ('QUEUED','UNKNOWN') ORDER BY q LIMIT 32").fetchall()
            for req in pending:
                if req["state"] == "UNKNOWN":
                    break
                old = con.execute("SELECT * FROM acceptances WHERE k=?", (req["k"],)).fetchone()
                if old:
                    state = "DECIDED" if old["root"] == req["root"] else "REJECTED"
                    reason = "IDENTICAL_ACCEPTANCE" if state == "DECIDED" else "TASK_ALREADY_ACCEPTED"
                    con.execute("UPDATE requests SET state=?,reason=? WHERE q=?", (state, reason, req["q"]))
                    continue
                task = con.execute("SELECT * FROM tasks WHERE k=?", (req["k"],)).fetchone()
                try:
                    self.reg.authorize(task, req["root"], con)
                    require(task["fence"] == req["fence"], "STALE_FENCE", code=6)
                    gen = con.execute("SELECT * FROM generations WHERE g=?", (req["g"],)).fetchone()
                    require(gen["state"] == "AVAILABLE" and con.execute(
                            "SELECT 1 FROM pins WHERE g=? AND owner=? AND kind='ADMISSION'",
                            (req["g"], req["o"])).fetchone() is not None, "VERIFICATION_UNQUALIFIED", code=7)
                except CASError as exc:
                    con.execute("UPDATE requests SET state='BLOCKED',reason=? WHERE q=?", (exc.reason, req["q"]))
                    continue
                ev = decode(gen["evidence"], wire=False)
                store = con.execute("SELECT * FROM store_info").fetchone()
                # This release deliberately cannot self-issue a production durability tier.
                verification = {"kind": "candidate_verification_evidence", "schema_version": 1,
                    "receipt_id": new_id(), "store_id": store["store_id"], "root_hash": req["root"],
                    "contract_sha256": task["contract_hash"], "snapshot_id": req["g"],
                    "scope": "FULL_CLOSURE", "contract_result": "MATCH", "totals": ev["totals"],
                    "verified_at_utc": utc(), "qualification": "NOT_GRANTED", "remote_evidence": "NOT_ASSERTED"}
                vbytes = canonical(verification)
                seq = con.execute("SELECT COALESCE(MAX(a),0)+1 FROM acceptances").fetchone()[0]
                receipt = {"kind": "candidate_acceptance_receipt", "schema_version": 1,
                    "receipt_id": new_id(), "operation_id": req["o"], "store_id": store["store_id"],
                    "campaign": task["campaign"], "task_id": task["task_id"], "task_revision": task["revision"],
                    "contract_sha256": task["contract_hash"], "submission_sha256": req["root"],
                    "verification_receipt_sha256": sha(vbytes), "authority_id": store["authority_id"],
                    "authority_epoch": store["authority_epoch"], "fence_epoch": task["fence"],
                    "decision_sequence": seq, "accepted_at_utc": utc(), "state": "ACCEPTED_LOCAL",
                    "semantic_review": "NOT_ASSESSED", "qualification": "NOT_GRANTED"}
                rbytes = canonical(receipt); rh = sha(rbytes)
                con.execute("INSERT INTO acceptances VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (seq, req["k"], req["root"], req["o"], req["q"], req["g"],
                             vbytes, rbytes, rh, utc()))
                con.execute("INSERT INTO receipt_outbox VALUES(?,?,?,'PENDING',0)", (rh, rbytes, task["intake"]))
                con.execute("INSERT OR IGNORE INTO pins VALUES(?,?,?,?)", (req["g"], req["k"], "ACCEPTANCE", utc()))
                con.execute("DELETE FROM pins WHERE g=? AND owner=? AND kind='ADMISSION'", (req["g"], req["o"]))
                con.execute("UPDATE tasks SET status='ACCEPTED' WHERE k=?", (req["k"],))
                con.execute("UPDATE requests SET state='DECIDED',reason='ACCEPTED_LOCAL' WHERE q=?", (req["q"],))
                self.reg.audit(con, "ACCEPTED_LOCAL", {"k": req["k"], "root": req["root"], "q": req["q"], "a": seq})
                decisions.append(receipt)
        return decisions

    def lookup(self, k: str) -> dict | None:
        rows = self.reg.read("SELECT * FROM acceptances WHERE k=?", (k,))
        return rows[0] if rows else None


class LocalCacheEvictor:
    def __init__(self, registry: AuthorityRegistry, supervisor: WorkerSupervisor):
        self.reg, self.supervisor = registry, supervisor

    def prune(self, target: int, *, dry_run: bool = False, operation: str | None = None) -> dict:
        uint(target)
        rows = self.reg.read("SELECT g.*,EXISTS(SELECT 1 FROM pins p WHERE p.g=g.g) AS pinned "
                             "FROM generations g WHERE g.state!='ABSENT' ORDER BY last_use,g")
        before = sum(r["size_bytes"] for r in rows)
        floor = sum(r["size_bytes"] for r in rows if r["pinned"] or r["state"] == "CORRUPT")
        candidates = [r for r in rows if not r["pinned"] and r["state"] in ("AVAILABLE", "RETIRING")]
        removed = count = skipped = 0
        if not dry_run:
            for row in candidates:
                if before - removed <= target and row["state"] != "RETIRING": break
                with self.reg.transaction() as con:
                    has_pin = con.execute("SELECT 1 FROM pins WHERE g=?", (row["g"],)).fetchone()
                    current = con.execute("SELECT state FROM generations WHERE g=?", (row["g"],)).fetchone()[0]
                    if has_pin or current not in ("AVAILABLE", "RETIRING"):
                        skipped += 1; continue
                    con.execute("UPDATE generations SET state='RETIRING' WHERE g=?", (row["g"],))
                self.supervisor.run("remove", {"path": row["path"], "private_root": str(self.reg.root)},
                                    operation=operation)
                with self.reg.transaction() as con:
                    con.execute("UPDATE generations SET state='ABSENT' WHERE g=? AND state='RETIRING'", (row["g"],))
                    self.reg.audit(con, "GENERATION_REMOVED", {"g": row["g"]})
                removed += row["size_bytes"]; count += 1
            registered = {r["g"] for r in self.reg.read("SELECT g FROM generations")}
            gen_dir = self.reg.root / "generations"
            if gen_dir.exists():
                for p in gen_dir.iterdir():
                    if p.is_dir() and p.name not in registered:
                        shutil.rmtree(p, ignore_errors=True)
        after_rows = self.reg.read("SELECT size_bytes FROM generations WHERE state!='ABSENT'")
        after = sum(r["size_bytes"] for r in after_rows)
        return {"action": "PLAN_ONLY" if dry_run else "PRUNED", "target_bytes": target,
                "accounted_before_bytes": before, "accounted_after_bytes": after,
                "protected_floor_bytes": floor, "removed_accounted_bytes": removed,
                "candidate_count": len(candidates), "removed_count": count, "skipped_count": skipped,
                "target_met_now": after <= target, "target_would_be_met": floor <= target,
                "cloud_deletions": 0}


def serialized_operation(method):
    @functools.wraps(method)
    def call(self, *args, **kwargs):
        if kwargs.get("dry_run", False): return method(self, *args, **kwargs)
        o = uuid_value(kwargs.get("operation_id") or new_id())
        kwargs["operation_id"] = o
        path = self.reg.root / "operation_locks" / o
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise CASError("OPERATION_BUSY", code=3) from None
            if hasattr(self, "supervisor") and hasattr(self.supervisor, "_op_guards"):
                self.supervisor._op_guards[o] = fd
            try:
                return method(self, *args, **kwargs)
            finally:
                if hasattr(self, "supervisor") and hasattr(self.supervisor, "_op_guards"):
                    self.supervisor._op_guards.pop(o, None)
        finally: os.close(fd)
    return call


class DriveEngine:
    def __init__(self, config_path: str | Path, *, wait_ms: int = 900000, offline: bool = False):
        require(sys.version_info >= (3, 13), "PYTHON_313_REQUIRED", code=7)
        self.config_path = absolute(config_path); self.c = load_config(config_path)
        self.reg = AuthorityRegistry(self.c); self.supervisor = WorkerSupervisor(self.reg.root, self.reg)
        self.broker = DropzoneAdmissionBroker(self.reg)
        self.offline = offline; self.deadline = self.reg.clock.ns() + wait_ms * 1000000

    def _run(self, kind: str, args: dict, o: str | None = None, provider: bool = False) -> dict:
        require(not (provider and self.offline), "OFFLINE_HOLD", code=3)
        remaining = (self.deadline - self.reg.clock.ns()) / 1e9
        require(remaining > 0, "WAIT_BUDGET_EXHAUSTED", code=3)
        if provider and o is not None: self.reg.begin_transport(o)
        success = False
        try:
            result = self.supervisor.run(kind, args, timeout=min(
                300 if kind in ("publish", "export", "receipt") else 120, remaining), operation=o)
            success = True
            return result
        finally:
            if provider and o is not None: self.reg.end_transport(o, success)


    def _capacity(self, needed: int) -> None:
        fs = os.statvfs(self.reg.root)
        free = fs.f_bavail * fs.f_frsize; total = fs.f_blocks * fs.f_frsize
        reserve = max(self.c["reserve_bytes"], total * self.c["reserve_fraction_milli"] // 1000)
        require(needed + reserve <= free, "DISK_RESERVE_REQUIRED", code=8)

    def _capture(self, source: str, row: dict, root: str, o: str | None, *, provider: bool) -> tuple[str, dict]:
        g = new_id(); dest = self.reg.root / "generations" / g
        contract = decode(row["contract"])
        try:
            if provider:
                estimate = self._run("inspect_manifest", {"source": source, "root": root,
                    "intake": row["intake"], "binding": [row["intake_dev"], row["intake_ino"]],
                    "max_bytes": self.c["max_task_bytes"]}, None, provider=True)
                if o is not None: self.reg.reserve(o, estimate["reserve_bytes"])
                else: self._capacity(estimate["reserve_bytes"])
            evidence = self._run("capture", {"source": source, "output": str(dest), "root": root,
                    "contract": contract, "intake": row["intake"],
                    "binding": [row["intake_dev"], row["intake_ino"]] if provider else None}, o, provider)
            # Second process, after acquisition writer exit; check retained logical bytes before registration.
            self._run("check_outputs", {"snapshot": str(dest), "evidence": evidence}, o)
            return g, evidence
        except Exception:
            if dest.exists():
                shutil.rmtree(dest, ignore_errors=True)
            raise

    def _snapshot(self, root: str, owner: str) -> tuple[dict, dict]:
        row = self.reg.pin_root(root, owner)
        ev = decode(row["evidence"], wire=False)
        try:
            self._run("check_outputs", {"snapshot": row["path"], "evidence": ev}, owner)
        except CASError as exc:
            if exc.reason in ("DIGEST_MISMATCH", "LENGTH_MISMATCH"):
                with self.reg.transaction() as con:
                    con.execute("UPDATE generations SET state='CORRUPT' WHERE g=?", (row["g"],))
                    self.reg.audit(con, "GENERATION_CORRUPT", {"g": row["g"], "reason": exc.reason})
            raise
        return row, ev

    @serialized_operation
    def put(self, file: str, *, dropzone: str | None = None, operation_id: str | None = None) -> dict:
        o = uuid_value(operation_id or new_id()); file = absolute(file)
        row = self.reg.task(dropzone); contract = decode(row["contract"])
        require(len(contract["artifacts"]) == 1, "TASK_SHAPE_UNSUPPORTED", code=7)
        intent = {"verb": "put", "source": file, "intake": row["intake"], "k": row["k"],
                  "contract": row["contract_hash"], "goal": GOALS["put"], "layout": "fixed-4m-v1"}
        op = self.reg.bind_operation(o, "put", intent)
        if op["state"] == "DONE": return decode(op["result"], wire=False) | {"replayed": True, "observation": "STORED_STATUS"}
        try:
            self.reg.authorize(row, None)
            pubs = self.reg.read("SELECT * FROM publications WHERE o=?", (o,))
            if pubs:
                pub = pubs[0]
                grow = self.reg.read("SELECT * FROM generations WHERE g=?", (pub["g"],))[0]
                ev = decode(grow["evidence"], wire=False); r = pub["root"]
            else:
                checkpoint = decode(op["checkpoint"], wire=False) if op["checkpoint"] else None
                if checkpoint:
                    build = Path(checkpoint["build"]); r = checkpoint["root"]
                else:
                    require(op["generation"] == 0, "SOURCE_CAPTURE_UNRESOLVED",
                            "No retained checkpoint; reconcile abandoned work before a new capture", 9)
                    self._capacity(16 * 1024 * 1024)
                    src_provider = within(file, self.c["exchange_root"]) or "/Library/CloudStorage/" in file
                    require(not (self.offline and src_provider), "OFFLINE_HOLD", code=3)
                    inspected = self._run("inspect_source", {"path": file}, None, src_provider)
                    size = uint(inspected["size_bytes"], 0, self.c["max_file_bytes"])
                    self.reg.reserve(o, 8 * size + 4 * MAX_JSON)
                    build = self.reg.root / "staging" / new_id()
                    prepared = self._run("build", {"sources": {contract["artifacts"][0]["path"]: file},
                         "contract": contract, "output": str(build), "producer": "local-producer",
                         "installation": self.c["installation_id"], "attempt": o,
                         "layout": "fixed-4m-v1", "capture_limit": size}, o, src_provider)
                    r = prepared["root_hash"]
                    self.reg.save_checkpoint(o, {"build": str(build), "root": r})
                g, ev = self._capture(str(build), row, r, o, provider=False)
                self.reg.register_snapshot(g, str(self.reg.root / "generations" / g), ev, o)
                grow = self.reg.read("SELECT * FROM generations WHERE g=?", (g,))[0]
                with self.reg.transaction() as con:
                    con.execute("INSERT INTO publications VALUES(?,?,?,?,'PENDING')",
                                (o, str(Path(row["intake"]) / "chunks" / r), r, g))
                shutil.rmtree(build)  # closed private preparation; pinned complete snapshot now owns bytes
            pub_result = self._run("publish", {"source": str(Path(grow["path"]) / "tree"),
                "intake": row["intake"], "binding": [row["intake_dev"], row["intake_ino"]],
                "contract": contract, "root": r}, o, True)
            with self.reg.transaction() as con:
                con.execute("UPDATE publications SET state='LOCAL_PUBLISHED' WHERE o=?", (o,))
            f = ev["files"][0]
            result = {"operation_id": o, "root_hash": r, "content_sha256": f["sha256"],
                      "size_bytes": f["size_bytes"], "file_map_sha256": f["file_map_sha256"],
                      "task_key": task_key(contract), "generation_id": grow["g"],
                      "source_scope": contract["artifacts"][0]["source_scope"],
                      "admission": "NOT_ASSERTED", "qualification": "NOT_GRANTED", **pub_result}
            with self.reg.transaction() as con:
                con.execute("UPDATE operations SET state='DONE',result=?,error=NULL WHERE o=?", (local_json(result), o))
                con.execute("DELETE FROM reservations WHERE o=?", (o,))
            return result
        except CASError as exc:
            self.reg.fail(o, exc); raise

    def verify(self, dropzone_dir: str) -> dict:
        """No source, acceptance, pin, operation or registry mutation. Ephemeral private capture only."""
        leaf = absolute(dropzone_dir); r = digest(Path(leaf).name)
        row = self.reg.task_for_leaf(leaf); self.reg.authorize(row, r, new_effect=False)
        require(not self.offline, "OFFLINE_HOLD", code=3)
        g, ev = self._capture(leaf, row, r, None, provider=True)
        path = self.reg.root / "generations" / g
        # No G was registered; this is closed, unshared verification scratch.
        shutil.rmtree(path)
        return {"root_hash": r, "integrity": "MATCH", "contract_result": "MATCH",
                "totals": ev["totals"], "scope": "FULL_CLOSURE", "inventory_scope": ev["inventory_scope"],
                "admission": "NOT_ASSERTED", "qualification": "NOT_GRANTED",
                "remote_evidence": "NOT_ASSERTED"}

    @serialized_operation
    def commit(self, dropzone_dir: str, *, operation_id: str | None = None) -> dict:
        o = uuid_value(operation_id or new_id()); leaf = absolute(dropzone_dir)
        r = digest(Path(leaf).name); row = self.reg.task_for_leaf(leaf)
        require(self.c["role"] == "authority", "AUTHORITY_LOCAL_ONLY", code=6)
        intent = {"verb": "commit", "leaf": leaf, "k": row["k"], "root": r, "goal": GOALS["commit"]}
        op = self.reg.bind_operation(o, "commit", intent)
        if op["state"] == "DONE":
            return decode(op["result"], wire=False) | {"replayed": True, "observation": "HISTORICAL_DECISION"}
        try:
            accepted = self.broker.lookup(row["k"])
            if accepted is not None:
                require(accepted["root"] == r, "TASK_ALREADY_ACCEPTED", code=5)
            else:
                self.reg.authorize(row, r)
                require(not self.reg.read("SELECT 1 FROM generations WHERE root=? AND state='CORRUPT'", (r,)),
                        "DIGEST_MISMATCH", "Known damaged generation requires explicit reconciliation")
                snaps = self.reg.read("SELECT g FROM generations WHERE root=? AND kind='SNAPSHOT' AND state='AVAILABLE'",
                                     (r,))
                if snaps:
                    grow, ev = self._snapshot(r, o); g = grow["g"]
                else:
                    self._capacity(MAX_JSON)
                    g, ev = self._capture(leaf, row, r, o, provider=True)
                    self.reg.register_snapshot(g, str(self.reg.root / "generations" / g), ev, o)
                self.broker.request_admission(o, row, r, g)
                self.broker.advance_admission_queue()
                accepted = self.broker.lookup(row["k"])
                if accepted is None:
                    q = self.reg.read("SELECT state,reason FROM requests WHERE o=?", (o,))[0]
                    require(q["state"] != "BLOCKED", q["reason"] or "APPROVAL_REQUIRED", code=6)
                    raise CASError("ADMISSION_PENDING", "Earlier queue outcome must be reconciled", 3)
                require(accepted["root"] == r, "TASK_ALREADY_ACCEPTED", code=5)
            receipt = decode(accepted["receipt"])
            result = {"operation_id": o, "root_hash": r, "request_sequence": accepted["q"],
                      "decision_sequence": accepted["a"], "acceptance_receipt": receipt,
                      "acceptance_receipt_sha256": accepted["receipt_hash"],
                      "original_operation_id": accepted["o"], "receipt_export": "PENDING",
                      "current_integrity": "NOT_ASSESSED", "qualification": "NOT_GRANTED"}
            self.reg.finish(o, result)
            with self.reg.transaction() as con: con.execute("DELETE FROM reservations WHERE o=?", (o,))
            # Receipt export is separately driven via service_receipt_outbox(), never required for this success.
            return result
        except CASError as exc:
            self.reg.fail(o, exc); raise

    @serialized_operation
    def get(self, root_hash: str, *, output: str | None = None, operation_id: str | None = None) -> dict:
        r = digest(root_hash); o = uuid_value(operation_id or new_id())
        destination = absolute(output) if output is not None else None
        if destination is not None:
            require(any(within(destination, p) for p in self.c["export_roots"]), "READ_SCOPE_DENIED", code=6)
            require(not within(destination, self.c["exchange_root"]) and not within(destination, str(self.reg.root)),
                    "UNSAFE_EXPORT_ROOT", code=7)
        intent = {"verb": "get", "root": r, "destination": destination, "goal": GOALS["get"]}
        op = self.reg.bind_operation(o, "get", intent)
        try:
            if op["state"] == "DONE":
                old = decode(op["result"], wire=False)
                self._run("check_single", {"path": old["output_path"], "sha256": old["content_sha256"],
                                           "size_bytes": old["size_bytes"]}, o)
                return old | {"replayed": True}
            if not self.reg.read("SELECT 1 FROM generations WHERE root=? AND kind='SNAPSHOT' AND state='AVAILABLE'", (r,)):
                require(not self.reg.read("SELECT 1 FROM generations WHERE root=? AND state='CORRUPT'", (r,)),
                        "DIGEST_MISMATCH", "Known damaged private generation")
                bindings = self.reg.read("SELECT t.* FROM tasks t JOIN approved_roots a ON a.k=t.k WHERE a.root=?", (r,))
                require(len(bindings) == 1, "FILE_MAP_UNAVAILABLE", "No unambiguous approved root locator", 7)
                binding = bindings[0]
                g, captured = self._capture(str(Path(binding["intake"]) / "chunks" / r), binding, r, o, provider=True)
                self.reg.register_snapshot(g, str(self.reg.root / "generations" / g), captured, o)
            grow, ev = self._snapshot(r, o)
            require(len(ev["files"]) == 1, "TASK_SHAPE_UNSUPPORTED",
                    "Root-based get requires exactly one logical artifact", 7)
            f = ev["files"][0]; self.reg.reserve(o, 2 * f["size_bytes"] + MAX_JSON)
            ex = self.reg.read("SELECT * FROM exports WHERE o=?", (o,))
            require(not ex or ex[0]["state"] != "BLOCKED", "OUTPUT_EXISTS", code=5)
            reconcile = bool(ex) and ex[0]["state"] == "UNKNOWN"
            if ex:
                destination = ex[0]["destination"]
            elif destination is None:
                exportdir = self.reg.root / "exports" / o
                exportdir.mkdir(mode=0o700, exist_ok=True)
                destination = str(exportdir / (f["sha256"] + ".bin"))
            if not ex:
                with self.reg.transaction() as con:
                    con.execute("INSERT INTO exports VALUES(?,?,?,?,?,'PENDING')", (o, r, grow["g"], None, destination))
            with self.reg.transaction() as con:
                con.execute("UPDATE exports SET state='UNKNOWN' WHERE o=?", (o,))
            self._run("export", {"source": str(Path(grow["path"]) / "files" / f["path"]),
                        "destination": destination, "sha256": f["sha256"], "size_bytes": f["size_bytes"],
                        "reconcile": reconcile}, o)
            output_g = None
            result = {"operation_id": o, "root_hash": r, "content_sha256": f["sha256"],
                      "file_map_sha256": f["file_map_sha256"], "size_bytes": f["size_bytes"],
                      "output_path": destination, "generation_id": grow["g"], "export_id": o,
                      "retention": "EXPLICIT_RELEASE_REQUIRED", "admission": "NOT_ASSERTED",
                      "qualification": "NOT_GRANTED"}
            with self.reg.transaction() as con:
                if output is None:
                    output_g = new_id()
                    ordinal = self.reg.audit(con, "EXPORT_CREATED", {"o": o})
                    con.execute("INSERT INTO generations VALUES(?,?,?,?,?,?,?,?,?)",
                                (output_g, r, str(Path(destination).parent), "EXPORT", f["size_bytes"],
                                 None, "AVAILABLE", ordinal, utc()))
                    con.execute("INSERT INTO pins VALUES(?,?,?,?)", (output_g, o, "EXPORT", utc()))
                con.execute("UPDATE exports SET state='DONE',output_g=? WHERE o=?", (output_g, o))
                con.execute("UPDATE operations SET state='DONE',result=?,error=NULL WHERE o=?", (local_json(result), o))
                con.execute("DELETE FROM reservations WHERE o=?", (o,))
            return result
        except CASError as exc:
            with self.reg.transaction() as con:
                con.execute("DELETE FROM pins WHERE owner=? AND kind='READER'", (o,))
                if exc.reason == "OUTPUT_EXISTS":
                    con.execute("UPDATE exports SET state='BLOCKED' WHERE o=?", (o,))
            self.reg.fail(o, exc); raise

    @serialized_operation
    def prune(self, *, max_size_gb: str = "100", dry_run: bool = False,
              operation_id: str | None = None) -> dict:
        target = parse_gb(max_size_gb)
        if dry_run:
            return LocalCacheEvictor(self.reg, self.supervisor).prune(target, dry_run=True)
        o = uuid_value(operation_id or new_id())
        intent = {"verb": "prune", "target_bytes": target, "goal": GOALS["prune"]}
        op = self.reg.bind_operation(o, "prune", intent)
        if op["state"] == "DONE": return decode(op["result"], wire=False) | {"replayed": True, "observation": "STORED_STATUS"}
        result = LocalCacheEvictor(self.reg, self.supervisor).prune(target, operation=o)
        result["operation_id"] = o
        if not result["target_met_now"]:
            exc = CASError("HOLD_RESOURCE", "Protected bytes exceed the requested target", 8, result=result)
            self.reg.fail(o, exc); raise exc
        self.reg.finish(o, result); return result

    def operation_status(self, operation_id: str, verb: str, operands: dict) -> dict:
        rows = self.reg.read("SELECT * FROM operations WHERE o=?", (uuid_value(operation_id),))
        require(bool(rows), "STATUS_ID_REQUIRED", code=2)
        row = rows[0]; intent = decode(row["intent"], wire=False)
        require(row["verb"] == verb, "INTENT_CONFLICT", code=5)
        if verb == "put":
            expected = {"source": absolute(operands["file"]),
                        "intake": self.reg.task(operands.get("dropzone"))["intake"]}
        elif verb == "get":
            expected = {"root": digest(operands["root_hash"]),
                        "destination": absolute(operands["output"]) if operands.get("output") else None}
        elif verb == "commit": expected = {"leaf": absolute(operands["dropzone_dir"])}
        else: expected = {"target_bytes": parse_gb(operands["max_size_gb"])}
        require(all(intent.get(k) == v for k, v in expected.items()), "INTENT_CONFLICT", code=5)
        if row["state"] != "DONE":
            error = decode(row["error"], wire=False) if row["error"] else {"reason": "PENDING_CONTENT", "code": 3, "message": "Unresolved operation"}
            raise CASError(error["reason"], error["message"], error["code"],
                           result={"operation_id": operation_id, "observation": "STORED_STATUS", "state": row["state"]})
        return decode(row["result"], wire=False) | {"replayed": True, "observation": "STORED_STATUS"}

    def service_receipt_outbox(self, limit: int = 8) -> list[dict]:
        """One explicit controller iteration. No daemon and no implicit background work."""
        rows = self.reg.read("SELECT * FROM receipt_outbox WHERE state!='LOCAL_PUBLISHED' ORDER BY receipt_hash LIMIT ?",
                             (uint(limit, 1, 32),))
        result = []
        for pending in rows:
            task = self.reg.task(pending["intake"])
            require(pending["attempts"] < 8, "HOLD_RETRY", code=3)
            with self.reg.transaction() as con:
                con.execute("UPDATE receipt_outbox SET attempts=attempts+1,state='UNKNOWN' WHERE receipt_hash=?",
                            (pending["receipt_hash"],))
            outcome = self._run("receipt", {"intake": task["intake"],
                 "binding": [task["intake_dev"], task["intake_ino"]],
                 "receipt": pending["bytes"].decode("ascii"), "sha256": pending["receipt_hash"]}, provider=True)
            with self.reg.transaction() as con:
                con.execute("UPDATE receipt_outbox SET state='LOCAL_PUBLISHED' WHERE receipt_hash=?", (pending["receipt_hash"],))
            result.append(outcome | {"sha256": pending["receipt_hash"]})
        return result


def parse_gb(value: str) -> int:
    require(type(value) is str and re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,3})?", value) is not None,
            "INVALID_SIZE", code=2)
    whole, _, frac = value.partition(".")
    require(len(whole) <= 7, "INVALID_SIZE", code=2)
    return int(whole) * 1000000000 + int(frac.ljust(3, "0") or "0") * 1000000


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CASError("INVALID_ARGUMENT", message, 2)


def parser() -> argparse.ArgumentParser:
    p = _Parser(prog="drive_cas.py", allow_abbrev=False,
                description="Immutable CAS candidates; only commit changes local task acceptance.")
    p.add_argument("--version", action="version", version=VERSION)
    p.add_argument("--config", default=str(Path.home() / "Library/Application Support/SovereignDrive/drive-engine/config.json"))
    p.add_argument("--operation-id")
    p.add_argument("--wait-ms", type=int, default=900000)
    p.add_argument("--offline", action="store_true")
    p.add_argument("--status-only", action="store_true")
    sub = p.add_subparsers(dest="verb", required=True, parser_class=_Parser)
    put = sub.add_parser("put", allow_abbrev=False); put.add_argument("file"); put.add_argument("--dropzone")
    get = sub.add_parser("get", allow_abbrev=False); get.add_argument("root_hash"); get.add_argument("--output")
    for verb in ("verify", "commit"):
        s = sub.add_parser(verb, allow_abbrev=False); s.add_argument("dropzone_dir")
    prune = sub.add_parser("prune", allow_abbrev=False)
    prune.add_argument("--max-size-gb", default="100"); prune.add_argument("--dry-run", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) == 2 and argv[0] == "--_worker":
        return _worker_main(argv[1])
    verb = None; o = None; engine = None; result = None
    try:
        seen = set()
        for a in argv:
            if a == "--": break
            if a.startswith("--"):
                flag = a.split("=", 1)[0]
                require(flag not in seen, "DUPLICATE_OPTION", code=2); seen.add(flag)
        args = parser().parse_args(argv); verb = args.verb
        require(1 <= args.wait_ms <= 900000, "INVALID_ARGUMENT", code=2)
        if args.operation_id:
            try: uuid_value(args.operation_id)
            except CASError: raise CASError("INVALID_UUID", code=2) from None
        if verb == "get":
            try: digest(args.root_hash)
            except CASError: raise CASError("INVALID_HASH", code=2) from None
        require(not args.status_only or (args.operation_id and verb != "verify" and not getattr(args, "dry_run", False)),
                "STATUS_ID_REQUIRED", code=2)
        if verb == "prune": parse_gb(args.max_size_gb)
        require(not (verb == "verify" and args.operation_id), "INVALID_ARGUMENT",
                "verify is an unrecorded fresh observation; no replay ID", 2)
        o = args.operation_id or (None if verb == "verify" or getattr(args, "dry_run", False) else new_id())
        engine = DriveEngine(args.config, wait_ms=args.wait_ms, offline=args.offline)
        if args.status_only: result = engine.operation_status(o, verb, vars(args))
        elif verb == "put": result = engine.put(args.file, dropzone=args.dropzone, operation_id=o)
        elif verb == "get": result = engine.get(args.root_hash, output=args.output, operation_id=o)
        elif verb == "verify": result = engine.verify(args.dropzone_dir)
        elif verb == "commit": result = engine.commit(args.dropzone_dir, operation_id=o)
        else: result = engine.prune(max_size_gb=args.max_size_gb, dry_run=args.dry_run, operation_id=o)
        code, reason, state = 0, {"put": "LOCAL_PUBLISHED", "get": "FILE_MATERIALIZED", "commit": "ACCEPTED_LOCAL",
                                 "verify": "FULL_CLOSURE_VERIFIED", "prune": "CACHE_TARGET_MET"}[verb], "DONE"
        if result.get("action") == "PLAN_ONLY": reason = "PLAN_PRODUCED"
        message = ""
    except CASError as exc:
        code, reason, message = exc.code, exc.reason, str(exc)
        result = exc.detail.get("result")
        state = "UNKNOWN" if code == 9 else "HOLD_RESOURCE" if code == 8 else "PENDING" if code == 3 else "REJECTED"
    except (sqlite3.Error, OSError) as exc:
        code, reason, state, message = 10, "AUTHORITY_OR_LOCAL_IO_ERROR", "HOLD_AUTHORITY", str(exc)[:512]
    except Exception as exc:
        code, reason, state, message = 11, "INTERNAL_CONTRACT_BREACH", "REJECTED", type(exc).__name__ + ": " + str(exc)[:512]
    except KeyboardInterrupt:
        code, reason, state, message = 130, "CALLER_INTERRUPTED", "UNKNOWN", "Replay the same operation identity."
    envelope = {"protocol": CLI_PROTOCOL, "version": VERSION, "command": verb, "operation_id": o,
                "invocation_id": None if engine is None else engine.supervisor.last_invocation,
                "state": state, "goal": "PRUNE_PLAN_PRODUCED" if reason == "PLAN_PRODUCED" else GOALS.get(verb),
                "goal_met": code == 0, "exit_code": code, "reason": reason,
                "observation": (result or {}).get("observation", "CURRENT_OPERATION"),
                "replayed": bool((result or {}).get("replayed")), "result": result,
                "diagnostic": {"message": message[:1024]}, "qualification": "NOT_GRANTED"}
    data = local_json(envelope)
    if len(data) > MAX_CONTROL:
        data = local_json({"protocol": CLI_PROTOCOL, "reason": "RESULT_SIZE_LIMIT", "exit_code": 11,
                           "operation_id": o, "goal_met": False})
        code = 11
    sys.stdout.buffer.write(data); sys.stdout.buffer.flush()
    return code




if __name__ == "__main__":
    raise SystemExit(main())
