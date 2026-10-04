#!/usr/bin/env python3
"""Raw-byte PE module workbench. Standard library only; no compiler or assembler."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import uuid
import zlib

MAGIC = b"LLMPE64\0"
HEADER_SIZE, RECORD_SIZE, DIRECTORY_CAPACITY = 512, 192, 128
UNWIND_CAPACITY, UNWIND_POOL, UNWIND_SLOT = 48, 576, 8
MAX_READ = 16 * 1024 * 1024
_raw_spec = importlib.util.spec_from_file_location("llmpe_raw_bytes", Path(__file__).with_name("raw_bytes.py"))
_raw = importlib.util.module_from_spec(_raw_spec)
_raw_spec.loader.exec_module(_raw)

def fail(message):
    raise ValueError(message)

def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")

def digest(value):
    return hashlib.sha256(value).digest()

def stream_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()

def align(value, multiple):
    return (value + multiple - 1) // multiple * multiple

def valid_name(name):
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,62}", name):
        fail("Invalid module name: " + repr(name))
    return name

def abi_hash(doc):
    value = doc.get("abi", {k: v for k, v in doc.items() if k not in ("purpose", "notes")})
    return digest(canonical(value))[:16]

def profile(doc):
    p = doc["implementation"]["unwind_profile"]
    if p == "leaf":
        return bytes.fromhex("01000000")
    if p == "stack56":
        return bytes.fromhex("0104010004620000")
    fail("Unsupported unwind profile; perform an explicit layout migration: " + str(p))

def check_profile(doc, code):
    p = doc["implementation"]["unwind_profile"]
    if p == "stack56":
        if not code.startswith(bytes.fromhex("4883ec38")) or not code.endswith(bytes.fromhex("4883c438c3")):
            fail("stack56 prologue/epilogue does not match: " + doc["name"])
    elif p == "leaf":
        if not code.endswith(b"\xc3"):
            fail("Leaf implementation must end with RET: " + doc["name"])
        if any(r["kind"] in ("call", "import") for r in doc.get("references", [])):
            fail("Leaf profile cannot contain declared calls: " + doc["name"])
    else:
        fail("Unsupported unwind profile")

def record_bytes(rec):
    b = bytearray(RECORD_SIZE)
    name = valid_name(rec["name"]).encode("ascii")
    b[:len(name)] = name
    struct.pack_into("<IHH", b, 64, zlib.crc32(name), rec["kind"], rec["version"])
    struct.pack_into("<7I", b, 72, rec["entry"], rec["impl"], rec["used"], rec["slot"],
                     rec["doc_rva"], rec["doc_size"], rec["doc_capacity"])
    b[100:132] = rec["code_hash"]
    b[132:164] = rec["doc_hash"]
    b[164:180] = rec["abi_hash"]
    struct.pack_into("<III", b, 180, rec.get("flags", 0), rec.get("generation", 1), 0)
    return bytes(b)

def read_record(b, offset):
    name = b[:64].split(b"\0", 1)[0].decode("ascii")
    valid_name(name)
    ident, kind, version = struct.unpack_from("<IHH", b, 64)
    if ident != zlib.crc32(name.encode("ascii")) or kind not in (1, 2, 3, 4):
        fail("Directory record identifier/kind mismatch: " + name)
    fields = struct.unpack_from("<7I", b, 72)
    return dict(zip(("entry", "impl", "used", "slot", "doc_rva", "doc_size", "doc_capacity"), fields),
                name=name, kind=kind, version=version, code_hash=b[100:132],
                doc_hash=b[132:164], abi_hash=b[164:180],
                flags=struct.unpack_from("<I", b, 180)[0],
                generation=struct.unpack_from("<I", b, 184)[0], record_offset=offset)

class PE:
    def __init__(self, path, metadata=True):
        self.path = Path(path)
        self.f = self.path.open("rb")
        self.size = self.path.stat().st_size
        self.bytes_read = 0
        dos = self.read(0, 64)
        if dos[:2] != b"MZ":
            fail("Not an MZ executable")
        self.nt = struct.unpack_from("<I", dos, 60)[0]
        nt = self.read(self.nt, 24)
        if nt[:4] != b"PE\0\0":
            fail("Not a PE executable")
        machine, count = struct.unpack_from("<HH", nt, 4)
        opt_size = struct.unpack_from("<H", nt, 20)[0]
        self.coff_flags = struct.unpack_from("<H", nt, 22)[0]
        if machine != 0x8664 or count > 96 or count == 0 or opt_size != 240:
            fail("Expected AMD64 PE32+ with a 240-byte optional header")
        self.opt_offset = self.nt + 24
        self.opt = self.read(self.opt_offset, opt_size)
        if struct.unpack_from("<H", self.opt)[0] != 0x20B:
            fail("Expected PE32+")
        self.base = struct.unpack_from("<Q", self.opt, 24)[0]
        self.entry = struct.unpack_from("<I", self.opt, 16)[0]
        self.section_align, self.file_align = struct.unpack_from("<II", self.opt, 32)
        self.image_size, self.headers_size = struct.unpack_from("<II", self.opt, 56)
        self.table_offset = self.opt_offset + opt_size
        table = self.read(self.table_offset, count * 40)
        self.sections = []
        for i in range(count):
            off = i * 40
            name = table[off:off+8].split(b"\0", 1)[0].decode("ascii")
            virtual, rva, raw_size, raw = struct.unpack_from("<IIII", table, off+8)
            flags = struct.unpack_from("<I", table, off+36)[0]
            self.sections.append(dict(name=name, virtual_size=virtual, rva=rva,
                                      raw_size=raw_size, raw_offset=raw, flags=flags))
        self.directories = [struct.unpack_from("<II", self.opt, 112+i*8) for i in range(16)]
        self.records = []
        if metadata:
            self.meta = self.section(".llm")
            self.meta_header = self.read(self.meta["raw_offset"], HEADER_SIZE)
            if self.meta_header[:8] != MAGIC:
                fail("Missing LLMPE64 metadata signature")
            major, minor = struct.unpack_from("<HH", self.meta_header, 8)
            header, width, cap, used, directory, arena, arena_end, arena_cap = struct.unpack_from("<8I", self.meta_header, 12)
            if (major, header, width, cap, directory) != (1, HEADER_SIZE, RECORD_SIZE, DIRECTORY_CAPACITY, HEADER_SIZE):
                fail("Unsupported metadata schema")
            if used > cap or arena < directory + cap*width or arena_end > arena_cap or arena_cap > self.meta["raw_size"]:
                fail("Metadata directory/arena bounds are invalid")
            self.arena, self.arena_end = arena, arena_end
            directory_bytes = self.read(self.meta["raw_offset"]+directory, used*width)
            self.records = [read_record(directory_bytes[i*width:(i+1)*width],
                                        self.meta["raw_offset"]+directory+i*width) for i in range(used)]
            if len({r["name"] for r in self.records}) != used or len({zlib.crc32(r["name"].encode()) for r in self.records}) != used:
                fail("Duplicate module names or IDs")

    def close(self):
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def read(self, offset, size):
        if offset < 0 or size < 0 or size > MAX_READ or offset+size > self.size:
            fail("File range is outside executable")
        self.f.seek(offset)
        data = self.f.read(size)
        self.bytes_read += len(data)
        if len(data) != size:
            fail("Short executable read")
        return data

    def section(self, name):
        found = [s for s in self.sections if s["name"] == name]
        if len(found) != 1:
            fail("Expected one section named " + name)
        return found[0]

    def offset(self, rva, size=1):
        for s in self.sections:
            if s["rva"] <= rva and rva+size <= s["rva"]+s["raw_size"]:
                return s["raw_offset"]+rva-s["rva"]
        if 0 <= rva and rva+size <= self.headers_size:
            return rva
        fail("RVA is not backed by file bytes: " + hex(rva))

    def record(self, name):
        found = [r for r in self.records if r["name"] == name]
        if len(found) != 1:
            fail("Unknown module: " + name)
        return found[0]

    def document(self, rec):
        start = rec["doc_rva"] - self.meta["rva"]
        if start < self.arena or rec["doc_size"]+1 > rec["doc_capacity"] or start+rec["doc_capacity"] > self.meta["raw_size"]:
            fail("Module document is outside its arena: " + rec["name"])
        payload = self.read(self.offset(rec["doc_rva"], rec["doc_size"]+1), rec["doc_size"]+1)
        if payload[-1] != 0 or digest(payload[:-1]) != rec["doc_hash"]:
            fail("Document hash/terminator mismatch: " + rec["name"])
        doc = json.loads(payload[:-1].decode("utf-8"))
        if doc.get("schema") != "llm-pe.module.v1" or doc.get("name") != rec["name"] or doc.get("contract_version") != rec["version"]:
            fail("Module document identity/version mismatch")
        if abi_hash(doc) != rec["abi_hash"]:
            fail("ABI digest mismatch: " + rec["name"])
        return doc

    def code(self, rec):
        if rec["kind"] != 1:
            return b""
        if not 0 < rec["used"] <= rec["slot"]:
            fail("Invalid code slot bounds: " + rec["name"])
        code = self.read(self.offset(rec["impl"], rec["used"]), rec["used"])
        if digest(code) != rec["code_hash"]:
            fail("Code hash mismatch: " + rec["name"])
        return code

def put(f, offset, data):
    f.seek(offset)
    f.write(data)

def patch_references(doc, code, symbols, base):
    _raw.validate_fixups(code, doc.get("references", []), doc.get("local_symbols", {}))
    b = bytearray(code)
    for r in doc.get("references", []):
        at, next_off = r["offset"], r["next_offset"]
        if not (0 <= at <= len(b)-4 and at+4 <= next_off <= len(b)):
            fail("Reference field is outside implementation")
        if r.get("local") is not None:
            target = base + r["local"]
            if not 0 <= r["local"] < len(b):
                fail("Local target outside implementation")
        else:
            if r["target"] not in symbols:
                fail("Unknown stable symbol: " + r["target"])
            target = symbols[r["target"]]
        delta = target - (base + next_off)
        if not -(1 << 31) <= delta < (1 << 31):
            fail("Reference exceeds signed rel32 range")
        struct.pack_into("<i", b, at, delta)
        r["rva"] = target
    return bytes(b)

def runtime_entries(pe):
    rva, length = pe.directories[3]
    if length % 12 or length // 12 > UNWIND_CAPACITY:
        fail("Exception directory exceeds reserved table capacity")
    raw = pe.read(pe.offset(rva, length), length)
    return [list(struct.unpack_from("<III", raw, p)) for p in range(0, length, 12)]

def write_runtime(pe, f, entries, profiles):
    if len(entries) > UNWIND_CAPACITY:
        fail("Runtime-function table exhausted; explicit migration required")
    if any(entries[i][0] >= entries[i+1][0] for i in range(len(entries)-1)):
        fail("Runtime-function ranges must be sorted")
    pdata = pe.section(".pdata")
    pool = bytearray(pdata["raw_size"])
    for i, row in enumerate(entries):
        unwind = profiles.get(row[0])
        if unwind is None:
            unwind = pe.read(pe.offset(row[2], UNWIND_SLOT), UNWIND_SLOT)
        if len(unwind) > UNWIND_SLOT:
            fail("Unwind record exceeds reserved eight-byte slot")
        row[2] = pdata["rva"]+UNWIND_POOL+i*UNWIND_SLOT
        struct.pack_into("<III", pool, i*12, *row)
        pool[UNWIND_POOL+i*UNWIND_SLOT:UNWIND_POOL+i*UNWIND_SLOT+len(unwind)] = unwind
    put(f, pdata["raw_offset"], pool)
    put(f, pe.opt_offset+112+3*8, struct.pack("<II", pdata["rva"], len(entries)*12))
    return {row[0]:dict(entry_index=i, begin_rva=row[0], end_rva=row[1], unwind_rva=row[2])
            for i, row in enumerate(entries)}

def migrate(spec_path, output):
    spec_path = Path(spec_path)
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    root = spec_path.parent.parent
    base = root / spec["base_file"]
    output = Path(output or root/spec["output_file"])
    if output.exists():
        fail("Output exists; choose a new candidate path")
    metadata, arena = spec["metadata"], spec["code_arena"]
    tmp = output.with_name(output.name+".building")
    if tmp.exists():
        fail("Unfinished output exists: " + str(tmp))
    shutil.copyfile(base, tmp)
    try:
        with PE(base, metadata=False) as pe, tmp.open("r+b") as f:
            raw_mods = align(pe.size, pe.file_align)
            raw_meta = raw_mods+arena["raw_size"]
            size = raw_meta+metadata["raw_size"]
            f.truncate(size)
            put(f, raw_mods, b"\xcc"*arena["raw_size"])
            extra = [
                dict(name=".mods", rva=arena["rva"], virtual_size=arena["virtual_size"], raw_offset=raw_mods, raw_size=arena["raw_size"], flags=0x60000020),
                dict(name=".llm", rva=metadata["rva"], virtual_size=metadata["virtual_size"], raw_offset=raw_meta, raw_size=metadata["raw_size"], flags=0x40000040)]
            if pe.table_offset+(len(pe.sections)+2)*40 > pe.headers_size:
                fail("No PE header space for new sections")
            for i, s in enumerate(extra, len(pe.sections)):
                sh = bytearray(40)
                sh[:len(s["name"])] = s["name"].encode()
                struct.pack_into("<IIII", sh, 8, s["virtual_size"], s["rva"], s["raw_size"], s["raw_offset"])
                struct.pack_into("<I", sh, 36, s["flags"])
                put(f, pe.table_offset+i*40, sh)
            put(f, pe.nt+6, struct.pack("<H", len(pe.sections)+2))
            put(f, pe.opt_offset+4, struct.pack("<I", struct.unpack_from("<I", pe.opt, 4)[0]+arena["raw_size"]))
            put(f, pe.opt_offset+8, struct.pack("<I", struct.unpack_from("<I", pe.opt, 8)[0]+metadata["raw_size"]))
            put(f, pe.opt_offset+46, struct.pack("<H", 1))
            put(f, pe.opt_offset+56, struct.pack("<I", metadata["rva"]+metadata["virtual_size"]))
            f.flush()
        with PE(tmp, metadata=False) as pe, tmp.open("r+b") as f:
            modules = copy.deepcopy(spec["modules"])
            symbols = next(m["document"]["symbols"] for m in modules if m["name"] == "Symbols")
            rows, profiles = [], {}
            for m in modules:
                if m["kind"] != 1:
                    continue
                d = m["document"]
                impl = d["implementation"]
                code = patch_references(d, bytes.fromhex(m["code_hex"]), symbols, impl["implementation_rva"])
                check_profile(d, code)
                if len(code) > impl["slot_bytes"]:
                    fail("Code slot exhausted: " + m["name"])
                put(f, pe.offset(impl["implementation_rva"], impl["slot_bytes"]), code+b"\xcc"*(impl["slot_bytes"]-len(code)))
                m["_code"] = code
                rows.append([impl["entry_rva"], impl["entry_rva"]+len(code), 0])
                profiles[impl["entry_rva"]] = profile(d)
            rows.sort()
            unwind_info = write_runtime(pe, f, rows, profiles)
            for m in modules:
                if m["kind"] == 1:
                    m["document"]["implementation"]["unwind"] = unwind_info[m["document"]["implementation"]["entry_rva"]]
            hdr = bytearray(HEADER_SIZE)
            hdr[:8] = MAGIC
            struct.pack_into("<HH8I", hdr, 8, 1, 0, HEADER_SIZE, RECORD_SIZE, DIRECTORY_CAPACITY,
                             len(modules), HEADER_SIZE, metadata["arena_offset"], 0, metadata["raw_size"])
            origin = bytes.fromhex(stream_hash(base))
            hdr[48:64] = uuid.uuid5(uuid.NAMESPACE_URL, "llm-pe:"+origin.hex()).bytes
            struct.pack_into("<II", hdr, 64, 1, 1)
            hdr[72:104] = origin
            message = b"Unknown embedded module. Use --describe for the index.\r\n\0"
            hdr[128:128+len(message)] = message
            cursor = metadata["arena_offset"]
            for i, m in enumerate(modules):
                doc = canonical(m["document"])
                cap = m["capacity"]
                if len(doc)+1 > cap or cursor+cap > metadata["raw_size"]:
                    fail("Documentation slot/arena exhausted: " + m["name"])
                impl = m["document"].get("implementation", {})
                rec = dict(name=m["name"], kind=m["kind"], version=m["document"]["contract_version"],
                           entry=impl.get("entry_rva", 0), impl=impl.get("implementation_rva", 0),
                           used=len(m.get("_code", b"")), slot=impl.get("slot_bytes", 0),
                           doc_rva=metadata["rva"]+cursor, doc_size=len(doc), doc_capacity=cap,
                           code_hash=digest(m["_code"]) if m["kind"] == 1 else b"\0"*32,
                           doc_hash=digest(doc), abi_hash=abi_hash(m["document"]), generation=1)
                put(f, raw_meta+HEADER_SIZE+i*RECORD_SIZE, record_bytes(rec))
                put(f, raw_meta+cursor, doc+b"\0")
                cursor += cap
            struct.pack_into("<I", hdr, 36, cursor)
            put(f, raw_meta, hdr)
        verify(tmp, quiet=True)
        os.replace(tmp, output)
    except Exception:
        if tmp.exists():
            tmp.unlink()
        raise
    print(json.dumps(dict(output=str(output), bytes=output.stat().st_size, sha256=stream_hash(output)), indent=2))

def verify(path, quiet=False):
    with PE(path) as pe:
        if pe.meta["flags"] & 0xA0000000 or not pe.meta["flags"] & 0x40000000:
            fail("Metadata must be readable and non-executable, without write permission")
        previous = align(pe.headers_size, pe.section_align)
        raw_ranges = []
        for s in pe.sections:
            if s["rva"] != previous or s["rva"] % pe.section_align or s["raw_offset"] % pe.file_align or s["raw_size"] % pe.file_align:
                fail("Invalid section alignment/adjacency: " + s["name"])
            if s["raw_size"] > s["virtual_size"] or s["raw_offset"]+s["raw_size"] > pe.size:
                fail("Invalid section capacity: " + s["name"])
            previous = s["rva"]+align(s["virtual_size"], pe.section_align)
            raw_ranges.append((s["raw_offset"], s["raw_offset"]+s["raw_size"]))
        if previous != pe.image_size or any(a[1] > b[0] for a,b in zip(sorted(raw_ranges), sorted(raw_ranges)[1:])):
            fail("Image size or raw section overlap mismatch")
        if not any(s["flags"] & 0x20000000 and s["rva"] <= pe.entry < s["rva"]+s["virtual_size"] for s in pe.sections):
            fail("Entry point is outside executable sections")
        if pe.directories[14] != (0, 0):
            fail("Unexpected CLR runtime")
        symbols = pe.document(pe.record("Symbols"))["symbols"]
        ranges, code_ranges, references = [], [], 0
        rows = runtime_entries(pe)
        if any(rows[i][0] >= rows[i+1][0] or rows[i][1] > rows[i+1][0] for i in range(len(rows)-1)):
            fail("Runtime-function table not sorted or overlaps")
        row_map = {r[0]:r for r in rows}
        for rec in pe.records:
            doc = pe.document(rec)
            ranges.append((rec["doc_rva"], rec["doc_rva"]+rec["doc_capacity"]))
            if rec["kind"] != 1:
                continue
            code = pe.code(rec)
            impl = doc["implementation"]
            if (rec["entry"], rec["impl"], rec["used"], rec["slot"]) != (impl["entry_rva"], impl["implementation_rva"], impl["used_bytes"], impl["slot_bytes"]):
                fail("Directory/implementation mismatch: " + rec["name"])
            check_profile(doc, code)
            resolved_doc = copy.deepcopy(doc)
            expected = patch_references(resolved_doc, code, symbols, rec["impl"])
            if doc.get("references", []) != resolved_doc.get("references", []):
                fail("Declared reference RVAs disagree with stable/local symbols: " + rec["name"])
            if code != expected:
                fail("Relative-address mismatch: " + rec["name"])
            references += len(doc.get("references", []))
            padding = pe.read(pe.offset(rec["impl"]+rec["used"], rec["slot"]-rec["used"]), rec["slot"]-rec["used"])
            if padding != b"\xcc"*len(padding):
                fail("Code reserve padding mismatch: " + rec["name"])
            code_ranges.append((rec["impl"], rec["impl"]+rec["slot"]))
            row = row_map.get(rec["impl"])
            if not row or row[1] != rec["impl"]+rec["used"] or pe.read(pe.offset(row[2], len(profile(doc))), len(profile(doc))) != profile(doc):
                fail("Unwind range/profile mismatch: " + rec["name"])
            if rec["entry"] != rec["impl"]:
                gate = impl.get("gate")
                if not gate:
                    fail("Relocated implementation lacks gate")
                gate_bytes = b"\xe9"+struct.pack("<i", rec["impl"]-(rec["entry"]+5))
                actual = pe.read(pe.offset(rec["entry"], gate["slot_bytes"]), gate["slot_bytes"])
                if actual != gate_bytes+b"\xcc"*(gate["slot_bytes"]-5):
                    fail("Stable jump gate mismatch")
                gate_row = row_map.get(rec["entry"])
                if not gate_row or gate_row[1] != rec["entry"]+5 or pe.read(pe.offset(gate_row[2], 4), 4) != b"\x01\0\0\0":
                    fail("Jump gate unwind mismatch")
                code_ranges.append((rec["entry"], rec["entry"]+gate["slot_bytes"]))
        for rs, name in [(ranges,"document"), (code_ranges,"code")]:
            if any(a[1] > b[0] for a,b in zip(sorted(rs),sorted(rs)[1:])):
                fail("Overlapping " + name + " slots")
        validate_imports(pe)
        result = dict(valid=True, modules=len(pe.records), functions=sum(r["kind"] == 1 for r in pe.records),
                      references=references, bytes_read=pe.bytes_read, executable_bytes=pe.size, sha256=stream_hash(path))
    if not quiet:
        print(json.dumps(result, indent=2))
    return result

def validate_imports(pe):
    declared = pe.document(pe.record("Architecture")).get("design", {}).get("system_imports")
    import_inventory(pe, declared)

def read_cstring(pe, rva, limit):
    data = bytearray()
    for i in range(limit):
        c = pe.read(pe.offset(rva+i),1)
        if c == b"\0":
            return data.decode("ascii")
        data += c
    fail("Unterminated ASCII string")

def inspect(path,name,with_bytes=False):
    with PE(path) as pe:
        if name is None:
            result = dict(schema="llm-pe.directory.v1",modules=[
                dict(name=r["name"],kind=r["kind"],contract_version=r["version"],entry_rva=r["entry"],
                     used_bytes=r["used"],slot_bytes=r["slot"],document_bytes=r["doc_size"],
                     document_capacity_bytes=r["doc_capacity"],generation=r["generation"]) for r in pe.records])
        else:
            r = pe.record(name)
            d = pe.document(r)
            code = pe.code(r)
            result = dict(module=d, revision=dict(code_sha256=r["code_hash"].hex(),document_sha256=r["doc_hash"].hex(),
                                                  abi_digest=r["abi_hash"].hex(),generation=r["generation"]))
            result["storage"] = dict(document_bytes=r["doc_size"],document_capacity_bytes=r["doc_capacity"],
                                     document_free_bytes=r["doc_capacity"]-r["doc_size"]-1,
                                     code_free_bytes=r["slot"]-r["used"])
            if with_bytes and r["kind"] == 1:
                result["code_hex"] = code.hex()
        result["read_stats"] = dict(bytes_read=pe.bytes_read,executable_bytes=pe.size)
    print(json.dumps(result,indent=2))
    return result

def template(path,name,output):
    with PE(path) as pe:
        r = pe.record(name)
        if r["kind"] != 1:
            fail("Patch templates target function modules")
        doc = pe.document(r)
        code = pe.code(r)
        obj = dict(schema="llm-pe.patch.v1",module=name,expected_code_sha256=r["code_hash"].hex(),
                   expected_document_sha256=r["doc_hash"].hex(),contract_version=r["version"],
                   reason="Describe the intended function change.",hex=code.hex(),documentation=doc,
                   limits=dict(code_slot_bytes=r["slot"],document_capacity_bytes=r["doc_capacity"],
                               document_bytes=r["doc_size"],document_free_bytes=r["doc_capacity"]-r["doc_size"]-1))
    out = Path(output)
    if out.exists():
        fail("Patch template output exists")
    out.write_text(canonical(obj).decode(),encoding="utf-8")
    print(json.dumps(dict(output=str(out),module=name,bytes=len(code))))

def patch(path,patch_path,output,allow_relocate=False):
    path, output = Path(path), Path(output)
    if path.resolve() == output.resolve() or output.exists():
        fail("Use a new candidate output; source is never patched in place")
    patch_doc = json.loads(Path(patch_path).read_text(encoding="utf-8"))
    if patch_doc.get("schema") != "llm-pe.patch.v1":
        fail("Unsupported patch schema")
    with PE(path) as pe:
        rec = pe.record(patch_doc["module"])
        original_doc, original_code = pe.document(rec), pe.code(rec)
        if rec["kind"] != 1:
            fail("Only function bodies can use a routine patch")
        if patch_doc["expected_code_sha256"] != rec["code_hash"].hex() or patch_doc["expected_document_sha256"] != rec["doc_hash"].hex():
            fail("Stale patch: expected revision hashes differ")
        doc = copy.deepcopy(patch_doc.get("documentation",original_doc))
        if doc["name"] != rec["name"] or patch_doc["contract_version"] != rec["version"] or doc["contract_version"] != rec["version"] or abi_hash(doc) != rec["abi_hash"]:
            fail("Public ABI/contract change requires an explicit migration")
        code = bytes.fromhex(patch_doc["hex"])
        if not code:
            fail("Empty implementation")
        check_profile(doc,code)
        symbols = pe.document(pe.record("Symbols"))["symbols"]
        impl = copy.deepcopy(original_doc["implementation"])
        old_impl, old_slot = rec["impl"], rec["slot"]
        relocated = len(code) > old_slot
        if relocated and not allow_relocate:
            fail("Code slot exhausted; review and use --relocate or perform a layout migration")
        if relocated:
            arena = pe.section(".mods")
            used = []
            for r in pe.records:
                if r["kind"] != 1:
                    continue
                d = pe.document(r)
                used.append((r["impl"],r["slot"]))
                for old in d["implementation"].get("retired",[]):
                    used.append((old["rva"],old["slot_bytes"]))
            start = align(max([arena["rva"]]+[a+b for a,b in used if arena["rva"]<=a<arena["rva"]+arena["raw_size"]]),1024)
            capacity = align(len(code),1024)
            if start+capacity>arena["rva"]+arena["raw_size"]:
                fail("Code growth arena exhausted; explicit migration required")
            if rec["entry"] != old_impl:
                retired = impl.setdefault("retired",[])
                retired.append(dict(rva=old_impl,slot_bytes=old_slot,used_bytes=rec["used"],
                                    code_sha256=rec["code_hash"].hex(),unwind_profile=impl["unwind_profile"]))
            impl["gate"] = impl.get("gate") or dict(entry_rva=rec["entry"],slot_bytes=old_slot,used_bytes=5)
            impl["implementation_rva"],impl["slot_bytes"] = start,capacity
        impl["used_bytes"] = len(code)
        impl["section"] = ".mods" if pe.section(".mods")["rva"]<=impl["implementation_rva"] else ".text"
        impl["unwind_profile"] = doc["implementation"]["unwind_profile"]
        impl["unwind_hex"] = profile(doc).hex()
        doc["implementation"] = impl
        doc["change"] = dict(reason=patch_doc.get("reason","Function patch"),generation=rec["generation"]+1,
                             previous_code_sha256=rec["code_hash"].hex(),previous_document_sha256=rec["doc_hash"].hex())
        code = patch_references(doc,code,symbols,impl["implementation_rva"])
        rows = runtime_entries(pe)
        by_start = {row[0]:row for row in rows}
        profiles = {impl["implementation_rva"]:profile(doc)}
        if relocated:
            gate_row = by_start.get(rec["entry"])
            if not gate_row:
                fail("Missing public-entry unwind record")
            gate_row[1] = rec["entry"]+5
            profiles[rec["entry"]] = bytes.fromhex("01000000")
            if impl["implementation_rva"] <= rows[-1][0]:
                fail("New bodies must append after current runtime-function entries")
            rows.append([impl["implementation_rva"],impl["implementation_rva"]+len(code),0])
        else:
            by_start[old_impl][1] = old_impl+len(code)
        direct_callers = []
        for other in pe.records:
            if other["kind"] == 1 and other["name"] != rec["name"]:
                other_doc = pe.document(other)
                if any(r["kind"] == "call" and r["target"] == rec["name"] for r in other_doc.get("references", [])):
                    direct_callers.append(other["name"])
        tmp = output.with_name(output.name+".building")
        if tmp.exists():
            fail("Unfinished candidate exists")
        shutil.copyfile(path,tmp)
        try:
            with tmp.open("r+b") as f:
                put(f,pe.offset(impl["implementation_rva"],impl["slot_bytes"]),code+b"\xcc"*(impl["slot_bytes"]-len(code)))
                if relocated:
                    gate = impl["gate"]
                    jump = b"\xe9"+struct.pack("<i",impl["implementation_rva"]-(rec["entry"]+5))
                    put(f,pe.offset(rec["entry"],gate["slot_bytes"]),jump+b"\xcc"*(gate["slot_bytes"]-5))
                unwind_info = write_runtime(pe,f,rows,profiles)
                impl["unwind"] = unwind_info[impl["implementation_rva"]]
                if relocated:
                    impl["gate"]["unwind"] = unwind_info[rec["entry"]]
                payload = canonical(doc)
                if len(payload)+1>rec["doc_capacity"]:
                    fail("Module documentation slot exhausted; explicit migration required")
                changed = dict(rec,impl=impl["implementation_rva"],used=len(code),slot=impl["slot_bytes"],
                               doc_size=len(payload),code_hash=digest(code),doc_hash=digest(payload),
                               generation=rec["generation"]+1)
                put(f,rec["record_offset"],record_bytes(changed))
                put(f,pe.offset(rec["doc_rva"],rec["doc_capacity"]),payload+b"\0"*(rec["doc_capacity"]-len(payload)))
            verify(tmp,quiet=True)
            os.replace(tmp,output)
        except Exception:
            if tmp.exists():
                tmp.unlink()
            raise
    report = binary_diff(path,output)
    report.update(module=rec["name"],relocated=relocated,entry_rva=rec["entry"],implementation_rva=impl["implementation_rva"],
                  direct_callers=direct_callers,native_tests_run=False,required_validation=["--test","--smoke"],candidate_sha256=stream_hash(output))
    Path(str(output)+".patch-report.json").write_bytes(canonical(report))
    print(json.dumps(report,indent=2))

def binary_diff(before,after):
    before,after=Path(before),Path(after)
    ranges, active, position = [],None,0
    with before.open("rb") as a,after.open("rb") as b:
        while True:
            x,y=a.read(65536),b.read(65536)
            if not x and not y:
                break
            for i in range(max(len(x),len(y))):
                changed = i>=len(x) or i>=len(y) or x[i]!=y[i]
                if changed and active is None:
                    active = position+i
                if not changed and active is not None:
                    ranges.append([active,position+i])
                    active = None
            position+=max(len(x),len(y))
        if active is not None:
            ranges.append([active,position])
    return dict(before=str(before),after=str(after),changed_bytes=sum(y-x for x,y in ranges),ranges=ranges)

def export_project(path,out):
    out=Path(out)
    if out.exists():
        fail("Export directory exists; choose an empty new path")
    out.mkdir(parents=True)
    (out/"sections").mkdir()
    (out/"modules").mkdir()
    with PE(path) as pe:
        layout=dict(schema="llm-pe.project.v1",nt_offset=pe.nt,headers_size=pe.headers_size,
                    dos_hex=pe.read(0,pe.nt).hex(),coff_flags=pe.coff_flags,
                    optional_hex=pe.opt.hex(),sections=pe.sections)
        for s in pe.sections:
            with (out/"sections"/(s["name"]+".bin")).open("wb") as target:
                pe.f.seek(s["raw_offset"])
                remaining=s["raw_size"]
                while remaining:
                    block=pe.f.read(min(65536,remaining))
                    if not block:
                        fail("Short section export")
                    target.write(block)
                    remaining-=len(block)
        for r in pe.records:
            doc=pe.document(r)
            (out/"modules"/(r["name"]+".json")).write_bytes(canonical(doc))
            if r["kind"]==1:
                (out/"modules"/(r["name"]+".bin")).write_bytes(pe.code(r))
        (out/"layout.json").write_bytes(canonical(layout))
    print(json.dumps(dict(project=str(out),modules=len(pe.records),deterministic=True)))

def build_project(project,output):
    project,output=Path(project),Path(output)
    if output.exists():
        fail("Build output exists")
    layout=json.loads((project/"layout.json").read_text(encoding="utf-8"))
    if layout.get("schema")!="llm-pe.project.v1":
        fail("Unsupported raw project schema")
    opt=bytes.fromhex(layout["optional_hex"])
    sections=layout["sections"]
    header=bytearray(layout["headers_size"])
    dos=bytes.fromhex(layout["dos_hex"])
    header[:len(dos)]=dos
    nt=layout["nt_offset"]
    header[nt:nt+4]=b"PE\0\0"
    struct.pack_into("<HHIIIHH",header,nt+4,0x8664,len(sections),0,0,0,240,layout["coff_flags"])
    header[nt+24:nt+264]=opt
    for i,s in enumerate(sections):
        at=nt+264+i*40
        name=s["name"].encode("ascii")
        header[at:at+len(name)]=name
        struct.pack_into("<IIII",header,at+8,s["virtual_size"],s["rva"],s["raw_size"],s["raw_offset"])
        struct.pack_into("<I",header,at+36,s["flags"])
    tmp=output.with_name(output.name+".building")
    if tmp.exists():
        fail("Unfinished build exists")
    try:
        with tmp.open("wb") as f:
            f.write(header)
            for s in sections:
                raw=(project/"sections"/(s["name"]+".bin")).read_bytes()
                if len(raw)!=s["raw_size"]:
                    fail("Section raw capacity differs from layout: "+s["name"])
                put(f,s["raw_offset"],raw)
        with PE(tmp) as pe:
            symbols=pe.document(pe.record("Symbols"))["symbols"]
            # Exported projects are lossless checkpoints. Function files may change only
            # through a reviewed patch; mismatches here fail instead of silently repairing docs.
            for r in pe.records:
                doc=json.loads((project/"modules"/(r["name"]+".json")).read_text(encoding="utf-8"))
                if canonical(doc)!=canonical(pe.document(r)):
                    fail("Project document differs; use a reviewed module patch: "+r["name"])
                if r["kind"]==1:
                    code=(project/"modules"/(r["name"]+".bin")).read_bytes()
                    if code!=pe.code(r):
                        fail("Project code differs; use a reviewed module patch: "+r["name"])
        verify(tmp,quiet=True)
        os.replace(tmp,output)
    except Exception:
        if tmp.exists():
            tmp.unlink()
        raise
    print(json.dumps(dict(output=str(output),sha256=stream_hash(output),bytes=output.stat().st_size)))


def new_image(output, import_names=None):
    """Create a loader-valid raw PE scaffold with an explicitly encoded exit-only entry."""
    output=Path(output).resolve()
    if output.exists():
        fail("New image output exists")
    imports = _raw.parse_imports(import_names or ["KERNEL32.dll:ExitProcess"])
    if not any(dll.lower()=="kernel32.dll" and "ExitProcess" in names for dll,names in imports.items()):
        fail("The scaffold requires KERNEL32.dll:ExitProcess")
    output.parent.mkdir(parents=True,exist_ok=True)
    root=output.parent/("."+output.name+".bootstrap")
    if root.exists():
        fail("Bootstrap directory exists")
    root.mkdir()
    arch=root/"architecture"
    arch.mkdir()
    base=arch/"base.exe"
    spec_file=arch/"migration.json"
    try:
        packed = _raw.pack_imports([dll+":"+api for dll,names in imports.items() for api in names],
                                   0x11000, capacity=0x4000)
        ro = bytearray(packed["data"])
        symbols = {"Entry":0x1000, "app_context":0x15000, "image.base":0}
        symbols.update({name:rva for name,rva in packed["symbols"].items() if name.count(".")==1})
        if len(symbols)-3 != sum(len(names) for names in imports.values()):
            fail("Ambiguous import name; use qualified registry keys in an explicit layout")
        while len(ro)%8:ro+=b"\0"
        anchor=0x11000+len(ro)
        symbols["imageAnchor"]=anchor
        ro+=struct.pack("<Q",0x140001000)
        code=bytearray.fromhex("4883ec3831c9ff15000000004883c438c3")
        struct.pack_into("<i",code,8,symbols["iat.ExitProcess"]-(0x1000+12))
        pdata=bytearray(1024)
        struct.pack_into("<III",pdata,0,0x1000,0x1000+len(code),0x19000+UNWIND_POOL)
        pdata[UNWIND_POOL:UNWIND_POOL+8]=bytes.fromhex("0104010004620000")
        reloc=struct.pack("<IIHH",anchor&~4095,12,0xA000|(anchor&4095),0)
        parts=[
            dict(name=".text",rva=0x1000,virtual_size=0x10000,raw=bytes(code)+b"\xcc"*(8192-len(code)),flags=0x60000020),
            dict(name=".rdata",rva=0x11000,virtual_size=0x4000,raw=bytes(ro),flags=0x40000040),
            dict(name=".data",rva=0x15000,virtual_size=0x4000,raw=struct.pack("<IIQ",16,1,0),flags=0xC0000040),
            dict(name=".pdata",rva=0x19000,virtual_size=0x1000,raw=bytes(pdata),flags=0x40000040),
            dict(name=".reloc",rva=0x1A000,virtual_size=0x1000,raw=reloc,flags=0x42000040)]
        cursor=1024
        for s in parts:
            s["raw_offset"]=cursor
            s["raw_size"]=align(len(s["raw"]),512)
            if s["raw_size"]>s["virtual_size"]:fail("Import section exhausted")
            cursor+=s["raw_size"]
        image=bytearray(cursor)
        struct.pack_into("<H",image,0,0x5A4D)
        struct.pack_into("<I",image,60,128)
        stub=b"Direct x64 PE scaffold.\r\n$"
        image[64:64+len(stub)]=stub
        struct.pack_into("<I",image,128,0x4550)
        struct.pack_into("<HHIIIHH",image,132,0x8664,5,0,0,0,240,0x22)
        o=152
        struct.pack_into("<H",image,o,0x20B)
        image[o+2]=1
        struct.pack_into("<IIII",image,o+4,parts[0]["raw_size"],sum(s["raw_size"] for s in parts[1:]),0,0x1000)
        struct.pack_into("<I",image,o+20,0x1000)
        struct.pack_into("<Q",image,o+24,0x140000000)
        struct.pack_into("<II",image,o+32,4096,512)
        struct.pack_into("<HHHHHH",image,o+40,6,0,1,0,6,0)
        struct.pack_into("<II",image,o+56,0x1B000,1024)
        struct.pack_into("<HH",image,o+68,3,0x8160)
        struct.pack_into("<QQQQ",image,o+72,1048576,4096,1048576,4096)
        struct.pack_into("<I",image,o+108,16)
        def directory(n,rva,size):
            struct.pack_into("<II",image,o+112+n*8,rva,size)
        directory(1,*packed["import_directory"])
        directory(3,0x19000,12)
        directory(5,0x1A000,12)
        directory(12,*packed["iat_directory"])
        for i,s in enumerate(parts):
            at=392+i*40
            image[at:at+len(s["name"])]=s["name"].encode()
            struct.pack_into("<IIII",image,at+8,s["virtual_size"],s["rva"],s["raw_size"],s["raw_offset"])
            struct.pack_into("<I",image,at+36,s["flags"])
            image[s["raw_offset"]:s["raw_offset"]+len(s["raw"])]=s["raw"]
        base.write_bytes(image)
        entry_doc=dict(schema="llm-pe.module.v1",name="Entry",contract_version=1,
                       purpose="Exit-only native scaffold; replace with the requested application and real native test dispatch.",
                       abi=dict(platform="Windows x64",inputs={},returns="Does not return; terminates through ExitProcess.",
                                caller_shadow_bytes=32,nonvolatile_preserved=["RBX","RBP","RDI","RSI","R12","R13","R14","R15","XMM6..XMM15"],
                                clobbers="Win64 volatile registers and flags",memory_contracts=[]),
                       implementation=dict(entry_rva=0x1000,implementation_rva=0x1000,used_bytes=len(code),slot_bytes=8192,
                                           section=".text",unwind_profile="stack56",unwind_hex="0104010004620000",gate=None),
                       dependencies=dict(functions=[],imports=["ExitProcess"],memory_symbols=[],contracts=[]),
                       references=[dict(offset=8,next_offset=12,target="iat.ExitProcess",rva=symbols["iat.ExitProcess"],local=None,kind="import")],
                       local_symbols={},tests=[],notes=["This bootstrap does not implement --test, --smoke or --describe; a zero exit is not test evidence."])
        module_specs=[
            dict(name="Architecture",kind=3,capacity=8192,document=dict(schema="llm-pe.module.v1",name="Architecture",contract_version=1,
                 purpose="Raw-byte application scaffold with stable slots and embedded contracts.",
                 design=dict(runtime="Explicit x64 opcode bytes; Windows DLL imports",system_imports=list(imports),
                             next_steps=["Define bounded context and module contracts.","Add native deterministic unit tests and platform smoke dispatch.","Implement the requested application in small explicit-byte modules."]),
                 native_modes=dict(test=False,smoke=False,describe=False),modules=["Entry","Data.AppContext","Symbols"],
                 limits=["Current entry only exits; no application or unit-test behavior is implied."])),
            dict(name="Symbols",kind=4,capacity=32768,document=dict(schema="llm-pe.module.v1",name="Symbols",contract_version=1,purpose="Stable RVA registry.",symbols=symbols)),
            dict(name="Data.AppContext",kind=2,capacity=4096,document=dict(schema="llm-pe.module.v1",name="Data.AppContext",contract_version=1,
                 purpose="Versioned context header reserved for a future explicit-pointer application ABI.",rva=0x15000,size=16,
                 fields=[dict(name="size_bytes",offset=0,type="uint32",value=16),dict(name="abi_major",offset=4,type="uint32",value=1),
                         dict(name="flags",offset=8,type="uint64",value=0)],ownership="Application-owned; no function currently accesses it.")),
            dict(name="Entry",kind=1,capacity=8192,code_hex=bytes(code).hex(),document=entry_doc)]
        spec=dict(schema="llm-pe.migration.v1",base_file="architecture/base.exe",output_file="unused.exe",
                  metadata=dict(rva=0x1F000,virtual_size=0x60000,raw_size=0x60000,arena_offset=0x7000),
                  code_arena=dict(rva=0x1B000,virtual_size=0x4000,raw_size=0x4000),modules=module_specs)
        spec_file.write_bytes(canonical(spec))
        migrate(spec_file,output)
    finally:
        # Only exact paths created above are removed; no recursive or computed shell deletion.
        for item in (base,spec_file):
            if item.exists():item.unlink()
        if arch.exists() and not any(arch.iterdir()):arch.rmdir()
        if root.exists() and not any(root.iterdir()):root.rmdir()



def import_inventory(pe, declared=None):
    rva, size = pe.directories[1]
    if not rva or not size or size % 20:
        fail("Invalid import directory")
    desc = pe.read(pe.offset(rva, size), size)
    result = []
    for pos in range(0, size, 20):
        lookup, timestamp, forward, name, iat = struct.unpack_from("<5I", desc, pos)
        if not any((lookup, timestamp, forward, name, iat)):
            return result
        if not lookup or not iat:
            fail("This profile requires an explicit ILT and IAT")
        dll = read_cstring(pe, name, 256)
        if (not re.fullmatch(r"[A-Za-z0-9_.-]+\.dll", dll, re.I)
                or declared is not None and dll.casefold() not in {value.casefold() for value in declared}):
            fail("DLL is invalid or absent from declared imports: " + dll)
        functions = []
        for index in range(4096):
            value = struct.unpack("<Q", pe.read(pe.offset(lookup+index*8, 8), 8))[0]
            iat_value = struct.unpack("<Q", pe.read(pe.offset(iat+index*8, 8), 8))[0]
            if value != iat_value:
                fail("On-disk IAT/ILT mismatch, including terminators")
            if not value:
                break
            row = dict(iat_rva=iat+index*8)
            if value >> 63:
                if value & 0x7fffffffffff0000:
                    fail("Reserved ordinal-thunk bits are set")
                row["ordinal"] = value & 0xffff
            else:
                pe.read(pe.offset(value, 2), 2)
                api = read_cstring(pe, value+2, 256)
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", api):
                    fail("Malformed named import: " + repr(api))
                row["name"] = api
            functions.append(row)
        else:
            fail("Unterminated import lookup")
        result.append(dict(dll=dll, functions=functions))
    fail("Unterminated import descriptors")

def resolve_system_imports(entries):
    if os.name != "nt":
        fail("Export resolution requires Windows; structural import inspection is portable")
    import ctypes
    kernel = ctypes.WinDLL("kernel32.dll", winmode=0x800)
    address = kernel.GetProcAddress
    address.argtypes, address.restype = [ctypes.c_void_p, ctypes.c_char_p], ctypes.c_void_p
    # System32 search only; never load a DLL from the executable's directory.
    for entry in entries:
        try:
            library = ctypes.WinDLL(entry["dll"], winmode=0x800)
        except OSError as exc:
            fail("Cannot load declared system DLL " + entry["dll"] + ": " + str(exc))
        for row in entry["functions"]:
            name = row.get("name")
            argument = name.encode("ascii") if name else ctypes.cast(ctypes.c_void_p(row["ordinal"]), ctypes.c_char_p)
            if not address(library._handle, argument):
                fail("Unresolved system import: " + entry["dll"] + ":" + str(name or row["ordinal"]))

def imports_view(path, resolve=False):
    with PE(path, metadata=False) as pe:
        entries = import_inventory(pe)
        if resolve:
            resolve_system_imports(entries)
        result = dict(imports=entries, system_exports_resolved=bool(resolve),
                      read_stats=dict(bytes_read=pe.bytes_read, executable_bytes=pe.size))
    print(json.dumps(result, indent=2))
    return result

def module_view(pe, name, with_bytes=False):
    rec = pe.record(name)
    doc = pe.document(rec)
    result = dict(module=doc, revision=dict(code_sha256=rec["code_hash"].hex(),
                  document_sha256=rec["doc_hash"].hex(), abi_digest=rec["abi_hash"].hex(),
                  generation=rec["generation"]),
                  storage=dict(code_slot_bytes=rec["slot"], code_free_bytes=rec["slot"]-rec["used"],
                    document_capacity_bytes=rec["doc_capacity"],
                    document_free_bytes=rec["doc_capacity"]-rec["doc_size"]-1))
    if with_bytes and rec["kind"] == 1:
        result["code_hex"] = pe.code(rec).hex()
    return result

def context_view(path, name, include=(), contracts=True, max_bytes=32768, output=None):
    if max_bytes <= 0:
        fail("Context byte budget must be positive")
    with PE(path) as pe:
        target = module_view(pe, name, True)
        doc = target["module"]
        contract_names = doc.get("abi", {}).get("memory_contracts", [])
        available = {rec["name"] for rec in pe.records}
        selected = list(dict.fromkeys(([value for value in contract_names if value in available] if contracts else []) + list(include)))
        selected = [value for value in selected if value != name]
        included = [module_view(pe, value) for value in selected]
        result = dict(schema="llm-pe.context.v1", target=target, included=included,
                      available_dependencies=doc.get("dependencies", {}),
                      missing_contract_documents=[value for value in contract_names if value not in available],
                      read_stats=dict(bytes_read=pe.bytes_read, executable_bytes=pe.size),
                      context_utf8_bytes=0)
    # Count the actual compact JSON, not code bytes or an invented token estimate.
    for _ in range(8):
        payload = (json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)+"\n").encode()
        if result["context_utf8_bytes"] == len(payload):
            break
        result["context_utf8_bytes"] = len(payload)
    if len(payload) > max_bytes:
        fail("Context requires "+str(len(payload))+" bytes; budget is "+str(max_bytes)+
             ". Narrow --include/use --no-contracts, or explicitly increase --max-bytes.")
    if output:
        destination = Path(output)
        if destination.exists():
            fail("Context output exists; choose a new path")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        print(json.dumps(dict(output=str(destination), context_utf8_bytes=len(payload), read_stats=result["read_stats"])))
    else:
        print(payload.decode(), end="")
    return result



def analyze_function(pe, name, capstone, listing=False):
    from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP, X86_INS_JMP
    rec = pe.record(name)
    if rec["kind"] != 1:
        fail("Static analysis targets function modules")
    doc, code = pe.document(rec), pe.code(rec)
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    engine.detail = True
    instructions = list(engine.disasm(code, rec["impl"]))
    starts = {item.address-rec["impl"]:item for item in instructions}
    refs = {ref["offset"]:ref for ref in doc.get("references", [])}
    errors, edges, checked = [], {}, set()
    if sum(item.size for item in instructions) != len(code):
        errors.append("Used body is not completely decodable as a linear x64 instruction stream")
    for insn in instructions:
        offset, end = insn.address-rec["impl"], insn.address-rec["impl"]+insn.size
        next_edges = []
        branch = insn.group(capstone.CS_GRP_JUMP)
        call = insn.group(capstone.CS_GRP_CALL)
        direct = bool(insn.operands and insn.operands[0].type == X86_OP_IMM and (branch or call))
        rip = next((op for op in insn.operands if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP), None)
        field = None
        target = None
        if direct:
            field = offset+insn.imm_offset
            target = insn.operands[0].imm
            expected_kind = "call" if call else "branch"
            if insn.imm_size != 4:
                errors.append("Relative control field is not a declared rel32 at "+hex(offset))
        elif rip:
            field = offset+insn.disp_offset
            target = insn.address+insn.size+rip.mem.disp
            expected_kind = "import" if call else "rip"
            if insn.disp_size != 4:
                errors.append("RIP-relative field is not 32 bits at "+hex(offset))
        if field is not None:
            ref = refs.get(field)
            if ref is None:
                errors.append("Undeclared relative instruction at "+hex(offset))
            else:
                checked.add(field)
                if ref["next_offset"] != end or ref["kind"] != expected_kind or ref["rva"] != target:
                    errors.append("Decoded instruction disagrees with declared field/end/kind/target at "+hex(offset))
        if direct and rec["impl"] <= target < rec["impl"]+len(code):
            destination = target-rec["impl"]
            if destination not in starts:
                errors.append("Control transfer enters the middle of an instruction at "+hex(offset))
            if branch:
                next_edges.append(destination)
        terminal = insn.group(capstone.CS_GRP_RET) or insn.group(capstone.CS_GRP_IRET)
        if not terminal and not (branch and insn.id == X86_INS_JMP) and end < len(code):
            next_edges.append(end)
        edges[offset] = next_edges
    for offset in refs.keys()-checked:
        errors.append("Declared relative field has no matching decoded instruction: "+hex(offset))
    for label, offset in doc.get("local_symbols", {}).items():
        if offset != len(code) and offset not in starts:
            errors.append("Named label is not an instruction boundary: "+label)
    seen, pending = set(), [0]
    while pending:
        offset = pending.pop()
        if offset in seen or offset not in starts:
            continue
        seen.add(offset)
        pending.extend(edges[offset])
    unreachable = sorted(starts.keys()-seen)
    result = dict(module=name, valid=not errors, instruction_count=len(instructions),
                  decoded_bytes=sum(item.size for item in instructions), relative_fields_checked=len(checked),
                  errors=errors, unreachable_instruction_offsets=unreachable,
                  limitations=["Linear code-body analysis; indirect transfers and call effects are not proven.",
                               "Does not prove register preservation, memory safety or intended application behavior."])
    if listing:
        result["instructions"] = [dict(offset=item.address-rec["impl"], hex=item.bytes.hex(),
            text=item.mnemonic+" "+item.op_str, successors=edges[item.address-rec["impl"]]) for item in instructions]
    return result

def audit_view(path, name, analyzer_path=None, listing=False):
    if analyzer_path:
        sys.path.insert(0, str(Path(analyzer_path).resolve()))
    try:
        import capstone
    except ImportError:
        fail("Optional audit needs Capstone 5.x in the tool environment or --analyzer-path. "
             "Nothing is installed automatically; inspect/verify/context remain standard-library only.")
    if not capstone.__version__.startswith("5."):
        fail("This optional adapter was validated with Capstone 5.x")
    with PE(path) as pe:
        result = analyze_function(pe, name, capstone, listing)
        result["read_stats"] = dict(bytes_read=pe.bytes_read, executable_bytes=pe.size)
        result["analyzer"] = "Capstone "+capstone.__version__
    print(json.dumps(result, indent=2))
    if not result["valid"]:
        fail("Static instruction/reference analysis failed")
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest="command",required=True)
    q=sub.add_parser("new");q.add_argument("--output",required=True);q.add_argument("--imports",nargs="*")
    q=sub.add_parser("migrate");q.add_argument("spec");q.add_argument("--output")
    q=sub.add_parser("inspect");q.add_argument("exe");q.add_argument("module",nargs="?");q.add_argument("--bytes",action="store_true")
    q=sub.add_parser("verify");q.add_argument("exe")
    q=sub.add_parser("context");q.add_argument("exe");q.add_argument("module")
    q.add_argument("--include",action="append",default=[]);q.add_argument("--no-contracts",action="store_true")
    q.add_argument("--max-bytes",type=int,default=32768);q.add_argument("--output")
    q=sub.add_parser("imports");q.add_argument("exe");q.add_argument("--resolve",action="store_true")
    q=sub.add_parser("audit");q.add_argument("exe");q.add_argument("module")
    q.add_argument("--analyzer-path");q.add_argument("--listing",action="store_true")
    q=sub.add_parser("patch-template");q.add_argument("exe");q.add_argument("module");q.add_argument("--output",required=True)
    q=sub.add_parser("patch");q.add_argument("exe");q.add_argument("patch");q.add_argument("--output",required=True);q.add_argument("--relocate",action="store_true")
    q=sub.add_parser("diff");q.add_argument("before");q.add_argument("after")
    q=sub.add_parser("export");q.add_argument("exe");q.add_argument("directory")
    q=sub.add_parser("build");q.add_argument("project");q.add_argument("--output",required=True)
    a=p.parse_args()
    if a.command=="new":new_image(a.output,a.imports)
    elif a.command=="migrate":migrate(a.spec,a.output)
    elif a.command=="inspect":inspect(a.exe,a.module,a.bytes)
    elif a.command=="verify":verify(a.exe)
    elif a.command=="context":context_view(a.exe,a.module,a.include,not a.no_contracts,a.max_bytes,a.output)
    elif a.command=="imports":imports_view(a.exe,a.resolve)
    elif a.command=="audit":audit_view(a.exe,a.module,a.analyzer_path,a.listing)
    elif a.command=="patch-template":template(a.exe,a.module,a.output)
    elif a.command=="patch":patch(a.exe,a.patch,a.output,a.relocate)
    elif a.command=="diff":print(json.dumps(binary_diff(a.before,a.after),indent=2))
    elif a.command=="export":export_project(a.exe,a.directory)
    elif a.command=="build":build_project(a.project,a.output)

if __name__=="__main__":
    try:
        main()
    except (ValueError,KeyError,OSError,json.JSONDecodeError,struct.error) as e:
        print("ERROR: "+str(e),file=sys.stderr)
        sys.exit(1)
