"""Deterministic packing of explicitly supplied bytes; no instruction selection."""
import copy
import re
import struct

def _bytes(value):
    return bytes.fromhex(value) if isinstance(value, str) else bytes(value)

def parse_imports(declarations):
    """Normalize named DLL exports. No file/network access."""
    imports, spellings = {}, {}
    for declaration in declarations:
        parts = declaration.split(":")
        if (len(parts) != 2 or not re.fullmatch(r"[A-Za-z0-9_.-]+\.dll", parts[0], re.I)
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", parts[1])):
            raise ValueError("Use DLL.dll:FunctionName; embedded NULs and escaped terminators are invalid")
        dll, api = parts
        key = dll.casefold()
        dll = spellings.setdefault(key, dll)
        names = imports.setdefault(dll, [])
        if api not in names:
            names.append(api)
    if not imports:
        raise ValueError("At least one named import is required")
    return imports

def pack_imports(declarations, rva, prefix=b"", capacity=None):
    """Append a complete descriptor/name/ILT/IAT layout, preserving prefix bytes.

    Returned RVAs are image-relative. Directory 1 describes only descriptors;
    directory 12 spans IAT arrays. Qualified symbols always exist; unqualified
    iat.Function symbols are supplied only when the export name is unique.
    """
    imports = parse_imports(declarations)
    if not 0 <= rva < 2**32:
        raise ValueError("Import base must be a uint32 RVA")
    data = bytearray(prefix)
    def allocate(payload, alignment=1):
        data.extend(b"\0" * ((-len(data)) % alignment))
        offset = len(data)
        data.extend(payload)
        if rva + len(data) > 2**32 or capacity is not None and len(data) > capacity:
            raise ValueError("Import range/capacity exhausted")
        return rva + offset
    directory = allocate(b"\0" * (20 * (len(imports) + 1)), 8)
    descriptors, symbols, entries, counts = [], {}, [], {}
    for dll, names in imports.items():
        dll_rva = allocate(dll.encode("ascii") + b"\0")
        name_rvas = [allocate(b"\0\0" + name.encode("ascii") + b"\0", 2) for name in names]
        thunks = b"".join(struct.pack("<Q", value) for value in name_rvas) + b"\0" * 8
        ilt = allocate(thunks, 8)
        iat = allocate(thunks, 8)
        descriptors.append((ilt, dll_rva, iat, len(thunks)))
        functions = []
        for index, name in enumerate(names):
            slot = iat + index * 8
            symbols["iat." + dll + "." + name] = slot
            counts.setdefault(name, []).append(slot)
            functions.append(dict(name=name, iat_rva=slot))
        entries.append(dict(dll=dll, functions=functions))
    for index, (ilt, name, iat, size) in enumerate(descriptors):
        struct.pack_into("<5I", data, directory - rva + index * 20, ilt, 0, 0, name, iat)
    symbols.update({"iat." + name: slots[0] for name, slots in counts.items() if len(slots) == 1})
    iat_start = min(row[2] for row in descriptors)
    iat_end = max(row[2] + row[3] for row in descriptors)
    return dict(data=bytes(data), symbols=symbols, entries=entries,
                import_directory=(directory, 20 * (len(imports) + 1)),
                iat_directory=(iat_start, iat_end - iat_start))

def validate_fixups(code, references, labels):
    """Check declared fields/labels, without claiming to decode x64 instructions."""
    occupied = set()
    for name, offset in labels.items():
        if not isinstance(offset, int) or not 0 <= offset <= len(code):
            raise ValueError("Local label outside byte block: " + name)
    for ref in references:
        at, end = ref["offset"], ref["next_offset"]
        if not 0 <= at <= len(code)-4 or not at+4 <= end <= len(code):
            raise ValueError("Reference field/end outside byte block")
        cells = set(range(at, at+4))
        if cells & occupied:
            raise ValueError("Overlapping relative fields")
        occupied.update(cells)
        if ref["kind"] not in ("rip", "call", "import", "branch"):
            raise ValueError("Unknown relative field kind")
        local = ref.get("local")
        if local is not None:
            if not 0 <= local < len(code):
                raise ValueError("Local branch target outside byte block")
            if ref["target"] not in labels or labels[ref["target"]] != local:
                raise ValueError("Local target disagrees with its named label: " + ref["target"])

class ByteBlock:
    """Raw hex, named labels and rel32 fields only; no mnemonic assembler."""
    def __init__(self):
        self.code = bytearray()
        self.references = []
        self.labels = {}

    @classmethod
    def from_module(cls, document, code):
        block = cls()
        block.code = bytearray(_bytes(code))
        block.references = copy.deepcopy(document.get("references", []))
        block.labels = copy.deepcopy(document.get("local_symbols", {}))
        validate_fixups(block.code, block.references, block.labels)
        return block

    def emit(self, raw):
        self.code.extend(_bytes(raw))
        return self

    def label(self, name):
        if name in self.labels:
            raise ValueError("Duplicate label: " + name)
        self.labels[name] = len(self.code)
        return self

    def relative(self, prefix, target, tail=b"", kind="rip"):
        self.emit(prefix)
        offset = len(self.code)
        self.emit(b"\0" * 4).emit(tail)
        self.references.append(dict(offset=offset, next_offset=len(self.code), target=target,
                                    local=None, kind=kind, rva=0))
        return self

    def manifest(self):
        references = copy.deepcopy(self.references)
        for ref in references:
            if ref["target"] in self.labels:
                ref["local"] = self.labels[ref["target"]]
        validate_fixups(self.code, references, self.labels)
        return dict(code_hex=bytes(self.code).hex(), references=references,
                    local_symbols=dict(self.labels))

    def insert_before(self, label, fragment, *, branch_targets):
        """Require an explicit choice: existing branches include or skip the hook.

        No positional offsets or implicit >= rebasing. Neither object is modified
        if validation fails. Fragment labels must not collide with existing labels.
        """
        if branch_targets not in ("include", "skip"):
            raise ValueError("Choose branch_targets='include' or 'skip'")
        if label not in self.labels:
            raise ValueError("Unknown insertion label: " + label)
        current, added = self.manifest(), fragment.manifest()
        if set(current["local_symbols"]) & set(added["local_symbols"]):
            raise ValueError("Inserted labels collide with existing labels")
        point, amount = self.labels[label], len(fragment.code)
        for ref in current["references"]:
            if ref["offset"] < point < ref["next_offset"]:
                raise ValueError("Insertion splits a declared relative instruction")
        def shift_target(offset):
            return offset + amount if offset > point or offset == point and branch_targets == "skip" else offset
        labels = {name: shift_target(offset) for name, offset in self.labels.items()}
        labels.update({name: point+offset for name, offset in fragment.labels.items()})
        refs = []
        for ref in current["references"]:
            ref = copy.deepcopy(ref)
            if ref["offset"] >= point:
                ref["offset"] += amount
                ref["next_offset"] += amount
            if ref["local"] is not None:
                ref["local"] = shift_target(ref["local"])
            refs.append(ref)
        for ref in added["references"]:
            ref = copy.deepcopy(ref)
            ref["offset"] += point
            ref["next_offset"] += point
            if ref["local"] is not None:
                ref["local"] += point
            elif ref["target"] in labels:
                ref["local"] = labels[ref["target"]]
            refs.append(ref)
        code = self.code[:point] + fragment.code + self.code[point:]
        validate_fixups(code, refs, labels)
        self.code, self.references, self.labels = code, refs, labels
        return self

    def update_document(self, document):
        """Return an edited copy; ABI/profile changes remain an explicit decision."""
        result = copy.deepcopy(document)
        manifest = self.manifest()
        result["references"] = manifest["references"]
        result["local_symbols"] = manifest["local_symbols"]
        result["implementation"]["used_bytes"] = len(self.code)
        return result
