# Reusable byte construction and static checks

scripts/raw_bytes.py provides ByteBlock, validate_fixups, parse_imports and pack_imports. These functions accept already chosen hex/data; they do not assemble mnemonics, compile expressions, select registers or implement application behavior.

## ByteBlock

emit appends explicit hex or bytes. label names a current offset. relative appends a supplied opcode prefix, a four-byte displacement placeholder and an optional immediate tail; it records the end of the entire instruction. manifest returns code_hex, references and local_symbols. The workbench resolves fields to local offsets or stable external RVAs.

```python
from raw_bytes import ByteBlock
block = ByteBlock()
block.relative("e9", "function.return", kind="branch")
block.label("function.return").emit("c3")
manifest = block.manifest()
```

Import the helper from the skill's scripts directory in a packing script; no installed package is required. For an existing module, ByteBlock.from_module(document, code_hex) retains declared fields/labels. update_document returns an edited copy with updated code length/labels/references; review ABI, dependencies, profile and purpose separately.

insert_before(label, fragment, branch_targets="include") makes existing branches to that label enter the new bytes. "skip" keeps those branches pointed at the previous instruction. There is no implicit default: the same rebasing policy is not correct for every hook. New fragment labels must be unique. An insertion splitting a declared relative instruction, overlapping fields or inconsistent local label targets is rejected without modifying either object.

These declarations do not prove instruction boundaries. Use an allowed analyzer when a label/boundary is uncertain; do not guess offsets from a previous revision.

## Imports

pack_imports(["KERNEL32.dll:ExitProcess"], rva=0x11000) returns a bytes payload, symbol RVAs, descriptor and IAT directory pairs. It packs the two-byte hint, ASCII NUL terminators, eight-byte ILT/IAT arrays and zero descriptors once. Optional prefix bytes are preserved and capacity bounds are checked. Qualified iat.DLL.dll.Function symbols exist; an unqualified iat.Function is emitted only when unambiguous.

Use these returned structures when constructing the chosen raw section/header layout. This is not an automatic migration of an annotated image. Existing IAT/public RVAs must remain stable when required by contracts; do not move them merely to add an API.

```text
python tools/pe_workbench.py imports app.exe
python tools/pe_workbench.py imports app.exe --resolve
```

Structural inspection works on raw or annotated images and validates named imports, thunk arrays and terminators. --resolve checks actual exports on Windows using only the system DLL search directory. It does not execute application code or validate API arguments. No resolver is required on non-Windows hosts; native validation still needs Windows.

## Optional instruction audit

```text
python tools/pe_workbench.py audit app.exe Function
python tools/pe_workbench.py audit app.exe Function --analyzer-path PATH_TO_CAPSTONE
python tools/pe_workbench.py audit app.exe Function --listing
```

audit uses optional Capstone 5.x, supplied by the tool environment or a local analyzer path. Nothing is installed automatically and the analyzer is not linked into the EXE. Other static analyzers are also allowed; preserve their input/output evidence.

The adapter decodes only the chosen used body, checks local labels/control targets against instruction starts, matches actual relative field locations/ends/kinds/targets to the manifest, and reports unreachable instruction offsets. Default output is a compact diagnostic summary; --listing adds decoded instructions and local successor offsets.

The current adapter assumes a linear instruction-only body. Embedded data, indirect jumps, exceptional control flow and call effects require additional interpretation. Unreachable offsets are clues, not proof of a defect. Passing decoding cannot prove intended branch semantics, ABI preservation, pointer bounds, adapter behavior or acceptance criteria; run the native regression.

See [Capstone's Python interface](https://www.capstone-engine.org/lang_python.html). No assembler or compiler is used by these helpers.
