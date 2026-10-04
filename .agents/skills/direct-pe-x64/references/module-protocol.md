# LLMPE64 module protocol, version 1

Read this for selective inspection, ABI-preserving patches and explicit migrations. All integers below are little-endian. Addresses in records are RVAs. The tool is the executable specification; these capacities describe its current tested profile.

## Directory and bounded reads

The read-only .llm section begins with a 512-byte header. A 192-byte record per module gives a name, typed kind, contract version, public entry, current body, reserved capacity and independent code/document/ABI digests. The reader loads PE headers, the small directory and requested document/body ranges. It does not place other bodies into model context. A streaming whole-file digest is separate from selective-read statistics.

Header:
| Offset | Representation | Meaning |
| --- | --- | --- |
| 0 | 8 bytes | LLMPE64 followed by NUL |
| 8 | uint16 pair | schema major 1, minor 0 |
| 12 | eight uint32 | header size 512, record size 192, directory capacity 128, used count, directory offset 512, document arena offset, used arena end, arena capacity |
| 48 | 16 bytes | deterministic image identity |
| 64 | uint32 pair | image build generation, schema flags |
| 72 | 32 bytes | origin image SHA-256 |
| 128 | NUL-terminated ASCII | unknown-module diagnostic |

Module record:
| Offset | Representation | Meaning |
| --- | --- | --- |
| 0 | 64 bytes | ASCII name, NUL padded |
| 64 | uint32 | CRC32 of name; checked for collisions |
| 68 | uint16 pair | kind, contract version |
| 72 | seven uint32 | entry RVA, body RVA, used code bytes, body slot bytes, document RVA, document length, document capacity |
| 100 | 32 bytes | SHA-256 of used body bytes |
| 132 | 32 bytes | SHA-256 of document bytes excluding NUL |
| 164 | 16 bytes | first 16 bytes of canonical ABI SHA-256 |
| 180 | uint32 triple | flags, module generation, reserved |

Kinds: function=1, data contract=2, architecture=3, stable symbols=4. Name restrictions are checked by the tool. Document slots contain canonical llm-pe.module.v1 JSON plus NUL and zero reserve. .llm is not executable or writable. These are development manifests, not a security trust boundary or a signature.

Function documents describe purpose, ABI, implementation/unwind, dependencies, typed memory contracts, test coverage, local_symbols and references. Each reference records offset, next_offset, target symbol, resolved RVA, optional local body offset and kind. Symbols supplies stable external RVAs; local branch targets move with their body.

Data contracts describe size, fields with offsets/types/units, ownership, read/write constraints and invariants. For new APIs, include a size/version header and pass a context pointer. The Starfall migration documents existing fixed globals without changing those legacy accesses.

## Commands

Run the skill's scripts/pe_workbench.py directly, or tools/pe_workbench.py from the toolkit root:

```text
inspect image.exe
inspect image.exe Move --bytes
inspect image.exe Data.State
patch-template image.exe Move --output move.patch.json
patch image.exe move.patch.json --output candidate.exe
diff image.exe candidate.exe
verify candidate.exe
export image.exe checkpoint-directory
build checkpoint-directory --output rebuilt.exe
```

inspect emits only the selected document/revision/body, or a compact module directory. Its storage fields expose document size/capacity/free bytes and code reserve; patch-template repeats capacity limits. Budget expanded documentation against canonical JSON length plus the NUL before patching. The native Starfall --describe MODULE command prints that same embedded JSON. Bare --describe prints Architecture; unknown names return exit 2. Generic scaffolds do not yet implement this native command.

Patch JSON has schema llm-pe.patch.v1, module, expected_code_sha256, expected_document_sha256, contract_version, reason, hex and documentation. Start from a fresh patch-template. If instructions move, update local_symbols and every affected reference offset/next_offset/local target. The patcher resolves listed displacements and updates their rva fields. It rejects stale revisions, changed public ABI/contract versions and unsupported frame profiles.

Candidate creation copies the image and rewrites only the target slot, its document/record and necessary unwind/header fields. It verifies before finalizing output and never patches the source in place. Review the sidecar patch-report: changed byte ranges, preserved entry, current body, declared direct callers, relocation status and candidate hash. native_tests_run is false: the tool does not infer or fabricate test execution.

## Growth and migrations

Use --relocate only after reviewing a body that exceeds its reserved slot. The tool appends a 1024-aligned body in .mods and writes E9 rel32 at the existing public entry. Local branches and external relative references are recomputed. The body gets its own unwind range; the entry gate gets leaf unwind. Other function bodies/call sites retain their bytes and public target RVAs.

Later relocations retain retired bodies and their unwind records. This avoids reusing old ranges while the profile remains append-only. Growth is finite: the reference has a 16 KiB .mods arena, 128 directory records, 384 KiB .llm, and 48 unwind entries. Per-module document capacities are independent. Exhaustion fails explicitly.

The current helper does not provide a universal add-module/import/data-layout migration. The migrate command handles a raw, unannotated base plus a reviewed specification, appending .mods/.llm; it is not a routine way to remigrate an already annotated image. Adapt the raw generator/layout for structural changes, version contracts, rebuild the candidate and verify all dependent accesses/callers. See the reference migration.json for explicit function bytes and contracts.

The new command builds an exit-only raw base and annotates it. Its context header and Entry reserve are scaffolding; complete applications require their own module/layout generation, native diagnostics and tests.

## Checkpoint semantics and assurance limits

export produces layout.json, raw section .bin snapshots, readable module .json documents and used function .bin bodies. build reconstructs the same bytes and rejects edited views that disagree with raw sections. This is lossless archival/reproducibility, not a second source of truth that silently repairs edited files. Apply reviewed patches first and export a fresh checkpoint afterwards.

verify checks the tested PE profile, section bounds/permissions, document/code/ABI hashes, declared fixup values, slot padding, import structures, stable gates and supported unwind ranges. It does not decode arbitrary instructions, prove register preservation, enforce memory effects, verify behavior or authenticate the binary. Behavioral assertions and byte review remain necessary.

Future extensions should version the protocol: indexed call/data dependency queries, more unwind encodings, migration tools for new modules/imports, richer context contracts and an optional x64 decoder used only for verification. Keep those optional; the current repository has no downloaded runtime dependencies.
