# PE layout and byte-generation findings

This is the tested toolkit profile, not a general PE linker. The Windows loader's requirements and x64 ABI are authoritative; check primary documentation when changing this profile.

## Address model and sections

Keep three address types distinct: file offset, RVA, and VA = loaded image base + RVA. For an RVA backed by a section, file offset = PointerToRawData + RVA - VirtualAddress. Zero-initialized virtual tails have no file bytes. Use section virtual capacity for address layout and raw capacity for file writes.

The tested images use Machine 0x8664, PE32+ magic 0x20B, a 240-byte optional header, 0x1000 section alignment and 0x200 file alignment. Section virtual addresses are ascending and adjacent after alignment; reserve virtual capacity to keep later sections stable. SizeOfImage covers the aligned final section. SizeOfHeaders must fit the complete section table, including planned additions.

Use RX .text/.mods, read-only .rdata/.llm/.pdata/.reloc, and RW .data. Keep file padding deterministic and code reserves filled with CC. Reserve BSS through VirtualSize rather than storing a giant zero buffer. Keep initialized context/storage headers in actual raw bytes.

The toolkit reserves .mods for append-only function growth and .llm for independently indexed documentation. Adding arbitrary new sections, imports or module ABIs remains explicit generator/layout work.

## Imports and relocation

A terminated IMAGE_IMPORT_DESCRIPTOR table points to DLL names, ILT and IAT arrays. PE32+ thunks are eight bytes. Name imports point to a two-byte hint followed by an ASCII API name and NUL. Terminate both thunk arrays. On disk, initial IAT and ILT values agree.

Moving .rdata requires updating EVERY embedded RVA in import descriptors and thunk/name records, not merely changing labels used by instructions. This was a real loader failure during the original build. An apparently valid API call cannot fix a stale import table.

The original images use Windows DLL imports only: KERNEL32.dll and USER32.dll. The scaffold accepts explicit DLL:Function declarations; declare the Windows imports required by a new application and verify against that declaration.

Dynamic-base flags alone do not establish useful relocation coverage. The reference includes a real absolute image-base pointer with a DIR64 relocation entry; its relocation block and directory are encoded manually. Relative calls/data accesses use RIP-relative or rel32 fields. Absolute addresses introduced later need appropriate relocation records.

## x64 calls and instruction references

At function entry, RSP is 8 modulo 16. Reserve 32 bytes of shadow space and align RSP to 16 before calls. The reference's normal non-leaf frame is sub rsp,56: 32 shadow bytes plus stack arguments at caller rsp+32, +40 and +48. Register arguments use RCX, RDX, R8, R9 with exact width and signedness. Preserve RBX, RBP, RSI, RDI, R12-R15 and other ABI-required nonvolatile state if used.

For any displacement field:
target RVA - (implementation RVA + instruction-end offset).
The instruction-end offset is after the ENTIRE instruction, including immediates following a RIP displacement. Do not assume it is always field offset + 4. Inserting bytes requires rebasing every affected local target and reference field/end offset. Stable external symbols always identify public entries, not movable bodies.

The helper packs already chosen bytes and displacement fields. It is not an assembler or disassembler; it cannot discover an undeclared call, incorrect opcode or register clobber.

## Unwind records

Sort RUNTIME_FUNCTION entries by begin RVA, with precise non-overlapping end RVAs. The reference reserves 48 entries and eight bytes per unwind record within a 1024-byte .pdata section.

Supported helper profiles:
- leaf: 01 00 00 00; no stack frame or declared calls.
- stack56: 01 04 01 00 04 62 00 00; a four-byte sub rsp,56 prologue, UWOP_ALLOC_SMALL of 56.

A relocated entry gate has a five-byte leaf unwind range; its body gets a separate accurate record. Unsupported stack layouts or saved-register profiles require extending the encoder and verifier explicitly. An instruction suffix/prologue check is only a consistency check, not semantic verification.

## Practical generation

Keep raw bytes and fixup manifests together. Canonical JSON uses sorted keys, UTF-8, ASCII escaping, indent 2 and a final LF. Prefer structured files to shell-built program text. On Windows, large command lines are limited; the original session wrote larger files in bounded chunks. That is an environment workaround, not a runtime dependency of the toolkit.

A loader-valid stub only proves that the image loads and exits. Build and test actual application transitions, input handling, rendering and storage separately.

Primary references:
- [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
- [Microsoft x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64)
