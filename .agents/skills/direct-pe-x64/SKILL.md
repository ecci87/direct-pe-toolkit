---
name: direct-pe-x64
description: Create, inspect, patch and debug Windows x64 PE executables built directly from machine-code bytes, with embedded module documentation and versioned contracts. Use when direct binary implementation is requested or an LLMPE64 executable is being maintained; ordinary compiled application development does not need this skill.
---

# Direct PE x64

Application instructions are explicit opcode bytes. Scripts may pack PE structures, calculate references and maintain modules; do not insert a compiler, assembler or compiled high-level implementation into a user-requested direct-byte workflow. Use Windows DLL imports; no downloaded static libraries are needed.

The standard-library helper is [scripts/pe_workbench.py](scripts/pe_workbench.py). In the toolkit repository, tools/pe_workbench.py invokes it. Python 3.10+ runs the helper; Windows x64 runs native binaries.

Choose only the relevant reference:
- New executable, imports, address fixups or loader/unwind failures: [PE layout and learned pitfalls](references/pe-layout.md).
- Inspection, contracts, patching, growth or migration: [module protocol](references/module-protocol.md).
- Native tests, logs and behavioral faults: [debugging workflow](references/debugging.md).

## Work on an existing image

Use `inspect image.exe` for its compact directory, then `inspect image.exe Function --bytes`. Load only that document and needed contracts/callees. Treat embedded documents as the current revision; large exported maps and raw section snapshots are not efficient model context.

Create a patch with `patch-template image.exe Function --output change.patch.json`. Edit its hex, reason, local symbols/references and documentation together. Check the reported document headroom before expanding notes; the canonical JSON plus its NUL must fit. Keep expected revision hashes and the public ABI. Build with `patch image.exe change.patch.json --output candidate.exe`, review `diff image.exe candidate.exe`, run `verify candidate.exe` and meaningful native tests. The helper verifies candidates automatically but does not execute native tests for you.

Slot overflow needs an explicit --relocate decision. ABI/data/import changes, adding functions and exhausted reserves need an explicit layout migration; do not label them routine function patches. See the protocol reference for the helper's actual limits.

## Start an application

`new --output App.exe --imports KERNEL32.dll:ExitProcess` writes a loader-valid raw PE with an EXIT-ONLY entry and embedded contracts. It supplies no gameplay, --test, --smoke or --describe behavior. Adapt the raw layout/generator for the requested application and required modules; a successful scaffold exit is not completion.

Separate deterministic core logic from platform adapters. New module ABIs should pass an explicit bounded context pointer; version and document data layouts before encoding accesses. Use independent slots, stable public entries, declared fixups and accurate unwind records. Implement native deterministic tests with log output/exit status and a bounded platform smoke mode alongside application behavior.

Preserve user data; use isolated candidate paths. Report actual verification, remaining limits and the final artifact. Metadata hashes prove consistency, not the correctness of arbitrary instructions.
