---
name: direct-pe-x64
description: Build, inspect, patch and debug Windows x64 PE executables directly from explicit machine-code bytes, with indexed module contracts and selective edits. Use for direct binary implementation or LLMPE64 maintenance; ordinary compiled development does not need this skill.
---

# Direct PE x64

Application behavior lives in explicit opcode bytes. Tooling may pack PE structures, calculate addresses and maintain contracts; it must not select instructions through a compiler, assembler or transpiler. Use documented Windows DLL imports. Static analyzers/disassemblers are permitted tools, with no dependency added to the delivered EXE.

The standard-library [workbench](scripts/pe_workbench.py) and [raw-byte helpers](scripts/raw_bytes.py) are portable Python 3.10+ tooling. The toolkit wrapper is tools/pe_workbench.py. Native execution requires Windows x64; optional audit uses Capstone 5.x only in the development environment.

Read only the relevant reference:

- Starting an application, minimizing context or choosing an edit strategy: [fast workflow](references/fast-workflow.md).
- Encoding explicit byte blocks, label edits, imports or static checks: [byte tools](references/byte-tools.md).
- PE sections, address types, ABI or loader/unwind issues: [PE layout](references/pe-layout.md).
- Existing modules, contract schemas, patch/growth or checkpoints: [module protocol](references/module-protocol.md).
- A behavioral failure, native test or platform adapter: [debugging](references/debugging.md).

For an existing image, inspect its compact directory once, then use context EXE MODULE to load one body and its direct contracts. Add only dependencies needed for the task. The compact JSON reports its actual byte size and enforces a configurable budget. Use patch-template and revision-checked patch to a new candidate; update bytes, labels, relative fields and documentation together. Review diff and required native checks. A new import/function/layout/ABI is a deliberate migration, not an ordinary patch.

For a new application, reuse deterministic packing helpers, define small bounded interfaces and make one actual end-to-end operation work early. Choose diagnostics appropriate to the host. The new command is an EXIT-ONLY scaffold; it supplies no application, native tests or self-description.

Preserve user data and live applications. Hashes, contracts and static decoding are useful checks; they do not prove runtime behavior. Indexed selective reads reduce context; hex encoding and verbose metadata can still cost tokens, so measure the packet instead of assuming the EXE is cheaper.
