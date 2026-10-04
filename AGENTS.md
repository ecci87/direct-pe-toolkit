# Direct PE application workflow

This repository supports Windows 10 x64 applications implemented directly as explicit machine-code bytes and PE records. Preserve that constraint when building applications here: no compiler, assembler, compiled C/C++/Rust implementation, downloaded static libraries, or hidden compilation step. Python/JavaScript/PowerShell may pack bytes, calculate fixups, maintain metadata and run verification; application behavior lives in native opcode bytes. Import documented Windows DLL APIs.

Read [.agents/skills/direct-pe-x64/SKILL.md](.agents/skills/direct-pe-x64/SKILL.md) for this work. The skill's scripts are the canonical implementation; tools/pe_workbench.py is a convenience entry point. Read only the references relevant to the operation. User requirements control application behavior and scope.

## Efficient inspection and changes

Start with `python tools/pe_workbench.py inspect PATH.exe` to obtain the compact directory. Inspect the target function with its bytes and only the data contracts, callees or callers relevant to the change. Embedded module documents are authoritative for this protocol. Avoid putting whole executable dumps, large hex files or every module document into model context. Full structural verification and streaming hashes can run outside the model's context.

A routine edit uses patch-template, an explicit byte/document change, then patch to a NEW candidate. Expected code and document hashes reject stale edits. Preserve public entry RVAs and the ABI; update local labels, every relative field and instruction-end offset when byte positions change. Ordinary changes should affect the target slot, its own metadata and necessary shared unwind records. Review the diff and affected callers.

A body that exceeds its slot can use an explicitly reviewed --relocate patch: the public entry becomes a rel32 jump gate into .mods. Other callers continue using the public entry. Growth is bounded. New functions/imports, data layout changes, public ABI changes, unsupported unwind profiles or exhausted code/document/unwind reserves require a separate versioned layout migration. The current helper does not automate every migration.

## Scalable application architecture

Separate pure state transitions from input, rendering, persistence and Windows API adapters. Give each function an independently padded slot and an embedded document declaring:
- register arguments, return values, preserved registers and stack/unwind profile;
- memory contracts, ownership, read/write effects, bounds, units, invariants and error behavior;
- function/import dependencies, local symbols, relative references and meaningful tests.

For NEW modules, prefer an explicit pointer to a bounded application context; start structs with size_bytes and an ABI version. Keep versioned binary storage contracts distinct from in-memory state. Do not silently convert legacy global addressing during unrelated changes: document its exact RVAs and migrate deliberately. Keep stable external entries distinct from movable implementations. Reserve growth based on likely module changes rather than creating enormous undifferentiated padding.

Embed UTF-8 JSON documentation in a readable, non-executable .llm section, with a fixed directory and separate document slots. Keep code RX and mutable state RW. Publish native --describe MODULE, deterministic --test with log output and exit 0/1, and bounded --smoke modes in completed applications. The new command creates an EXIT-ONLY scaffold; it has NONE of those native modes yet.

## Verification and delivery

Run verify, review the candidate diff, then run the application's relevant native tests and platform smoke checks on Windows x64. The reference game supplies 51 unit assertions and five console smoke assertions. A zero process exit from an application lacking tests is not test evidence. Hashes and declared contracts check consistency; they do not prove machine-code semantics or that the ABI is actually obeyed.

Test in isolated output folders. Preserve user scores/data and a running application. Promote a verified candidate only when the destination is available; retain the previous binary for rollback. No live memory patching is part of this workflow. Report the executable path/hash, tests actually run and material remaining limits.

Toolkit maintenance uses Python 3.10+ standard library. Native execution requires Windows x64; structural inspection can run elsewhere. Keep dependency installation, publication, repository creation on a hosting service and changes to unrelated agent configuration within the user's requested scope.
