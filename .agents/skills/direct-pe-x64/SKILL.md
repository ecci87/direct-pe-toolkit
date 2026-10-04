---
name: direct-pe-x64
description: Build, inspect, edit and debug Windows x64 executables directly from explicit instruction bytes, with concise embedded names/contracts and optional Python retrieval helpers.
---

# Direct PE x64

Implement behavior with explicit opcode bytes and PE records. Scripts may pack bytes, calculate addresses and maintain indexing; do not compile/assemble/transpile application logic or download runtime code. Static analyzers are allowed development tools.

Direct EXE editing is always an available workflow. Use a binary editor, your own script or these optional standard-library Python helpers. The frontend supports named retrieval and managed patches; it does not own the EXE or restrict other correct editing methods.

Embedded metadata is a small navigation aid: brief architecture, function purposes/ABIs, data contracts and declared calls. Keep change history, tutorials and test transcripts outside it. Concise storage separates readable descriptions from compressed mechanical edit records.

From the toolkit root:

```text
python tools/pe_workbench.py overview App.exe
python tools/pe_workbench.py graph App.exe Function
python tools/pe_workbench.py get App.exe Function --bytes
python tools/pe_workbench.py get App.exe Data.Context
```

Load fixups only when needed with get --fixups or context. For direct byte changes, get --bytes --raw can retrieve a body whose old hash is stale; sync refreshes same-slot indexing with accurate declarations. Managed patch-template/patch and relocation are alternatives. Read only the relevant reference:

- [Fast workflow](references/fast-workflow.md): implementation decisions, reuse, validation and bounded output.
- [Byte helpers](references/byte-tools.md): literal frames, byte blocks, fixups, imports and optional audit.
- [Module protocol](references/module-protocol.md): compact storage, views, direct edits and managed patch limits.
- [PE layout](references/pe-layout.md): address types, loader and unwind rules.
- [Debugging](references/debugging.md): actual adapter failures and native evidence.

The scaffold only exits. Adapt host entry, callbacks, diagnostics and acceptance to the requested application. Reuse verified functions/fragments under their actual contracts; arbitrary register/stack changes need analysis. Preserve user data/live processes, keep scratch files in one workspace and run the relevant native path. Byte size, padded file size and model context size are different measurements.
