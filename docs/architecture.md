# Named direct-byte executable editing

The executable is the editable artifact. Names, a brief architecture, function purposes/ABIs, data contracts and declared calls provide navigation. Application behavior remains explicit x64 bytes. The optional Python frontend retrieves these descriptions and addresses, extracts one function and can write managed patches; direct binary scripts/editors remain fully permitted.

Readable embedded metadata is concise JSON. Fixups, labels, symbol maps and unwind bookkeeping live in independently bounded compressed technical records. The frontend expands those only for an operation that needs them. Common platform rules and repeated history do not belong in every readable description.

overview retrieves names/purposes and contracts without code bodies. graph retrieves declared incoming/outgoing direct calls. get retrieves a named function or contract, with optional bytes/fixups. inspect/context retain expanded compatibility views. get --raw and sync support same-slot direct edits with stale code indexing; sync does not infer or rewrite new instruction fields.

Stable public entries and independent slot reserves permit local updates. Relocation, imports, data layouts and callbacks still need their real PE/ABI consequences handled correctly. A restriction of the managed helper is not a prohibition on another binary-editing workflow.

raw_bytes.py supplies literal frame profiles, explicit byte blocks, field rebasing and import packing. It selects no instructions from high-level application logic. Reuse complete verified operations where possible. Native tests and platform acceptance remain necessary; static decoding cannot establish intended behavior.

Use one bounded scratch workspace, preserve current reproduction inputs and compact evidence, and avoid historical dumps/candidates in deliverable folders. The application determines its host, concurrency and diagnostics; no sample game's architecture is imposed.

See [module protocol](../.agents/skills/direct-pe-x64/references/module-protocol.md), [fast workflow](../.agents/skills/direct-pe-x64/references/fast-workflow.md) and [byte helpers](../.agents/skills/direct-pe-x64/references/byte-tools.md).
