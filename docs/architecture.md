# Architecture for selective direct-byte edits

Application behavior is stored in explicit instruction bytes. The workbench packs PE structures and declared references; it does not compile or choose opcodes. Ordinary Windows DLL APIs are the platform boundary. Development-only static analyzers can check encoded instructions independently.

## Independent modules

An executable directory indexes function bodies, data contracts, architecture and stable symbols. Each function has a padded slot, public entry, implementation range, code/document/ABI hashes, local labels, fixups and an ABI document. Data contracts declare bounds, ownership, field types/units, mutation and error behavior.

New module interfaces should pass explicit bounded arguments. A size/version header is useful for evolving contexts; separate contexts and storage contracts when ownership differs. The exact application decides host entry, callbacks, concurrency and resource lifecycle. There is no required event loop, console, board, timer or persistence format.

Windows x64 volatile/nonvolatile register rules, stack alignment and unwind layout apply regardless of application. The current helper supports leaf and stack56 frames. More complex prologues require explicit encoder/verifier extensions, not an undocumented workaround.

## Stable edits

Callers target stable public entries; bodies can relocate behind jump gates when a slot fills. Same-slot edits rewrite only the affected body/document/record and necessary unwind metadata. The patch report identifies declared callers without placing unrelated bodies into model context.

Routine patches preserve contract version and public ABI. Function/import additions, data changes and unsupported profiles are explicit migrations. Reserves remain finite; read the current image's capacities rather than importing the example's layout assumptions.

## Context and tooling

inspect reads the compact directory or one named module. context returns one body plus necessary documents, with compact JSON, revision hashes and a byte budget. It does not load all function bodies or fabricate an absent caller index. Whole-file hashes, structural checks and checkpoint snapshots run outside model context.

raw_bytes.py centralizes declared field ends, local-label rebasing, explicit insertion policy and import packing. It accepts literal bytes and symbolic addresses, not a high-level application or assembly language. The static audit adapter independently decodes a selected body and compares it with those declarations.

Small machine code does not by itself imply low token use: hex is larger than raw bytes and semantic information must be retained. Independent contracts and retrieval boundaries make small edits efficient. Keep descriptions local, preserve evidence and avoid oversized universal contexts/reserves.

See [fast workflow](../.agents/skills/direct-pe-x64/references/fast-workflow.md), [byte tools](../.agents/skills/direct-pe-x64/references/byte-tools.md) and [module protocol](../.agents/skills/direct-pe-x64/references/module-protocol.md).
