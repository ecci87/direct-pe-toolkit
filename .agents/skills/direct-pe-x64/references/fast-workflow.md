# Efficient direct-byte work

Start with one observable input-to-output acceptance case and the actual host contract. A service callback, file transformation or adapter needs its own real path. Get that path working before expanding modules.

Choose how to edit the EXE. Direct byte scripts/editors are permitted. Optional frontend views provide an overview, declared incoming/outgoing calls, names, RVAs/file offsets and only the selected body/contract. Load technical fixups only for a change that needs them; avoid whole-image hex or unrelated bodies in model context.

Reuse complete verified functions first, then fixed-register literal fragments. raw_bytes.py supplies leaf/stack56 frames, relative-field packing and import packing. A fragment should declare its inputs, outputs, clobbers, bounds, patchable fields and evidence. Helpers must not select instructions from arbitrary high-level application logic. A shared native test runner with data cases can reduce repeated setup/assertion bytes when actual repetition justifies it; there is no mandatory universal runner.

The agent writes semantics once: purpose, ABI, bounds, ownership, mutations and errors. Tools derive byte lengths, addresses, hashes, symbol locations and dependencies. Keep descriptions concise and local. Reuse a common profile; do not append migration history to every function or bump ABI versions for implementation-only changes.

Managed patching preserves indexed interfaces. Direct edits can change any executable part when the corresponding PE/ABI/address consequences are handled correctly. sync is a same-slot metadata repair helper, not a requirement or general linker. Preserve working platform adapters during unrelated changes.

Use out/work/TASK for scratch output, one current candidate and minimal evidence. Successful repository tests remove their process-owned temporary directories and retain out/evidence reports. Keep current reproduction inputs and a useful rollback, using Git for historical versions. Delete only identified generated artifacts.

Run structural checks and a focused regression while iterating. Finalize contracts before the required broader checks. Reuse behavioral evidence only when code, relevant data, addresses, imports and host assumptions are unchanged and identify that equivalence explicitly. A description-only change normally needs integrity/self-description checks rather than another complete native suite.

Keep the edit packet bounded. get defaults to 32 KiB; explicit --fixups may require a larger budget for a large diagnostic function. context remains an expanded compatibility/edit packet. Compact serialization saves disk; selective retrieval and removing repeated explanations save model context.
