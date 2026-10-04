Read AGENTS.md, the direct-pe-x64 skill, and only its fast-workflow reference initially.

Build [application, host/entry contract, inputs, outputs, and acceptance criteria] for Windows x64. Native behavior must be explicit machine-code bytes in a PE; no compiler, assembler, downloaded runtime code or static libraries. Packing/fixup scripts and static analyzers are allowed.

Reuse deterministic byte/import packing tools and documented Windows APIs. Get the smallest real input-to-output operation working early; then extend it in bounded modules with explicit contracts and independently indexed documentation. Choose test/diagnostic dispatch appropriate to the host. The exit-only scaffold is not a completed application.

Use isolated candidates and fixtures. Validate imports, ABI/stack layout, fixups and unwind, then relevant native behavior. Run focused checks while iterating and required broader acceptance checks before delivery. Deliver the verified executable, hash, reproducible packing/checkpoint path and actual evidence.
