# Embedded architecture and scalable edits

The upgraded Starfall EXE is a concrete example, not only an instruction proposal. It contains 38 indexed JSON documents: 29 functions, seven data contracts, Architecture and Symbols. Public addresses of the original 28 functions remain stable. Entry now dispatches a native DescribeRequest function before the existing game/test modes.

Each function has its own used body, padded capacity, revision hashes, ABI declaration, dependencies, local fixups and tests. .llm keeps these documents separate and readable. The directory lets a tool fetch a single function without reading every body. Inspecting Move and its bytes reads 11,303 bytes from the 462,848-byte reference image; loading relevant contracts/callees adds only their own ranges.

Within its reserve, a function update changes its body, document, directory record and necessary unwind metadata. A larger body can relocate into .mods behind its stable entry. The integration checks verify that all other function implementation hashes and public target symbols stay unchanged, and run native tests against both variants.

This preserves the original gameplay: an @ dodges falling stars, difficulty rises, and survival time becomes the high score. The legacy code still accesses fixed global state; its seven data contracts now expose those exact layouts. New applications should use explicit context-pointer APIs to reduce such coupling. Converting the game's entire ABI would be a separate migration.

The original executable is 53,248 bytes. The annotated example is 462,848 bytes, mostly because documentation and future growth have reserved capacity. This is a deliberate inspectability/growth tradeoff. Capacities can be reduced for a release profile or enlarged through a reviewed migration. A release without metadata would need a separate development artifact and a different inspection workflow.

Current implementation limits are explicit: finite .mods/.llm/unwind capacity, two supported frame profiles, routine patches only for existing function modules, and checkpoint rebuilds rather than automatic arbitrary source edits. Verification checks recorded invariants, not the semantics of unknown opcodes. This approach is useful for small direct-byte experiments; it does not acquire compiler-scale optimization, type checking or automatic linking merely by adding metadata.

See [the protocol](../.agents/skills/direct-pe-x64/references/module-protocol.md) for binary offsets, commands and migration boundaries. The proposed next extensions are context-based module APIs, indexed dependency queries, additional unwind encodings and deliberate module/import migration support. Those are future improvements, not claimed implemented features.
