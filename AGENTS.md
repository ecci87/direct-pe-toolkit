# Direct PE application work

Application behavior lives in explicit Windows x64 instruction bytes. Do not introduce a compiler, assembler, transpiled application, downloaded runtime code or static libraries. Packing scripts and static analyzers are allowed.

The EXE is the artifact being edited. Agents may always inspect or modify it directly using their own byte scripts, a binary editor or other suitable tools. The Python frontend is optional: it provides names, descriptions, addresses, code, contracts, declared calls and managed patching. Its limitations do not prohibit another correct binary-editing approach.

Read [.agents/skills/direct-pe-x64/SKILL.md](.agents/skills/direct-pe-x64/SKILL.md). Keep embedded descriptions short: a brief architecture, one purpose per function, essential ABI/data contracts and declared call relationships. Generate lengths, addresses, hashes and fixup bookkeeping mechanically. Keep tutorials, history and test transcripts outside the EXE.

For a local change, retrieve only the affected functions and necessary contracts. Optional commands are overview, graph EXE NAME, get EXE NAME --bytes, and get EXE NAME --fixups when editing address fields. Preserve working adapters during unrelated changes. Reuse verified complete functions or literal byte fragments with fixed registers, patchable fields and known frame contracts.

Direct edits must leave executable addresses, branches, imports and unwind information correct. If managed metadata should remain usable, refresh affected records; sync can do this for same-slot edits with accurate fixup declarations. It does not infer new semantics. A tool-required migration is a constraint of that helper, not a requirement to use it.

Use a bounded work directory under out/work. Retain current reproduction inputs, one useful rollback and compact evidence; successful tests clean their owned temporary files. Do not accumulate numbered candidate folders or duplicate whole-image dumps.

Run focused structural/native checks during iteration. Finalize semantic contracts before required broad checks. Cosmetic descriptions need structural/description checks; code, interfaces, data layout, imports or host changes need their relevant behavioral checks. Preserve user data and live applications, and report which artifact and behavior were actually verified.
