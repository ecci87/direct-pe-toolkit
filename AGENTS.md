# Direct PE application workflow

Build Windows x64 executable behavior from explicit machine-code bytes and PE records. Do not introduce a compiler, assembler, transpiled implementation, downloaded runtime code or static libraries. Scripts may pack bytes, resolve fields and run checks. Documented Windows DLL imports are the runtime platform. Static machine-code analyzers/disassemblers are permitted development tools.

Read [.agents/skills/direct-pe-x64/SKILL.md](.agents/skills/direct-pe-x64/SKILL.md), then only the reference needed for the operation. Its scripts are canonical; tools/pe_workbench.py is a thin entry point.

For edits, obtain the directory once and use context for the target function plus necessary contracts. Keep unrelated bodies and whole-file dumps outside model context. Embedded module documents describe the current revision. Preserve public entries and contracts; use patch-template and patch for existing functions. Additions or layout/ABI/import changes require an explicit migration.

For new applications, get one real input-to-output path working before expanding modules or reserves. Keep platform adapters separate from core operations, with explicit arguments and owned/borrowed resources. Choose diagnostic/test dispatch suitable for the application's host; a service, adapter or file processor need not have a console UI. The scaffold only exits.

Before a fix, reproduce the reported failure through the actual path involved. Run structural and focused native checks while iterating, then the required broader checks once the candidate works. Pure tests cannot establish adapter behavior. Log expected/actual results and meaningful failure status; avoid rebuilding unchanged modules or repeating passed checks without a reason.

Deliver a new verified candidate, preserve user data/live processes and retain rollback artifacts. Report actual tests and limitations. Follow [the fast workflow](.agents/skills/direct-pe-x64/references/fast-workflow.md) for byte budgets, reuse, migrations and small edit packets.
