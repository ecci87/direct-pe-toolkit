# Debugging a direct-byte Windows application

Work on a copy in an isolated folder. Record the command, exit status, stdout/log and candidate hash. Preserve the user's live binary, score and other state.

## Locate the failure

A loader error happens before application tests:
- error 193 often indicates an invalid image or wrong machine/format;
- status 0xC0000135 indicates an unresolved DLL/load dependency;
- access violation 0xC0000005 during execution needs instruction/reference/stack analysis.

These are clues, not unique diagnoses. Check headers, section adjacency, imports including embedded name/thunk RVAs, IAT fields and actual DLL/API availability. verify catches the toolkit profile's structural inconsistencies but does not diagnose every loader rule.

If --test runs, use its failed assertion and the module's embedded tests/dependencies to choose the next document. Check register widths, signed comparisons, instruction-end offsets, local branches, initialization and caller/callee contracts. Avoid inspecting every function by default.

If unit tests pass but --smoke fails, inspect console/API adapters and argument layout: the Win64 fifth and later arguments live above the shadow area. Confirm real handles, return values and cleanup. A hidden console smoke launch still requires an actual new console; redirected output alone is not a complete rendering test.

## Reference evidence and regression targets

Starfall's native --test runs 51 assertions over board state, movement bounds, collisions, acceleration/spawning, score records and persistence. --smoke creates a real console, performs 120 frames and checks five assertions. These test modes use their own score paths; the toolkit's integration harness copies the fixture into a fresh output directory.

The original build also verified that an intentionally incorrect assertion produces a failed log and exit 1. Do not accept a test runner that always returns success. Log both the assertion and expected/actual information useful to diagnose failures.

A real storage bug was fixed by ensuring score-save reconstructs the record signature after an invalid-load test had altered the shared buffer. Cover invalid signature/length/content followed by save and reload, rather than assuming a previous buffer remains valid. Score units and binary layout are documented by Data.ScoreRecord.

The maintenance harness additionally checks selective reads, native module descriptions, hash/ABI rejection, same-slot patch isolation, overflow gates, rebased relative fields, byte-identical checkpoint rebuilding, corruption detection and execution from paths containing spaces and Unicode.

Native tests are implemented in the EXE, not simulated by the helper. The scaffold only exits and its metadata honestly says that test/smoke/describe are absent. For a new app, deterministic logic tests should share production function slots and accept an explicit seed or known state where useful; a bounded smoke mode covers actual Windows adapters.

## Review the fix

Write a new candidate; verify its hashes/fixups/unwind and inspect the byte diff. Run the failed regression and applicable callers, then the existing native suite and relevant smoke mode. Add tests when they establish behavior, not when they merely duplicate the chosen bytes.

If structural verification passes but behavior fails, declarations may be wrong. A SHA-256 and ABI description do not prove compliance. Inspect the actual bytes with a debugger/disassembler when needed for diagnosis; do not use an assembler/compiler to replace the user's direct-byte implementation constraint.

Keep error logs and patch reports with the candidate evidence. Deliver only after required checks actually pass, or explicitly report the unresolved failure and preserve the artifacts for the next iteration.
