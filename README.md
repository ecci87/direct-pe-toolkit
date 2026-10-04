# Direct PE Toolkit

Build and maintain Windows 10 x64 applications directly from explicit machine-code bytes. No compiler, assembler or downloaded static libraries participate in application generation. A Python 3.10+ standard-library tool packs PE records, resolves declared references and maintains embedded documentation.

This repository packages the reusable direct-pe-x64 skill, shared agent instructions, prompts, the upgraded Starfall example and reproducible native checks. Source repository: [ecci87/direct-pe-toolkit](https://github.com/ecci87/direct-pe-toolkit).

## Start with your agent

Open this folder as the workspace. [AGENTS.md](AGENTS.md) is the shared workflow. Small Claude/Copilot files route to it. The [compatibility guide](docs/agent-compatibility.md) explains discovery and the explicit-read fallback for other clients.

Use a prompt from [new-app](prompts/new-app.md), [update-module](prompts/update-module.md) or [debug](prompts/debug.md). In Codex, invoke $direct-pe-x64. For other agents, ask them to read [.agents/skills/direct-pe-x64/SKILL.md](.agents/skills/direct-pe-x64/SKILL.md). The helper itself is independent of the agent provider.

## Try the real example

On Windows x64, run examples/starfall/Starfall.exe. Arrow keys or WASD move @; Enter/Space start, R/Enter/Space restart and Esc quits. Avoid falling stars for as long as possible; difficulty increases and Starfall.score stores the record beside the EXE.

From PowerShell in the repository root:

```powershell
python tools/pe_workbench.py inspect examples/starfall/Starfall.exe
python tools/pe_workbench.py inspect examples/starfall/Starfall.exe Move --bytes
python tools/pe_workbench.py verify examples/starfall/Starfall.exe
& ./examples/starfall/Starfall.exe --describe Move
python tests/run_checks.py
```

The harness copies the example into a fresh out/checks-* directory before native execution. It preserves artifacts and emits report.json. It exercises the 51 native unit assertions and five console smoke assertions as well as structural checks, selective inspection, patch isolation, growth, stale revisions and checkpoint rebuilding. Native execution requires Windows x64; inspect/verify and raw checkpoint operations can run on other hosts.

The Windows CI workflow runs that same harness on pushes and pull requests, and retains the JSON report as a workflow artifact.

## Patch one module

```powershell
New-Item -ItemType Directory -Force out | Out-Null
python tools/pe_workbench.py patch-template examples/starfall/Starfall.exe Move --output out/move.patch.json
# Edit explicit hex and its matching documentation/references.
python tools/pe_workbench.py patch examples/starfall/Starfall.exe out/move.patch.json --output out/candidate.exe
python tools/pe_workbench.py diff examples/starfall/Starfall.exe out/candidate.exe
python tools/pe_workbench.py verify out/candidate.exe
& ./out/candidate.exe --test
& ./out/candidate.exe --smoke
```

Do not assume a structural pass proves behavior. Review the generated patch report, affected callers and actual tests. Use --relocate deliberately when a body outgrows its slot. Public ABI/data/import changes require a layout migration.

## Reproduce or start

```powershell
python tools/pe_workbench.py migrate examples/starfall/architecture/migration.json --output out/from-migration.exe
python tools/pe_workbench.py export examples/starfall/Starfall.exe out/checkpoint
python tools/pe_workbench.py build out/checkpoint --output out/rebuilt.exe
python tools/pe_workbench.py new --output out/App.exe --imports KERNEL32.dll:ExitProcess
```

The migration contains the reference's explicit opcode hex and contracts and starts from the preserved raw v1 image. Export/build is a byte-identical checkpoint path. The new command creates an EXIT-ONLY scaffold; it does not yet implement an application, --test, --smoke or --describe. Adding new application functions/imports requires adapting a reviewed raw generator/layout; the helper is not a general compiler/linker.

The packaged harness passed all 37 checks on Windows 10 x64. [Recorded validation](docs/validation.md) gives the fixture hash and scope of that evidence.

The [architecture overview](docs/architecture.md) explains the 38 embedded modules, independent contracts, stable entry gates, selective reads and remaining limits. The annotated example is 452 KiB versus 52 KiB originally, primarily because of reserved documentation/growth capacity.

## Repository map

- AGENTS.md, CLAUDE.md and .github/: discovery adapters and shared workflow.
- .agents/skills/direct-pe-x64/: canonical portable skill, focused references and sole tool implementation.
- tools/pe_workbench.py: thin convenience entry point.
- prompts/: application, update and debugging prompts.
- examples/starfall/: working annotated EXE and raw migration inputs.
- tests/run_checks.py: local/CI integration evidence.
- docs/: architecture, compatibility and measured validation.

Personal scores/logs and generated output are excluded by .gitignore. No distribution license is currently declared.
