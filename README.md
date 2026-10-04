# Direct PE Toolkit

Build and edit Windows x64 executables directly from explicit machine-code bytes. Python helpers pack PE records and retrieve named information; no compiler, assembler, downloaded runtime code or static libraries are required.

**The EXE can always be edited directly.** Use your own byte scripts/editor or the optional frontend. The toolkit's managed-patch restrictions do not prohibit another correct binary-editing workflow.

## Retrieve only what is needed

Python 3.10+ and the standard library are sufficient. Native checks require Windows x64.

```text
python tools/pe_workbench.py overview App.exe
python tools/pe_workbench.py graph App.exe ProcessRecord
python tools/pe_workbench.py get App.exe ProcessRecord --bytes
python tools/pe_workbench.py get App.exe Data.Context
python tools/pe_workbench.py get App.exe ProcessRecord --bytes --fixups
```

overview returns brief architecture, function names/purposes/addresses and contracts, without function bodies. graph returns declared direct incoming/outgoing calls; indirect/dynamic calls are not inferred. get retrieves one name, its description, addresses and optional code/fixups. Views are compact JSON with a default 32 KiB output budget and optional --output.

The current sample's entire overview is 9101 bytes; one 77-byte function with description and code is 1026 bytes. That function view omits contracts and technical fixups until requested. These are measured bytes, not a tokenizer or productivity benchmark.

## Concise embedded descriptions

Embed a brief architecture, one purpose per function, essential ABI/data contracts and declared calls. Keep tutorials, change history and test transcripts outside the EXE. The agent writes semantics; tools derive addresses, lengths, dependencies, hashes and reserves.

Concise storage keeps readable JSON separate from independently bounded compressed edit records for fixups, labels, symbol maps and unwind. The helper expands those records only when needed. Legacy expanded images remain readable.

The sample's readable metadata fell from 418361 to 36184 bytes; its EXE fell from 878592 to 235520 bytes. Every function body/public address was preserved. The smaller image still includes reserved slots, an index and mechanical records.

```text
python tools/pe_workbench.py compact App.exe --output out/work/task/compact.exe
```

new defaults to concise storage but supplies only an EXIT-ONLY scaffold. Migration specifications opt in with metadata.format=concise-v1; legacy specifications retain their original packing.

## Edit by either workflow

Managed edits use patch-template/patch and optional relocation. Direct edits can use any suitable binary tooling. Same-slot indexing repair is available:

```text
python tools/pe_workbench.py get edited.exe ProcessRecord --bytes --raw
python tools/pe_workbench.py sync edited.exe ProcessRecord --used-bytes 123 --manifest module.json --output out/work/task/candidate.exe
python tools/pe_workbench.py verify out/work/task/candidate.exe
```

--raw reports stale code hashes while returning the indexed body. sync preserves the bytes as edited and refreshes indexing; it does not infer/rewrite instruction fields. Supply an accurate expanded manifest if fields moved. Other layout/interface changes can use a correct direct edit or an explicit migration.

[raw_bytes.py](.agents/skills/direct-pe-x64/scripts/raw_bytes.py) supplies literal frame profiles, byte blocks, named field rebasing and import packing. It does not translate application logic or choose instruction encodings. Optional audit uses a development-only Capstone 5.x installation.

## Workflow and validation

[AGENTS.md](AGENTS.md), the [skill](.agents/skills/direct-pe-x64/SKILL.md), [prompts](prompts/update-module.md) and [client adapters](docs/agent-compatibility.md) support application-neutral work in Codex, Copilot, Claude and explicit-read clients.

Reuse verified operations, keep one out/work workspace, finalize semantic contracts before broad checks and retain current reproduction inputs plus compact evidence. Successful test runs clean their owned temporary files and retain out/evidence JSON reports.

```text
python tests/test_primitives.py
python tests/test_primitives.py --analyzer-path PATH_TO_CAPSTONE
python tests/run_checks.py
```

[Validation evidence](docs/validation.md) records actual checks. The [Starfall example](examples/starfall/README.md) supplies a native fixture; its gameplay/input solution is not a requirement for another application. The repository declares no distribution license.

Source: [ecci87/direct-pe-toolkit](https://github.com/ecci87/direct-pe-toolkit).
