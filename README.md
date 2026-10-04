# Direct PE Toolkit

Build and maintain Windows x64 executables directly from explicit machine-code bytes and PE structures. The workflow removes the source-to-machine-code compile/assemble step. Python tooling packs already chosen bytes, resolves addresses and maintains independently indexed module contracts. Delivered applications use documented Windows DLL imports; no downloaded runtime code or static libraries are required.

The repository is application-neutral: process tools, file processors, services, adapters and interactive applications use the same bounded module workflow. Entry, callbacks, I/O and test hosting follow the application actually requested. [AGENTS.md](AGENTS.md) and the portable [direct-pe-x64 skill](.agents/skills/direct-pe-x64/SKILL.md) steer compatible agents; [discovery adapters](docs/agent-compatibility.md) support Codex, Copilot, Claude and explicit-read clients.

## Work on a small context

Use Python 3.10+ with the standard library. Windows x64 is required for native execution.

```text
python tools/pe_workbench.py inspect PATH.exe
python tools/pe_workbench.py context PATH.exe Function --output out/function.context.json
python tools/pe_workbench.py context PATH.exe Function --include Data.Required
python tools/pe_workbench.py patch-template PATH.exe Function --output out/change.patch.json
python tools/pe_workbench.py patch PATH.exe out/change.patch.json --output out/candidate.exe
python tools/pe_workbench.py diff PATH.exe out/candidate.exe
```

context includes the selected function body/document, revision hashes, capacities and direct data contracts. Explicit --include adds only a needed document; other function bodies stay out. Compact output has an exact UTF-8 byte count and a default 32 KiB budget. --no-contracts or --max-bytes lets you choose the scope deliberately; oversized packets fail instead of silently omitting essential data.

In the checked-in fixture, one 77-byte function and its direct contract produce a 5666-byte JSON packet; the EXE is 747520 bytes. This demonstrates selective context, not a tokenizer benchmark or guaranteed speedup. Hex expands binary data, semantic contracts still matter, and documentation/padding can dominate file size.

## Catch packing errors early

[raw_bytes.py](.agents/skills/direct-pe-x64/scripts/raw_bytes.py) provides byte blocks, named labels, relative field declarations and import packing. It supplies no mnemonic assembler or application implementation. Named insertion requires choosing whether existing branches enter or skip a new hook. Field overlaps, conflicting labels and stale local targets are rejected.

```text
python tools/pe_workbench.py imports PATH.exe
python tools/pe_workbench.py imports PATH.exe --resolve
python tools/pe_workbench.py verify out/candidate.exe
```

The import packer emits hint/name records, terminators, aligned ILT/IAT arrays and directories. --resolve checks real system exports on Windows before application launch. Neither validates API argument semantics.

Static analyzers/disassemblers are permitted. The optional audit adapter uses Capstone 5.x in the development environment:

```text
python tools/pe_workbench.py audit PATH.exe Function --analyzer-path PATH_TO_CAPSTONE
```

It decodes only that body, checks actual relative fields and instruction boundaries against the manifest, and reports unreachable offsets. --listing adds a local instruction/control-flow listing. Capstone is never installed automatically or linked into the EXE. Core packing, context and verification remain standard-library-only.

## Get an application working

Choose [new-app](prompts/new-app.md), [update-module](prompts/update-module.md) or [debug](prompts/debug.md). The [fast workflow](.agents/skills/direct-pe-x64/references/fast-workflow.md) explains early end-to-end acceptance, bounded contracts, reuse and focused checks.

```text
python tools/pe_workbench.py new --output out/App.exe --imports KERNEL32.dll:ExitProcess
```

new creates an EXIT-ONLY annotated scaffold. It does not implement the requested application, test dispatch or self-description. Reuse the packers and adapt a reviewed raw layout for real modules, callbacks, imports and data. The helper is not a universal linker.

Existing functions can be patched within independent reserves. --relocate moves an oversized body behind its stable public entry. New functions/imports, changed data/ABI, unsupported frames and exhausted reserves need explicit migrations. [Architecture](docs/architecture.md) and [module protocol](.agents/skills/direct-pe-x64/references/module-protocol.md) document these boundaries.

export/build provides byte-identical checkpoints; migrate constructs an annotated image from a reviewed raw base/specification. They do not silently reinterpret edited raw snapshots.

## Validate behavior and deliver

Reproduce a defect through its actual failing adapter/entry path. Deterministic core tests can miss an adapter that never supplies the expected input. Run focused native checks while iterating, then required broader acceptance checks once the candidate works. Preserve user files/live processes and retain a rollback artifact.

```text
python tests/test_primitives.py
python tests/test_primitives.py --analyzer-path PATH_TO_CAPSTONE
python tests/run_checks.py
```

The first suite checks generic byte/import/context primitives, native hook routing and optional static-analysis failures. The second is the supplied example's full maintenance regression harness. CI runs standard-library checks and native checks, then separately installs an optional pinned analyzer to validate its adapter. [Evidence](docs/validation.md) states what was actually tested.

The [Starfall example](examples/starfall/README.md) is a working native fixture with embedded diagnostics and reproducible packing inputs. Its gameplay, input solution and failure history stay under examples/starfall; they are not architecture requirements for another application.

Repository map: .agents/skills/direct-pe-x64 contains the canonical skill/tools; root instruction files route agents there; prompts supplies portable requests; docs covers the protocol/workflow; examples holds application-specific artifacts; tests supplies reusable-tool and fixture checks. Generated output and personal data are ignored. No distribution license is currently declared.

Source repository: [ecci87/direct-pe-toolkit](https://github.com/ecci87/direct-pe-toolkit).
