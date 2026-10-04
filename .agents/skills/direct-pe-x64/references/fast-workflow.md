# Fast direct-byte workflow

## A new application

Define the smallest observable acceptance case: what reaches the process/module, what state changes, what is returned/written, and how failure is reported. Choose the required host contract before encoding entry/callback bytes. A normal process exit does not validate a service-manager callback, protocol adapter or file transformation.

Reuse the raw-byte/import packers and known-good byte fragments under documented ABIs. Verify imported export names early with imports --resolve on Windows. Get one real input-to-output operation working, then add behavior in bounded function slots. Do not copy a sample application's state layout or event loop into an unrelated application.

Keep core operations and platform adapters distinct. New interfaces should state pointer bounds, field types/units, ownership, mutations, errors and register arguments/results. A versioned context header helps when modules share evolving state; do not impose one giant global context. Reserve realistic headroom per module and measure it before growth.

Implement native test dispatch and diagnostics appropriate to the application. --test, --smoke and --describe are useful conventions, not a requirement for an interactive console or installation of a live service. A separate test/diagnostic entry path may exercise the same function slots in a safe host. Document which modes actually exist.

## An existing application

1. Read the directory once with inspect. Obtain context EXE MODULE, including direct contracts; use --include NAME for a necessary caller/callee document.
2. Decide the change class before encoding: ordinary patch, slot relocation, or explicit migration. Preserve existing working platform adapters during unrelated core changes.
3. State one observable regression, encode the smallest bounded change and let tools rebase named fields/labels. Write a new candidate.
4. Run structural verification and the focused regression. Use optional static audit when control flow, relative fields or instruction boundaries changed.
5. Once that path works, run the required broader native/integration checks, review diff and promote the verified artifact.

Use patch-template for revision hashes and exact capacities. Relocate only when an existing body outgrows its slot. New functions, imports, data/ABI changes, unsupported stack frames or exhausted reserves require a documented migration. Separate the structural change from behavioral diagnosis; do not redesign the entire application to fix one path.

The helper is a packer/maintainer, not a general linker. A migration may still require adapting the raw layout. Reuse the packing primitives rather than rewriting import terminators, alignment and displacement arithmetic.

## A small edit packet

Keep the request, target document/body, direct contracts, expected/actual reproduction, current revision and relevant validation commands together. Add dependencies only when the target's ABI or observed failure requires them. Preserve module-local labels, fixups and external symbol names; callers use public entries.

context defaults to a 32768-byte compact JSON budget. --no-contracts can omit automatic contract expansion; --include adds explicitly selected documents. Oversized packets fail without silently dropping essential fields. Increase --max-bytes deliberately or inspect a dependency separately. Its context_utf8_bytes is exact UTF-8 size, not a token estimate. Included callees carry documents only; inspect a callee with --bytes when its body is needed.

Avoid exporting every section or reading large raw hex/map files into model context for a local edit. Whole-file verification, hashes, reverse-caller scans and checkpoints can run outside model context. The patch report finds declared callers; context does not scan every body or invent an index that is absent.

## Reuse and evidence

Retain verified adapters/diagnostic byte fragments with argument/result contracts, fixup manifests and tests. Add a reusable fragment when it removes demonstrated repetition; do not build a speculative framework first. Scripts may compose explicitly supplied byte blocks but must not compile application logic or select instruction encodings from a high-level program.

Run fast failing-path checks during iteration. Do not repeat the full suite after every documentation edit or unchanged build. Broaden checks after a new dependency, ABI/layout change, failure or unresolved concern. Preserve failed evidence for diagnosis and record successful candidate commands/hashes.

Machine code is compact on disk, but hex expands it and loses semantic names. Indexed contracts and bounded retrieval make iterative context small. Keep documentation concise and local; padded code/document reserves can dominate file size. Measure actual context, read bytes and used/reserved bytes before claiming a token or speed improvement.
