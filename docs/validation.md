# Toolkit validation evidence

Validated locally on 2026-10-04 using Windows 10 x64 (10.0.19045) and Python 3.10. The core workbench/helper path uses the standard library. The optional instruction-audit adapter was tested separately with Capstone 5.0.7 in an isolated ignored tool directory.

[tool-validation.json](tool-validation.json) records source hashes, commands and measured context size. The application-neutral primitive suite passed 20 tests, including native include/skip hook routing through process exit status. Coverage includes import terminators/alignment/real export resolution, ambiguous symbols, malformed declarations, capacity failures, exact context-size accounting, selective retrieval, output protection, complete-instruction field ends and atomic label conflict rejection.

Optional analyzer tests prove that mid-instruction branches, undeclared relative fields and wrong instruction-end declarations are rejected, and unreachable instructions are reported. They do not prove application correctness, register preservation or pointer safety.

The existing example passed all 37 maintenance checks after the tooling update. [validation.json](validation.json) records the fixture hash and those checks. This exercises revision/ABI rejection, patch isolation, growth behind stable entries, twice-relocated bodies, native success/failure status, import layout, corruption checks, Unicode/spaced paths and byte-identical checkpoint/raw migration reproduction.

A selected 77-byte function plus its direct contract produced 5666 bytes of compact context JSON while reading 17192 bytes from a 747520-byte fixture. These are byte measurements, not token counts or a source/binary performance comparison.

Application-specific behavior and failure history are documented in [the example evidence](../examples/starfall/validation.md). The sample fixture supplies behavioral coverage; it does not establish that a future service, adapter or processor meets its own acceptance criteria.

Client discovery adapters were documented earlier; every supported agent client was not executed locally. [The earlier Windows CI run](https://github.com/ecci87/direct-pe-toolkit/actions/runs/37210333626) validated the previous fixture. Current local and any subsequent CI evidence should be distinguished by commit/artifact revision.
