# Toolkit validation evidence

Validated locally on 2026-10-04 on Windows 10 x64. Core packing/retrieval uses Python's standard library; optional static analysis uses Capstone 5.0.7 only in the development environment.

[tool-validation.json](tool-validation.json) records source hashes, commands, fixture measurements and test counts. The helper suite passed 31 tests with the analyzer enabled: 26 core/frontend cases and five optional audit cases. New coverage includes concise/legacy reading, deterministic compaction, body/address preservation, overview/call filtering, named extraction, data RVAs versus virtual storage, output budgets, technical-record corruption/stale revisions, exact metadata headroom, fixed-frame field rebasing and direct byte editing.

The direct-edit regression modifies a real EXE using ordinary file writes. get --raw reports its stale hash. sync rejects stale field declarations, accepts an accurate updated manifest without rewriting code, and the synchronized Windows process returns the expected changed exit value, 42. This tests the advertised optional-helper workflow through native execution.

The supplied fixture passed all 37 maintenance checks; [validation.json](validation.json) lists results and its SHA-256. Its native modes passed 184 unit assertions and 16 real-console assertions over 400 frames. The maintenance checks exercise managed patch isolation, stale/ABI rejection, two relocations, success/failure status, corruption detection, native descriptions, Unicode/spaced paths and byte-identical migration/checkpoints.

Compaction preserved every function/public RVA and all code/data section bytes. Readable descriptions shrank from 418361 to 36184 bytes, while the EXE shrank from 878592 to 235520 bytes. The metadata section is 143360 bytes, including its index, independent reserves and compressed mechanical records.

The entire overview is 9101 bytes. A selected 77-byte function with its concise description/code occupies 1026 bytes of output; contracts and edit records are omitted until requested. These are byte measurements, not token counts or a source/binary speed benchmark.

All 45 fixture function bodies passed the optional instruction audit: 3321 instructions and 1872 relative fields. Static checks cannot establish intended semantics, register preservation or pointer safety. Application behavior/failure history stays in [example evidence](../examples/starfall/validation.md).

Successful repository tests remove their process-owned temporary workspaces and retain compact out/evidence reports. Failed runs retain their workspace for diagnosis. Historical generated candidates are not canonical reproduction inputs.

Skill frontmatter validation passed. Every supported agent client was not executed locally. [The previous Windows CI](https://github.com/ecci87/direct-pe-toolkit/actions/runs/37219305402) validated the prior revision; the evidence above is the current local run.
