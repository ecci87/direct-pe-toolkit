Read AGENTS.md, the direct-pe-x64 skill and its debugging reference.

Investigate [EXE path] for [minimal reproduction, observed result, expected result]. Reproduce through the actual failing entry/adapter path using an isolated fixture. Distinguish loader, core operation, platform/host adapter and reference-layout failures before editing.

Load only the failing function and necessary contracts/dependencies. Use import resolution and optional static analysis where relevant. Add a meaningful regression that reaches the production path; do not treat simulated state, a metadata pass or an exit-only scaffold as proof.

Make the smallest explicit-byte fix, preserving ABI/public entries unless a deliberate migration is necessary. Verify and run the focused regression, then required broader checks. Deliver the cause, corrected artifact/hash and actual evidence.
