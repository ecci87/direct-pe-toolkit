# Validation evidence

On 2026-10-04, the packaged harness passed all 37 maintenance checks on Windows 10 x64 (10.0.19045), Python 3.10. [validation.json](validation.json) records each check and the tested executable SHA-256.

The reference EXE passed 51 native unit assertions and five real-console assertions over 120 smoke frames. Same-slot patches and relocated bodies passed the native tests; relocation was exercised twice. The deliberately incorrect native assertion produced FAIL output and exit 1. The harness also reproduced the annotated binary exactly from both its raw migration and exported checkpoint.

Selective Move inspection reads 11,303 bytes of the 462,848-byte image. Module-only patch checks verified stable public addresses and unchanged other function implementation hashes. Stale revisions, incompatible ABI edits, unapproved overflow and code corruption were rejected.

The skill passed the skill-creator frontmatter validator, and local Markdown reference links resolved. An independent agent completed a documentation-only Move update: every executable section, public entry and ABI digest stayed unchanged; native description, all 51 unit assertions and five smoke assertions passed. Its initial document-capacity rejection led to adding visible capacity/headroom fields and overflow-cleanup checks. Client instruction adapters follow their official documentation; the individual Copilot, Claude and VS Code clients were not all executed here. The initial GitHub Windows CI run also [passed](https://github.com/ecci87/direct-pe-toolkit/actions/runs/37210333626) for commit 92c8354d6cb25340927222128b32b682d4f9b2f6.

The evidence covers this fixture and helper profile. It does not establish correctness of arbitrary future opcode changes, behavior under every Windows configuration or an unlimited migration system.
