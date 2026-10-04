---
applyTo: "**/*.exe,**/*.bin,**/*.patch.json,**/migration.json,**/layout.json"
---
For executable and raw PE artifact changes, read [the shared workflow](../../AGENTS.md) and [the direct PE skill](../../.agents/skills/direct-pe-x64/SKILL.md). Inspect only the affected module and contracts. Preserve stable public entries and versioned ABIs, patch a new candidate, review its byte diff, and run structural plus relevant native verification.
