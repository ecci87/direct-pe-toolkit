---
applyTo: "**/*.exe,**/*.bin,**/*.patch.json,**/migration.json,**/layout.json"
---
For executable and raw PE artifact changes, read [the shared workflow](../../AGENTS.md) and [the direct PE skill](../../.agents/skills/direct-pe-x64/SKILL.md). Inspect only affected functions/contracts. Direct byte scripts/editors are allowed; the Python helper is optional. Keep embedded descriptions concise, derive bookkeeping mechanically, maintain actual PE/ABI correctness and run relevant structural/native checks.
