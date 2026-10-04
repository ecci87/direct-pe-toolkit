Read AGENTS.md and .agents/skills/direct-pe-x64/SKILL.md.

Update [executable path] so that [requested behavior]. Begin with its compact directory and inspect only the relevant function documents, bytes and data contracts. Identify callers affected by the change.

Create a revision-checked patch for the smallest suitable module. Preserve the public ABI and entry address, update its bytes, local labels, fixups, documentation and tests together, and write a new candidate under out/. If the change needs a different ABI, new imports/functions/data layout or exhausted reserves, perform an explicit documented migration.

Review the byte diff, run structural verification and relevant native tests. Deliver the verified candidate, patch evidence and any material limitation. Preserve existing user files and live applications.
