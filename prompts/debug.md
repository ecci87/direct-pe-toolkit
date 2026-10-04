Read AGENTS.md and .agents/skills/direct-pe-x64/SKILL.md, then its debugging reference.

Investigate [executable path] with these symptoms: [reproduction and observed output].

Reproduce in an isolated folder. Distinguish loader failure, native assertion failure, platform integration failure and gameplay behavior. Inspect only the failing module, relevant callers/contracts and recorded references. Use --test/--smoke only if the image actually implements those modes. Add a meaningful regression assertion when the failure warrants it.

Fix explicit bytes and their metadata together, generate a new candidate, check its diff, verify it and rerun the relevant native checks. Report the cause, resulting behavior and tested artifact. Do not overwrite user state.
