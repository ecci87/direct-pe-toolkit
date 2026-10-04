# Agent instruction discovery

One canonical workflow lives in [AGENTS.md](../AGENTS.md). A portable [skill](../.agents/skills/direct-pe-x64/SKILL.md) supplies task-specific references and the standard-library workbench. The root instruction files route agents to that content instead of maintaining divergent procedures.

| Environment | Repository entry | How to use |
| --- | --- | --- |
| Codex CLI / app | AGENTS.md; .agents/skills/direct-pe-x64/SKILL.md | Open this repository as the task workspace; invoke $direct-pe-x64 or ask for direct PE work. |
| GitHub Copilot CLI | AGENTS.md and .github/copilot-instructions.md | Start in this repository. Use /instructions to inspect loaded instructions; restart the session after changes. |
| VS Code Copilot | .github/copilot-instructions.md; .github/instructions/direct-pe.instructions.md | Open the repository folder and use agent/chat mode. The path-scoped file routes binary changes to the shared workflow. |
| Claude Code / Claude agent in VS Code | CLAUDE.md importing @AGENTS.md | Start in this folder. /memory shows loaded memory; explicitly ask it to read the linked skill. |
| Other Claude-compatible or open agent clients | AGENTS.md + explicit skill path | If the client does not auto-discover these files, paste a prompt from prompts/ and include their paths. |

These are documented discovery conventions, not a claim that every CLI or extension was executed in this session. The repository does not change global settings, require a provider SDK or call an AI service from the workbench. “Open Claude” clients vary; the explicit-read fallback avoids assuming a vendor-specific discovery rule.

Codex discovers the repository-local .agents skill. For a discoverable personal skill, copy that skill folder to the client's supported skills directory; the current desktop user's Codex copy can live under ~/.codex/skills. No copies of toolkit scripts outside this folder are required.

Claude Code supports project skills under .claude/skills. If native Claude skill discovery is desired, copy the folder there; CLAUDE.md already makes it usable through an explicit read without duplication. Keep a single maintained source and refresh any installed copies deliberately.

VS Code supports relative Markdown links in instructions. If instruction loading is disabled in local settings, use Chat: Open Customizations to inspect it and enable the appropriate setting yourself. AGENTS support is controlled by chat.useAgentsMdFile; Copilot instruction loading by github.copilot.chat.codeGeneration.useInstructionFiles. Instructions apply to agent/chat work; they are not equivalent to inline suggestion configuration.

Official documentation consulted for the adapters:
- [Codex AGENTS.md configuration](https://learn.chatgpt.com/docs/agent-configuration/agents-md)
- [Codex skills](https://learn.chatgpt.com/docs/build-skills)
- [Copilot CLI custom instructions](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-custom-instructions)
- [VS Code custom instructions](https://code.visualstudio.com/docs/agent-customization/custom-instructions)
- [Claude Code memory and imports](https://code.claude.com/docs/en/memory)
- [Claude Code skills](https://code.claude.com/docs/en/skills)

Discovery behavior was checked against these docs on 2026-10-04. Documentation and client versions may evolve; the explicit-read prompts remain usable independently of automatic discovery.
