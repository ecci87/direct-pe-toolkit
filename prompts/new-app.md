Read AGENTS.md and .agents/skills/direct-pe-x64/SKILL.md.

Build this application: [describe the application, inputs, output and acceptance criteria].

Target Windows 10 x64. Implement the application's native behavior directly in explicit machine-code bytes and PE structures, without a compiler, assembler or downloaded static libraries. Packing/fixup scripts are allowed. Choose small documented function modules, bounded versioned data contracts and an explicit context pointer for new APIs. Embed module documentation and implement --describe, deterministic --test with logs and exit 0/1, and a bounded --smoke mode.

Use out/ for candidates and test data. Complete the application beyond the exit-only bootstrap. Verify layout, imports, fixups and unwind records, then run meaningful native tests on Windows x64. Deliver the executable and a reproducible raw-byte generation/checkpoint path, with its SHA-256, test results and real limitations.
