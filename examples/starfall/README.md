# Starfall: direct-byte Windows x64 example

Run Starfall.exe on Windows 10 x64. Move @ with arrows or WASD and avoid the falling *. Enter/Space starts, R/Enter/Space restarts after a collision, and Esc quits. Falling/spawning speeds rise with survival time. Starfall.score is written beside the executable.

Native diagnostic modes:
- --describe prints Architecture.
- --describe Move prints the indexed function JSON.
- --describe Data.ScoreRecord prints the versioned storage contract.
- --test runs 51 assertions, logs beside the executable, exits 0 on success or 1 on failure.
- --smoke runs 120 real console frames and five integration assertions.

The fixture contains 29 native function modules and nine architecture/symbol/data documents. The original public entry addresses remain stable; Entry has been extended for self-description. Original globals are documented as typed contracts rather than silently moved.

architecture/Starfall-v1.exe preserves the original raw image. architecture/migration.json contains explicit function bytes, reference manifests, docs and reserved capacities. From the repository root, reconstruct with:

```powershell
python tools/pe_workbench.py migrate examples/starfall/architecture/migration.json --output out/starfall-rebuilt.exe
```

The shared test harness uses isolated copies so developer checks do not overwrite a player's score. See the repository README and embedded Architecture for maintenance commands and finite capacity limits.
