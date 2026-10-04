# Starfall: direct-byte Windows x64 example

Run Starfall.exe on Windows 10 x64. Move the green ^ with arrows or WASD. Quick taps move immediately; held movement repeats every 75 ms. Press or hold Space to shoot an upward cyan dot. The first shot is ready; normal firing has a five-second cooldown.

Collect falling items by moving onto them:

- Green F enables one shot per second and shortens a pending longer cooldown.
- Magenta P enables powered shots. Each dot removes exactly one # cell from a meteoroid.

Both upgrades last until restart. The HUD shows FAST and POWER status. Pickups alternate F/P every six fall steps, with at most four on the board. Stars and meteor cells can conceal an overlapping pickup.

Yellow * stars disappear after one hit. Red # meteoroids start as a five-cell cross:

```text
 #
###
 #
```

Normal dots are absorbed. A powered dot removes just the cell it hits; remaining cells keep falling, and the gaps are safe. Five successful hits clear an intact cross. Shots do not pierce multiple cells or overlapping objects. Meteoroids enter every ten fall steps, and falling accelerates over time.

Enter/Space starts, R/Enter/Space restarts after death, and Esc quits. Starfall.score stores the survival-time record beside the EXE; its 16-byte storage contract is unchanged.

Native diagnostics:

- --describe prints Architecture.
- --describe PickupCollect or --describe Data.Upgrades prints one embedded document.
- --test runs 184 assertions with log output and exit 0/1.
- --smoke checks actual queued A/D/Space taps, game-loop pickup collection and cell damage, then renders 400 frames; 16 assertions with log output and exit 0/1.

The image has 45 function modules and 11 architecture/symbol/data documents. All v3 public entries stay stable. The existing 1152-byte combat/input layout remains unchanged; the new 256-byte Data.Upgrades context stores four pickups, upgrade flags and eight damage masks. Each function and contract remains independently indexed.

architecture/Starfall-v1.exe and Starfall-v2.exe preserve earlier fixtures; Git retains the prior current image. build_combat.py and migration-v3.json describe the earlier combat/input migration. build_pickups.py layers explicit new x64 bytes on the archived v3 manifest/raw base. pickup-base.exe and migration.json are the current reproduction inputs.

From the repository root:

```powershell
python tools/pe_workbench.py migrate examples/starfall/architecture/migration.json --output out/starfall-rebuilt.exe
python examples/starfall/architecture/build_pickups.py --workbench .agents/skills/direct-pe-x64/scripts/pe_workbench.py --source examples/starfall/architecture --directory out/pickups-rebuilt
```

The fixture uses concise readable descriptions with separate compressed edit records: 36184 description bytes in a 235520-byte EXE. Every function body and public address is unchanged by compaction. Direct EXE editing remains allowed; the Python frontend is optional.

Both paths reproduce the current fixture exactly. Scripts pack explicitly supplied opcodes and structures; no compiler, assembler or downloaded runtime code is used. Tests use isolated score paths and preserve player records.
