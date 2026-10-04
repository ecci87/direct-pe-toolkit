# Starfall: direct-byte Windows x64 example

Run Starfall.exe on Windows 10 x64. Move the green ^ with arrows or WASD. A quick tap moves immediately; held movement repeats every 75 ms. Press or hold Space to shoot an upward cyan dot. The first shot is ready, then each shot has a five-second cooldown shown in the HUD.

Yellow * stars disappear after one hit. Red # meteoroids fall as a five-cell cross, three columns wide and three rows tall:

```text
 #
###
 #
```

A shot hitting a meteoroid disappears; the cross remains intact. Its corners are empty and safe. Meteoroids enter every ten fall steps. Falling accelerates over time. Enter/Space starts, R/Enter/Space restarts after death, and Esc quits.

Starfall.score stores the survival-time record beside the EXE. Its 16-byte storage contract is unchanged.

Native diagnostic modes:

- --describe prints Architecture.
- --describe Keys or --describe Data.Combat prints one embedded document.
- --test runs 127 assertions with log output and exit 0/1.
- --smoke checks actual queued A/D/Space taps through production Keys/Tick, then renders 400 combat frames; 11 assertions, log output and exit 0/1.

The image has 40 function modules and ten architecture/symbol/data documents. All v2 public entries remain stable. The new combat/input context is 1152 bytes with a size/version header.

architecture/Starfall-v1.exe and Starfall-v2.exe preserve earlier versions. migration-v2.json is the earlier manifest. build_combat.py emits explicit x64 bytes and the reviewed combat/input migration; combat-base.exe contains expanded read-only storage and new console import records; migration.json describes the current image.

From the repository root:

```powershell
python tools/pe_workbench.py migrate examples/starfall/architecture/migration.json --output out/starfall-rebuilt.exe
python examples/starfall/architecture/build_combat.py --workbench .agents/skills/direct-pe-x64/scripts/pe_workbench.py --source examples/starfall/architecture --directory out/combat-rebuilt
```

Both paths reproduce the current fixture exactly. Tests use isolated score paths and preserve player records.
