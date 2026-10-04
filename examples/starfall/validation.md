# Validation evidence

On 2026-10-04, the concise pickup fixture passed all 37 maintenance checks on Windows 10 x64 (10.0.19045). [validation.json](../../docs/validation.json) records each check and executable SHA-256.

The EXE passed 184 native unit assertions: the previous 127 movement/state/score/render/combat/input checks and 57 pickup/damage regressions. New coverage includes both upgrades, the 999/1000 ms fast-fire boundary, shortening a pending cooldown without postponing it, repeated pickups, coordinate matching, bounded/alternating spawns, expiration, colors, obstacle concealment, restart and context guards.

Powered projectile tests remove one cell, preserve the four remaining cells, verify collision-safe holes after map rebuild and falling, clear all five cells with five shots, restore a reused meteor slot, and reject hits on empty corners or already removed cells. One dot cannot pierce overlapping meteors or a star beneath armor.

The real-console smoke mode passed 16 assertions. It opens its own CONIN$ input buffer, queues A/D/Space press/release pairs, and calls production Keys/Tick to verify immediate movement and shooting. It also collects F/P through Tick, checks the fast deadline and single-cell damage, restarts, and renders 400 baseline combat frames. It sends no desktop keystrokes or foreground activation.

All 45 function bodies passed the optional Capstone 5.0.7 audit: 3321 instructions and 1872 declared relative fields, without decoder/reference errors. The analyzer is a development tool and adds no runtime dependency. Static decoding does not prove behavior or memory safety.

Compaction reduced the EXE from 878592 to 235520 bytes and readable descriptions from 418361 to 36184 bytes. All code/data section bytes and function/public RVAs are preserved; the final metadata section and PE size fields changed. Native --describe prints the concise JSON without a new runtime decoder.

All v3 public entries remain stable. Keys, InputDecode, InputEvent, ReadKeyEvents and MovementGate machine-code bodies are unchanged. The new bounded 256-byte upgrade context preserves the existing 1152-byte combat/input ABI and the player's score format/file.

Same-slot patches and two successive relocations passed native checks. An intentionally incorrect assertion logged FAIL and returned exit 1. Raw migration, explicit-byte generation and checkpoints reproduce the fixture byte-for-byte. Unicode/spaced paths, stale revisions, ABI rejection, reserve overflow and corruption checks passed.

The previous input fix addressed a live branch bypassing Space and short taps missed by a sampling gate. The current smoke retains that actual adapter coverage. Redirected stdin may be a pipe even with a new console, and frame counts cannot predict exact elapsed time because sleep can overrun.

The skill's discovery adapters were documented and exercised earlier; every supported agent client was not executed here. [The previous Windows CI](https://github.com/ecci87/direct-pe-toolkit/actions/runs/37219305402) validated the tooling/input revision. Pickup evidence above is the current local Windows run.

These checks cover this fixture and the supported helper profile, not arbitrary future bytes or unlimited migrations.
