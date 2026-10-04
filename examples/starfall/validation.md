# Validation evidence

On 2026-10-04, the combat/input fixture passed all 37 maintenance checks on Windows 10 x64 (10.0.19045). [validation.json](../../docs/validation.json) records each check and executable SHA-256.

The EXE passed 127 native unit assertions: 51 original assertions, 45 combat regressions and 31 input regressions. Coverage includes exact 4999/5000 ms cooldown boundaries, projectile collisions, meteor geometry/invulnerability, clipping and frame characters/colors. Input checks cover Space's fire bit, rapid press/release pairs, repeated taps, autorepeat suppression, direction reversal, immediate movement, 75 ms held cadence and invalid input handles.

The real-console smoke mode passed 11 assertions. It opens its own console input buffer, queues A/D/Space key-down/up pairs, calls production Keys and Tick, and verifies immediate movement and a fired dot. It then renders 400 frames with held fire and a cross, checks the elapsed-time firing bound and confirms the meteor remains intact. It sends no desktop keystrokes and takes no foreground focus.

The prior combat-only suite passed despite a live Space branch skipping its fire check and short taps being missed by the 75 ms sampling gate. Testing the Windows adapter and production input chain now covers those reported regressions. Redirected stdin may be a pipe even with a new console; the smoke adapter opens CONIN$ explicitly. Frame counts also cannot predict exact elapsed time because sleep can overrun.

Same-slot and relocated bodies passed native tests. Two successive relocations retained the public entry; an intentionally incorrect assertion logged FAIL and returned exit 1. Raw migration and checkpoints reproduced the fixture byte-for-byte. Unicode/spaced paths, stale revisions, ABI rejection, reserve overflow and corruption checks passed.

The skill's original independent exercise and discovery adapters were validated earlier. Individual Copilot, Claude and VS Code clients were not all executed here. The initial GitHub Windows CI [passed for v2](https://github.com/ecci87/direct-pe-toolkit/actions/runs/37210333626); current combat/input evidence is the local Windows run.

These checks cover this fixture and helper profile, not arbitrary future opcode changes or unlimited migrations.
