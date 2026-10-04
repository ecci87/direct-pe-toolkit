# Debug a direct-byte executable efficiently

Reproduce the reported failure through its actual entry/adapter path in an isolated environment. Record the smallest triggering input, observed result, expected result, command, exit status/log and artifact revision. Do not expand architecture before locating the failing boundary.

## Choose the failing layer

| Evidence | Inspect first |
| --- | --- |
| Image never reaches entry | PE headers, sections, import names/thunks, relocation and loader status |
| Entry runs; operation faults | Selected body, pointer bounds, stack arguments, register widths and lifetimes |
| Core tests pass; real operation fails | Actual adapter, callback/host contract, resource types and result/error handling |
| One path is skipped or stale | Branch targets, named insertion policy, initialization and state transitions |
| Patch corrupts a working path | Revision hashes, ABI/data changes, field/end rebasing and affected callers |

Loader status is a clue, not a unique diagnosis. Use imports --resolve when exports changed. Use context for the failing function and only necessary contracts/dependencies; a whole image dump is rarely the shortest route to an answer.

verify checks recorded structural invariants. Optional audit checks actual decoded instructions against references and boundaries. Neither proves intended behavior. If uncertain, examine the selected body with an allowed static analyzer/debugger; do not substitute a compiler/assembler implementation.

## Test the path that failed

A prewritten context or simulated request may bypass the faulty adapter. Test both the deterministic operation and the real path that reaches it. Use a host/resource of the correct type, check API return values, and distinguish owned from borrowed resources. Redirection, callbacks, encoding, partial I/O and host scheduling may differ from the harness's assumptions.

Use bounded deterministic timestamps/data where units matter. For adapter timing, compare actual observed time/results rather than inferring them from loop count. For reused mutable buffers, cover failure followed by a valid operation and reinitialize output fields according to their contract.

Native assertions should call production slots, report expected and actual values with units, and fail with nonzero status. Establish that an intentionally incorrect assertion really fails. A scaffold exit or a logger that always reports success is not acceptance evidence.

A focused diagnostic mode or bounded trace can log a failing boundary's input, selected path, output/error and state revision. Add only what helps reproduce the observed defect; diagnostic code must not change production semantics. Applications without a console can write an appropriate log or return structured results.

## Finish one candidate

Fix bytes and metadata together, review the targeted diff, verify and rerun the failing regression. Broaden to relevant callers/adapters and required acceptance checks once the path works. Repeat passed checks only when new edits, failures or unresolved concerns justify them.

Keep failed logs for diagnosis and successful evidence associated with the candidate hash. Preserve user state and a running image. Deliver a verified new artifact or state the concrete unresolved failure; do not claim a metadata hash proves native semantics.
