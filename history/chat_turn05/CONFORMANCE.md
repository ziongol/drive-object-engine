# Conformance and release boundaries

This is a functional implementation candidate, not a claim that every Turn 4 production contract is implemented and qualified. No passing selected test may erase these distinctions.

## Explicit latest-instruction changes

| Change | Implementation |
|---|---|
| 4 MiB `put` | Existing `fixed-4m-v1` writer profile is now the default; both fixed readers remain supported |
| `get <root_hash>` | R is exactly the submission manifest digest; one logical artifact is required; H is not guessed as another namespace |
| `--max-size-gb` | Decimal GB; old spelling rejected |
| Read-only `verify` | No persistent authority/pin mutation; fresh observed-closure diagnostic, not a retained qualified receipt |
| Interface versioning | CAS stays `gdoe-cas/1`; local CLI/worker envelopes are explicitly v2 |

## Implemented core

Strict typed/canonical CAS nodes; short-read-aware splitting; empty files/datasets with independent policy; full ordered reconstruction and destination readback; exact source/destination lengths; no-follow descriptor traversal; bounded process acquisition; actual native no-clobber calls; immutable-operation binding; private snapshot consumption; stable local authority guard; request and decision sequences; one acceptance per K excluding epoch; approval/fence checks; exact stored receipts; transactional acceptance/pins/receipt outbox; retained exports; deterministic private retirement; explicit missing-authority/recovery hold; bounded dispatch count; and separate unqualified lab evidence.

Task/root enrollment and approval are administrative acts, not values trusted from a producer manifest. The implementation protects against cooperative faults and hostile transport content, not arbitrary same-privilege changes to the local trusted program/database.

## Material differences or incomplete parts of the full freeze

| Area | What this candidate actually does | Required before full conformance |
|---|---|---|
| Private/global physical deduplication | Exact reuse within a self-contained candidate; independently retained submission generations can contain duplicate blocks | A protected cross-generation block index, byte-comparison/reuse and complete lifecycle protocol |
| Shared cloud pool | `store-pool-v1` fails explicitly; no partial-intake promotion or automatic cloud GC | Separate steward import implementation and its qualification |
| Disposable metadata DB | Authoritative snapshot/read index is in `state.sqlite3`; there is no separate `cache.sqlite3` | Rebuildable hint-cache implementation and loss tests, without moving pins out of authority |
| Capacity reservations | Per-write observed free-space reserve and file/task/member limits; unresolved generations stay pinned | Atomic global reservation ledger, pending-source quota, full reconstruction/export reservation and AT-27 fault campaign |
| Retry scheduler | Eight persisted worker dispatches per conservative continuous-clock window; manual replay; no automatic jitter loop | Frozen active-time accounting, persisted equal jitter, next-eligibility policy and complete disconnect scheduler |
| Worker scheduling/profile | Two inherited acquisition slots, one publication slot; unclosed children keep their slots and operation guard; whole-job deadlines | Separate private-validation slot, detailed J/phase history, per-block deadlines, complete IPC and unreaped-process qualification |
| Worker wire | Bounded v2 fixed-function JSON arguments, not v1 authority binding IDs | Versioned adapter or exact approved replacement for the full worker envelope |
| CLI status envelope | Bounded `gdoe-cli/2` result with goals, codes, qualification fields and command results | Complete migration map for every v1 status/retry/evidence field expected by the existing lab caller |
| Verification receipts | Read-only verify is diagnostic. Retained capture creates exact strong-schema receipts only after external qualification; lab receipts have different kinds | All 32 mandatory target suites and independent qualification; no self-upgrade from this subset |
| Complex/multi-artifact workloads | Internal/external bounded datasets supported, public put/get are single-artifact; IPC report limits may narrow configured maxima | Full large-dataset/page-amplification and capacity-qualified integration tests |
| Orphan recovery | Complete closed put capture can be recovered; uncertain/incomplete construction is retained, not silently recaptured or deleted | Complete owner-reconciliation, abort and administrative orphan-retirement workflow |
| Receipt exporter | Exact immutable receipt outbox and bounded explicit local publishing | Full durable transport-operation/retry-window reconciliation and all outbox fault cuts |
| Strong durability/host control | Local fsync/fullfsync calls and process isolation; fullfsync PRAGMA is requested but lacks separate readback; no power-loss claim or hard kernel-cancellation claim | Actual platform, volume, sleep/reboot, pressure, power-loss and responsiveness campaigns as applicable |
| Native provider controls and Linux ingress | No eviction, cloning, native Workspace export, REST, remote witness or Linux Google mount is presumed | Separately approved adapters; absence cannot invoke a forbidden fallback |

These omissions are not implemented by empty stubs returning success. Unsupported storage profiles and unqualified strong operations refuse. Some narrower implemented policies intentionally hold work rather than provide the full freeze's availability behavior. The report must not describe this as a completely matching production implementation.

## Qualification control

The administrative helper creates only `LAB_CANDIDATE` stores. `PRODUCTION` mode requires an independently approved qualification record matching source bytes, configuration and runtime; the code does not run a test and declare itself qualified. The selected harness does not produce that record. Installing an approval record is an explicit trusted administrative act, not authentication of arbitrary producer JSON.

Full production admission also requires resolving the material conformance differences above. A manually asserted all-PASS record cannot make omitted implementation work real. Do not install one merely to bypass the gate.
