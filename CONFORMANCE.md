# Turn 6 capability and conformance register

| Requirement | Implementation status | Evidence boundary |
|---|---|---|
| Signed historical receipts | Implemented for both exact config profiles | Public-key sign/verify/replay/tamper tested on recorded host; new Darwin backend requires target run |
| Durable drain_receipts | Implemented, finite batches, persistent exact envelope, no-clobber output and replay | Local tests; upload/peer receipt NOT_ASSERTED |
| Qualified activation | Implemented separate attestation and explicit enrollment gate | Positive branch is FIXTURE_ONLY here; no automatic production record |
| Historical byte/audit binding | Original acceptance/verification bytes, K/R/Q/A/G and sealed audit event | Native old audit tail is checkpointed at extension observation; not signed at original commit |
| Generation retirement / protected floor | Implemented, unique paths, transaction/trigger pin exclusion, idempotent removal | Local races and protected-floor tests; physical reclaimed SSD bytes not promised |
| Deterministic concurrent candidate arbitration | Existing one-authority brokers retained; bounded adapters supplied | Same-host process tests, not physical two-device transport qualification |
| ./lab drive wrapper | Implemented profile-aware public adapter, sample standalone launcher | No edit of the existing Gemini lab dispatcher was made |
| FileProvider mocked faults | Both profiles have test-only real-read fault adapters | Modeled dataless; injected EIO/SIGBUS; distinct actual private mapped-file truncation |
| No pip dependencies | Only standard-library Python imports and shipped local modules | Native system crypto / no-clobber libraries are explicit dependencies |
| Shared cloud pool / cloud GC | Not enabled | No speculative deduplication or deletion promise |
| Global distributed locks / automatic authority failover | Excluded | One local registry; transport cannot elect authority |
| Full 32-suite live certification | Not granted by this package | Test methods are subcases; actual provider/cellular/two-device/power-loss gates remain separate |
| Receipt retry scheduler | Persistent eight dispatches and finite iteration; explicit new window | Full elapsed-time/equal-jitter receipt scheduler not implemented; existing lab loop owns cadence |
| NATIVE54 existing task/source retry accounting | Original implementation preserved | Contains durable reservation / active-time behavior; not replaced with CHAT66 semantics |
| CHAT66 aggregate reservation and full historical scheduler | Prior gaps remain | Do not transfer NATIVE54 features to this alternate profile by label |

The archive name contains “Production” because that is the requested release artifact name. It is not an independently granted production capability certificate. The meaningful statuses are the exact executed results and current configuration-bound qualification record.
