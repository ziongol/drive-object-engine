# Turn 6 native qualification boundaries

## Reported upstream result

The user reported a Darwin ARM64 run of 54 tests / 16 suites in 47.085 seconds, 54 PASS, zero failures/errors/skips, Python 3.14.7 and SQLite 3.53.4; native `renameatx_np(RENAME_EXCL)` and pip-free primitives were also reported. The connected Drive archive contains a 54-test source with a different schema from the earlier 66-test chat artifact. That exact original source is preserved here. The raw `apple_silicon_results.json` was not retrieved, so no source-hash binding of the actual Mac run is asserted. `UPSTREAM_APPLE_SILICON_ATTESTATION.json` preserves the distinction.

## New positive capabilities requiring this exact build on Apple Silicon

Run `run_release_validation.py` against an immutable copy with the intended interpreter. Retain its complete results, each raw log, runtime/OS build and checksums. In particular, execute the **Apple Security.framework** key creation/export/reimport/sign/public-verify/tamper tests; the Linux OpenSSL backend is not its qualification. Confirm file and directory no-clobber on the actual provider volume, not only private APFS.

For live FileProvider: use a disposable, independently backed ordinary blob with known bytes in the enrolled domain. Record actual flag/read behavior, pause/offline and restore observations, worker isolation and destination hashes. The supplied mocked dataless flag and injected EIO/SIGBUS tests do not replace this observation. Never truncate or evict a real user model to obtain a fault. The real mmap-truncation test here uses a fresh owned temporary file in its own child process.

For actual multi-device coverage, use two genuinely independent producers and a declared ingress into one Mac authority. Reverse delivery/request orders in separate trials. Retain each producer's root and source identity, the authority Q/A records, conflicts and exact signed receipts. Two local processes are a concurrency test, not two-device synchronization evidence.

For cellular recovery, preserve stable operation identity and private source across a controlled link interruption. Restore a second dependency later and measure recovery after the last necessary dependency. No local write or signature is a remote upload witness. The native mount engine cannot cancel Drive's preexisting network backlog.

## Qualification decision

Signing must work independently of granting a production label. A successful historical signature preserves the old candidate label. A separately reviewed current-build record is required before qualified activation. Positive activation in unit tests is `FIXTURE_ONLY`, not production evidence.

No power-loss experiment has been performed. SIGKILL, process restart and SQLite settings are narrower evidence. The package does not silently install a production qualification record or overwrite your configuration.

## Inherited source note

The unchanged 54-test source emits Python ResourceWarnings about a connection created during its enrollment helper. Warnings are retained in raw logs, not suppressed into a zero-warning claim. Its source is deliberately not patched and falsely presented as the already tested Mac build. New receipt connections use explicit closing contexts. A subsequent reviewed core-source patch would require a new source identity and reenrollment review.
