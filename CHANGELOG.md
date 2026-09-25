# Changelog

All notable changes to `drive-object-engine` are documented in this file.

## [1.0.1] - 2026-09-25

### Red-Team Adversarial Hardening
Hardened distributed Content-Addressed Storage (CAS) and native FileProvider isolation against adversarial fault injection, stress testing, and boundary edge cases on Apple Silicon bare-metal hardware (31/32 checks PASS):

- **Stream Short Reads**: Hardened payload streaming and ingest pipelines against partial and truncated reads from slow or partitioned disk streams.
- **Flock Inheritance Across Parent Termination**: Ensured file locks (`fcntl.flock`) and operation guard file descriptors are properly duplicated (`os.dup`) and passed to child worker supervisor processes (`pass_fds`), preventing lock races or dangling state upon parent worker termination.
- **Reader Pin Cleanups on Abort**: Guaranteed explicit transactional removal of reader pins (`DELETE FROM pins WHERE owner=? AND kind='READER'`) when operations fail or are aborted, eliminating orphaned pins.
- **Reservation Cleanup on Failure**: Ensured storage capacity reservations and uncommitted generation directories are proactively purged and rolled back upon acquisition errors.
- **Outbox Retry Backoff**: Introduced `HOLD_RETRY` state for receipt outbox dispatch to prevent retry storms when attempts exceed max thresholds, maintaining monotonic sequence ordering.

---

## [1.0.0] - 2026-09-25

### Initial Release
- Machine-native distributed CAS and FileProvider isolation engine for Google Drive on Apple Silicon (`macOS ARM64`).
- Content-addressed Merkle blob tree, atomic transactional registry (SQLite), and verifiable signed receipts.
- Triadic Sovereign Authorship & Provenance Standard compliance.
