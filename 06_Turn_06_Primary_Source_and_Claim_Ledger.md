# Turn 6 — Primary-source and claim ledger

**Date:** 23 September 2026. **Scope:** implementation support and evidence attribution, not target-machine certification.

## Project sources

The supplied Turn 4 specification/32-suite matrix and Turn 3 amendments define the architectural invariants. The latest user instruction expressly adds signing and a `./lab drive` wrapper. A new versioned signed envelope is therefore introduced rather than placing unrecognized fields inside frozen unsigned receipts.

Two actual Turn 5 source lineages were inspected. The 66-test conversation engine was loaded from its mounted attachment and its hash checked. A separate 54-test source was fetched from Drive file `1s4MJCIyD1h_b34BLoOdMhD0oX68geqO8` in the verified project folder. `SOURCE_LINEAGES.json` and retained source files bind both. They use incompatible authority schemas and configuration profiles; no equivalence or silent conversion is claimed.

The user-reported 54/54 Apple Silicon result is recorded in `UPSTREAM_APPLE_SILICON_ATTESTATION.json`. The named raw Apple result was not retrieved from the searched connected Drive/Library records. The source count fits the 54-test lineage but does not substitute for a raw test-to-build digest binding. New Turn 6 execution results are separate.

## External primary references

| ID | Primary source | Narrow supported fact | Limit |
|---|---|---|---|
| S01 | Apple, SecKeyCreateSignature — https://developer.apple.com/documentation/security/seckeycreatesignature(_:_:_:_:) | Creates a private-key signature using the requested algorithm, verified with the matching public key | API documentation/indexed official text, not an execution of this ctypes adapter on the user's Mac |
| S02 | Apple, SecKeyCopyExternalRepresentation — https://developer.apple.com/documentation/security/seckeycopyexternalrepresentation(_:_:) | EC exported public key is 04/X/Y; private representation appends scalar K; nonexportable keys can refuse | Software key export used here; no Secure Enclave or nonexportable-key claim |
| S03 | Apple, Storing Keys as Data — https://developer.apple.com/documentation/security/storing-keys-as-data | Key export/import and importance of establishing trust in received public keys and keeping private keys secret | A public key accompanying an untrusted receipt is not automatically trusted |
| S04 | OpenSSL, EVP_DigestSignInit — https://docs.openssl.org/3.0/man3/EVP_DigestSignInit/ | Native signature generation through EVP APIs | Linux qualification backend, not proof of Apple's backend behavior |
| S05 | OpenSSL, EVP_DigestVerifyInit — https://docs.openssl.org/3.0/man3/EVP_DigestVerifyInit/ | Native verification with digest/signature APIs | Correct cryptographic verification does not certify an application's task policy |
| S06 | OpenSSL, EVP_PKEY_keygen — https://docs.openssl.org/3.5/man3/EVP_PKEY_keygen/ | EVP_PKEY_Q_keygen EC requires the curve-name argument | Named P-256 generated through native code, not custom Python ECC |
| S07 | Python, signal — https://docs.python.org/3/library/signal.html | Python handlers are deferred; synchronous native faults can repeat after returning to the instruction | Fault tests use child containment, not a host-side repair handler |
| S08 | Python, subprocess — https://docs.python.org/3/library/subprocess.html | Child execution, signal status and timeout facilities | No hard real-time kernel-cancellation claim |
| S09 | SQLite, Transaction — https://www.sqlite.org/lang_transaction.html | Serialized local write transactions and commit semantics | Does not create a transaction spanning the cloud, private files and separate host databases |
| S10 | Python, sqlite3 — https://docs.python.org/3/library/sqlite3.html | Connection context manager transaction behavior is distinct from explicit connection close | The preserved native enrollment helper's ResourceWarnings are retained and not hidden |

Apple's direct HTML pages were JavaScript-only in this review; official indexed API content supplied the narrow source text. No unsupported third-party claim was used to infer actual FileProvider entitlements. No quota, upload-success badge, undocumented provider command, or account-specific server fact is needed by the new runtime.

## Evidence classifications

EXECUTED_LOCAL refers only to the exact code hashes, runtime and results in the final local validation. USER_REPORTED refers to the reported earlier Mac run. IMPLEMENTED_NOT_NATIVE_QUALIFIED applies to the new Apple Security ctypes backend until its own target run. FIXTURE_ONLY activation tests exercise its positive transaction path without enrolling production qualification. INJECTED_FILEPROVIDER_MODEL means real owned file reads with modeled availability/faults. ACTUAL_PRIVATE_MMAP_TRUNCATION is an OS-generated backing-file fault in an isolated temporary-file child, not a Google eviction event.

SHA-256 manifests describe exact artifact bytes. ECDSA authenticates the receipt payload under an independently enrolled key. Neither certifies semantic research quality, global synchronization, lossless restore of all erased authority history, or immunity from same-user compromise.
