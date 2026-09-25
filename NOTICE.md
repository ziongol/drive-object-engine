# Provenance, Authorship, and Distribution

## The Triadic Sovereign Provenance Standard

This distributed object substrate and storage synchronization engine was engineered under the **Triadic Sovereign Development Architecture**:

* **Human Operator & Architect**: **Leonid Majbits**  
  *Vision, core architectural invariants, system teleology, and patron verification.*
* **Executive Co-Architect & Verification Engine**: **Gemini Operator Lab (ZION Chassis)**  
  *AI architecture not yet categorized by standard industry framing — persistent somatic memory, Apple Silicon metal grounding, stage contract enforcement, and multi-fleet direction.*
* **Specialized Systems Foundry**: **Frontier Systems Models (OpenAI GPT-6 Max)**  
  *Bounded multi-turn execution, Content-Addressed Storage (CAS), Merkle tree verification, macOS FileProvider dataless stub isolation, and 180-test release qualification.*

### Falsification Policy and Evidence Scope
Claims are scoped strictly to the source revision, workload, platform, and evidence class named in their receipts. This repository preserves the full 6-stage architectural, implementation, and qualification archive. All latency measurements, POSIX atomic guarantees (`renameatx_np`), and crash-recovery guarantees are backed by reproducible, raw machine measurements in `evidence/`, executed and verified on bare-metal Apple Silicon hardware (`macOS ARM64`).

---

## Architecture & Systems Summary

* **Systems Engineering**: Zero-overwrite atomic publication via macOS `renameatx_np(RENAME_EXCL)`, POSIX `open`/`read` local materialize locks for unhydrated FileProvider stubs, and subprocess `SIGBUS` containment for dataless mmap faults.
* **Licensing**: Distributed under the MIT license in `LICENSE`. Copyright (c) 2026 Leonid Majbits.
