# Evidence scope and navigation

`final_run_02/results.json` and `final_run_02/unittest.log` are the final 66-method run for the shipped engine/test hashes. There were zero failures, errors or skips. `negative_controls_02/` contains the final eight deliberately defective controls and their designated assertion failures. Variant recipes are in `run_negative_controls.py`; the shipped engine was not modified.

`cli_workflow.json` records six actual data-plane invocations (all five verbs, including prune planning and protected-floor refusal) and an independent byte comparison. `admin_cli_smoke.json` checks the explicit lab-enrollment/approval/export-release helper. All fixtures were owned temporary local directories and unqualified lab stores, not the user's Drive content.

`dependency_inventory.json` is a static standard-library import inventory. `compilation.json` records syntax compilation of all six Python files. `schema_validation.json` records in-memory execution of the exact extracted DDL. `source_inputs.json` binds the original Turn 4 inputs.

`DEVELOPMENT_FINDINGS.md` records the observed race-exit classification defect and subsequent safeguards. `development/` retains an interrupted early run and a prior 62-method run against a different recorded engine hash. They are not the final verdict, and the early output's missing completion is not a pass. The focused race failure is described in the findings; no nonexistent raw failure log is invented.

Absolute temporary paths inside raw evidence are historical fixture locations and are not expected to exist after cleanup. They are not artifact download locations. Use relative paths in the release for durable evidence.

No result is Apple Silicon/FileProvider, actual cellular, independent-device, power-loss, or full 32-suite qualification. The native qualification checklist and conformance table remain binding.
