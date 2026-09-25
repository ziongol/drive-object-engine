# Apple Silicon and FileProvider qualification still required

The supplied recorded run is Linux x86-64. It establishes only the observations in its evidence files. This checklist is not a PASS record or an executable substitute for the full Turn 4 matrix.

## First target run

Record the exact Apple Silicon model, macOS build, Python executable/version/build, SQLite version/effective pragmas, Drive version, FileProvider mode, private volume and provider volume, and explicit root enrollment. Run `python3.13 run_validation.py evidence/my-mac-run-001` from the extracted bundle. Retain failures and the source hashes. Private-filesystem success does not qualify the actual Drive-managed volume.

## Minimum provider-specific evidence

Use an explicitly authorized, disposable provider test folder and an independent private reference copy. Keep production tasks and the only copy of any useful data out of fault tests.

1. Verify the real `renameatx_np` ABI, flag values, EEXIST behavior for files and directories, occupied-name race, and same-volume requirements on the private and **provider-managed** volumes separately. A typed unsupported outcome is not positive publication qualification.
2. Establish an actual ordinary-blob SF_DATALESS observation where possible. Interrupt only the approved test connection or pause through supported operator controls. Read through the engine and record timeout/refusal versus successful acquisition. Do not label injected EIO, a fake flag or a normal local file as an observed cloud stub.
3. Confirm every provider stat/open/list/read/flush/rename stays in the child, and sample the host/controller heartbeat. The frozen 20 Hz / 60-second / 500 ms-gap obligation is not implemented by the selected unit suite.
4. Exercise the native continuous clock, timebase and boot-session ID across actual sleep and a controlled restart. Preserve reader pins and old decisions. A fresh credential or reboot must not revive business approval.
5. Use an approved real cellular/hotspot path. Record the last required dependency returning, not merely link-up. Keep the same O and source generation; distinguish local publication from a truly independent receiver's observation. The core cannot cancel Drive Desktop's preexisting traffic.
6. Exercise an actual independent device with a separately identified ingress. Two folders or two processes on one machine do not qualify distributed delivery. No official Linux Drive mount is assumed.
7. Run the full original AT-01 through AT-32 matrix, including capacity, worker lifetime, restore history, delayed cleanup, aliases, interrupted receipt publication and deliberately defective controls. Optional disabled branches must be explicitly classified, never reported as executed successes.

The included SIGBUS case delivers an actual signal to an owned test child. It is **injected**, not evidence of spontaneous FileProvider eviction. The included SIGKILL case kills an owned child after a committed decision. It is a process-crash result, not power-loss evidence.

## Stop conditions

Any duplicate canonical K, acceptance of an incomplete/incorrect closure, release of an active/unknown pin, write through a hostile link, destructive overwrite, source recapture under ambiguous original intent, or fabricated remote-success receipt blocks release. Retain the evidence; do not weaken the expected result to obtain a pass.

No `fileproviderctl`, credential copying, Web UI automation, cloud mutex or provider deletion fallback is authorized by this checklist. Missing capabilities remain explicit holds. Resolve `CONFORMANCE.md` before claiming full Turn 4 conformance.
