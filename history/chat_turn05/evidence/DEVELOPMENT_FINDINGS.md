# Development findings — retained, not target qualification

The initial complete-suite invocation was terminated by the execution wrapper after 200 seconds. Its retained log is an incomplete run, not a full-suite pass.

A subsequent four-case run observed one failure in the two-process test: exit categories were [0, 6], where the frozen oracle required [0, 5]. The winning process accepted once; the losing process reached eligibility registration after that decision and returned TASK_NOT_OPEN instead of TASK_ALREADY_ACCEPTED. The broker now checks the existing canonical decision inside the request-registration transaction as well as before capture. The test oracle was not weakened.

Code review also replaced hash-only reconciliation of explicit output destinations with a persisted, pre-rename staged-inode proof. An unrelated occupied output must remain OUTPUT_EXISTS even when its contents happen to match. This was a preventive correction, not evidence that a deployed system was compromised.

Later complete runs and their exact source hashes are retained separately. No Apple Silicon/FileProvider results are inferred from these Linux observations.
