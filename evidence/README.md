# Turn 6 evidence index

`final_turn06/results.json` is the final frozen-source execution record: 180 methods and eight negative controls. Per-group raw logs and results live below that directory. `crypto_interoperability.json` is a cross-interface native signature check, not an independent algorithm implementation.

The `turn06_*development*`, `extension_development_02.log`, `native_extension_development.log`, and earlier `turn06_base_regression_*` paths preserve development runs. The earliest was interrupted; one base run passed methods but failed its source-stability requirement. They are not part of the final pass count. Specific failed assertions and subsequent fixes are described in the main report.

Older Turn 5 evidence has been moved without rewriting its bytes into `history/chat_turn05/evidence/`. Historical evidence does not qualify new code. The user-reported Mac run is separately recorded in `UPSTREAM_APPLE_SILICON_ATTESTATION.json`; no raw Apple result was retrieved. No actual FileProvider, cellular or physically independent-device test is represented by these local fixtures.
