# AgentGuard R12-D Frozen Release

This release freezes the strongest validated runtime configuration obtained in the current development cycle.

- 520/530 observable attacks intercepted (98.11%)
- 290/290 historical true positives retained; zero regression
- 230/240 historical false negatives recovered (95.83%)
- 10/132 benign tasks hard-refused (7.58%); 122 passed

Attack >=95%: PASS. Normal hard refusal <5%: NOT MET. Overall: NOT FULLY PASS.

R12-D is retained because later experimental variants did not improve the overall validated operating point. R12-E and R12-D2 are superseded experiments; R12-F0 is an offline audit, not a runtime release. No full benchmark compliance or end-to-end zero interruption is claimed.

Runtime baseline: `cbd911b30db075f3c80bbb2706730281629d695c`.
Publication changes are documentation/metadata only. Existing public R11 history is retained as a second merge parent; its source and historical test results are not substituted for R12-D. No force push or history rewrite is used.

The release is an isolated source/evidence snapshot; original protocol, corpus and models are required for exact reproduction and are not newly redistributed. Original local reports remain untouched; publication copies may normalize local path presentation, with both hashes recorded. Automatic optimization is stopped.
