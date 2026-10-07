# AgentGuard R12-D — Frozen Validated Baseline

当前最佳真实运行版本已冻结。攻击拦截指标达到要求，但正常任务硬拒绝率仍高于目标；整体比赛性能门槛尚未全部通过。自动优化已停止。

## Current frozen version

**R12-D**. Frozen runtime baseline: `cbd911b30db075f3c80bbb2706730281629d695c`.
Official branch: `release/r12-d-frozen`; annotated tag: `r12-d-frozen`.
The release commit adds documentation and publication metadata only. The frozen runtime and evaluator are unchanged.

## Frozen evaluation

| Metric | Validated result |
|---|---:|
| Observable attack interception | 520/530 = 98.11% |
| Attack false negatives | 10/530 |
| Historical TP retained | 290/290 = 100% |
| Historical TP regression | 0 |
| Historical FN recovered | 230/240 = 95.83% |
| Normal tasks passed | 122/132 |
| Normal hard refusals | 10/132 = 7.58% |

Attack detection target >=95%: **PASS**.
Benign hard-refusal target <5%: **NOT YET MET**.
Overall official performance target: **NOT FULLY PASS**.

98.11% comes from 530 observable injection samples in one frozen full validation. The full replay contained 1,081 traces, including 419 nonobservable attack traces; these do not increase the 530 denominator. All 290 historical TP were retained. Three normal runtime errors overlap the ten normal hard refusals and are not valid attack detections.

Ten normal hard refusals remain. Complete end-to-end business continuity has not been verified. A single frozen corpus does not establish generalization across all attack families or all model/agent configurations. These results do not establish full competition acceptance, CPU compliance or latency compliance under every workload.

## Source and reproducibility boundary

This branch publishes the exact isolated R12-D runtime/evaluator snapshot and selected evidence. It is not a self-contained competition environment. `track2/collector` and `track2/detector` are the frozen runtime; `05_复现脚本/evaluate_external_r10.py` is the unchanged evaluator. Historical `tools/` scripts document the original local experiment and depend on its original layout; do not run them as installation or optimization steps.

The frozen benchmark, labels, original trace archives, model assets, protocol and existing R11 verifier configuration remain preserved locally and are not redistributed here. Authorized reproduction requires those same inputs, asset hashes and the original verifier; no new validation is claimed by this publication. Python syntax and repository/hash checks are recorded in `reports/R12-D/publication_integrity.json`.

The prior public R11 snapshot remains available in Git history at `fe16da817a5dc241c90a1c007c1984be88adbf76`. Its installation/test results are historical and must not be attributed to this R12-D release. That history, including the later project-guideline document, is retained through a normal merge parent. No existing history was rewritten.

## Evidence and superseded experiments

- [Final status](docs/R12D_FINAL_STATUS.md)
- [Release notes](RELEASE_NOTES_R12D.md)
- [Frozen metrics](reports/R12-D/r12d_metrics.json) and [failure cases](reports/R12-D/r12d_failure_cases.md)
- [Publication evidence manifest](reports/R12-D/publication_evidence_manifest.json): original and publication-copy hashes; local path presentation may be normalized without changing experimental results.
- [Experimental history](reports/experiments/README.md): R12-E regressed; R12-D2 retained 520/530 attacks but regressed normals to 12/132 = 9.09%.
- [R12-F0 offline audit](reports/audits/R12-F0/r12f0_final_report.md): not a runtime release. Its projected 9/132 = 6.82% is counterfactual, not a real-run result.

## Development status and third-party material

Automatic optimization is frozen. Further changes require a new explicitly approved development cycle. No model, threshold, prompt, evaluator, labels, samples or denominator were changed during publication.

No official arena, bulk benchmark dump, model weights, credential or environment cache is newly published. The existing third-party notices are preserved in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). No project license is added or replaced.

The published FN-recovery CSV omits its bulk `runtime_evidence` column to avoid redistributing raw benchmark text. All 240 rows, identifiers, verdicts and scoring fields are preserved; the original complete CSV remains unchanged locally. This omission is recorded in the evidence manifest.
