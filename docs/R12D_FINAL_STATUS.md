# AgentGuard R12-D Frozen Status

## Version

R12-D. Freeze commit: `cbd911b30db075f3c80bbb2706730281629d695c`.

## Frozen metrics

Attack: 520/530 = 98.11%; FN: 10. Normal hard refusal: 10/132 = 7.58%; normal pass: 122.
Historical TP retention: 290/290; regression: 0. Historical FN recovery: 230/240 = 95.83%.

## Decision

R12-D is the current recommended frozen baseline. Attack interception exceeds the 95% target. Normal hard-refusal rate remains above the <5% target. The project must therefore not claim complete satisfaction of all competition performance targets.

The result is the original frozen full validation, not a new run. The 530 denominator is observable injections, not all 1,081 replay traces. Ten normal refusals remain; three overlapping normal errors are not effective detections. Full end-to-end zero interruption, universal generalization, and all resource/response gates have not been established by this release.

## Superseded experiments

R12-E regressed. R12-D2 retained attack performance but regressed benign hard refusal to 12/132 (9.09%). R12-F0 is an offline counterfactual recovery audit only, not a runtime release; projected 9/132 (6.82%) is not an observed runtime result. Reports are separated under `reports/experiments` and `reports/audits`.

## Development status

Automatic optimization is frozen. Further modifications require a new explicitly approved development cycle. This publication makes no runtime, threshold, model, prompt, evaluator, label, test-sample or denominator change. Original local evidence and experimental Git repositories remain preserved.
