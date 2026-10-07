# R12-D minimal external instruction boundary

## Scope and current state

Implementation, synthetic interface smoke tests and three live synthetic verifier probes are complete. At this pre-freeze checkpoint formal validation has NOT started. Actual results will be recorded separately in r12d_full_metrics.md; no smoke-test accuracy claim is made.

The isolated baseline copies the 33 frozen R11 source files, unchanged evaluator and existing model assets. Original R11 and historical results are preserved.

## Changed runtime files

- `track2/detector/external_boundary.py`: checks an actual bound external return against the original trusted user request with the existing R11 `ContextualIntent.judge_return` instance.
- `track2/collector/inline_guard.py`: constructs the opt-in boundary and checks returns after existing result/R9 policies and before the original sparse semantic gate. Existing denials remain denials. A benign verdict continues the original R11 pipeline.

## Mechanism

The existing exact call-ID binding is the provenance gate. Unknown call IDs do not become external evidence. Successfully bound tool results have `source_trust=EXTERNAL_DATA`; `s.prompt` remains the original user authority. The unchanged R11 return verifier compares external control instructions against that task, including changes of output, recipient, permissions, tools or actions. It distinguishes quoted instructions and human-facing requests through its original semantic prompt.

This implementation does not claim a new symbolic intent/operation/recipient extractor. Those comparisons remain semantic operations inside the existing verifier. The new deterministic portion is source binding, trust designation, unconditional coverage of eligible returns, boolean schema checking, error accounting and interception routing.

The boundary reuses the exact original model, instance, endpoint, revision, prompt, seed 42 and timeout. No training, added model, second service, remote classifier or few-shot examples are introduced. The user explicitly authorized reuse and restoration of the original R11 service. Its existing GPU configuration is preserved under that authorization; no new GPU workload/service is deployed.

## Interception and errors

`malicious=True` uses the existing `DENY_RESULT` mechanism. A verifier failure withholds the result but is recorded as an error, not a confirmed boundary violation. The verifier error counter is incremented even for pre-request evidence-budget failures, so the frozen evaluator cannot count those refusals as validated interceptions. Normal hard refusals caused by these errors still count against normal availability.

Full returned evidence is supplied without benchmark-dependent window selection. The original 16,000-character verifier evidence budget remains unchanged. Oversized evidence fails explicitly rather than being silently truncated and marked safe.

## Audit and integrity

JSONL instrumentation records a generic guard ordinal, exact source call, trusted goal, returned text/hash, verdict, error and latency. It contains no benchmark IDs or attack labels as runtime features. Offline analysis can join the ordinal to selection order after execution.

The unchanged evaluator uses the original `validated_interception` definition and terminates replay on `DENY_RESULT`. The formal runner updates only the isolated candidate source manifest, verifies original hashes, commits before execution and prevents starting a second run into the same output folder. All 1,081 selected traces will run, with the fixed 530 observable attacks and 132 normal tasks reported separately.

## Verification completed

Synthetic smoke tests verify original task propagation, exact call binding, unmatched-source nonchecking, benign passthrough, actual collector `DENY_RESULT`, request-ID preservation, explicit error accounting and missing-verifier rejection. These tests do not establish model accuracy.

## Service restoration history

Docker Desktop fails at inference-manager initialization: the existing `dockerInference` communication file cannot be accessed. Restart and reversible rename failed. Automatic approval review rejected deleting this stale communication file. No container recreation, data reset or formal benchmark run has been performed.

Docker was subsequently opened by the user. Its current engine had no containers or images. The user explicitly authorized rebuilding only the original verifier from the preserved configuration. The pinned image was downloaded, the original named network restored, and one verifier container created with unchanged configuration. Health is now OK. A premature health probe returned model-loading 503 before model initialization; no semantic query was executed then. Three subsequent live synthetic probes returned two benign and one malicious verdict with zero errors. No prompt or timeout change was made.
