# Publication audit

No new model inference, benchmark execution, tuning, training or detector changes were performed. Thirty-nine frozen Python files passed AST syntax parsing and Git baseline-blob identity checks. The unchanged evaluator and runtime are listed in `publication_integrity.json`.

A pre-publication scan inspected 127 baseline-history blobs and working files for private keys, GitHub/API/AWS token patterns, credential-bearing URLs and literal credential assignments. No credential finding or file over 10 MiB was found. No new model weights, environment cache, raw trace dump or virtual environment is included. This is a scoped publication audit, not a proof that arbitrary secrets are algorithmically impossible.

Local report-path presentation was normalized in the publication copies; originals and hashes remain preserved. The exact designated baseline Git history necessarily retains its historical local workspace paths, since changing those historical objects would change the required baseline commit and rewrite history. Those paths are workspace provenance, not authentication material. Frozen Python tools retain their historical local layout assumptions and are not altered.

Only publication documentation, report copies, `.gitignore` and preserved third-party notices are changed relative to the runtime baseline. The existing public R11 history is retained as the second merge parent. Complete D2 source history and F0 audit evidence remain in their original local directories; selected reports are separately published. No existing branch, tag or experiment has been deleted or overwritten.

The published FN-recovery CSV omits its bulk `runtime_evidence` column to avoid redistributing raw benchmark text. All 240 rows, identifiers, verdicts and scoring fields are preserved; the original complete CSV remains unchanged locally. This omission is recorded in the evidence manifest.
