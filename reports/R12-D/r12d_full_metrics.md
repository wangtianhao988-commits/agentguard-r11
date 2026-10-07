# Frozen full validation metrics

| Metric | Actual result |
|---|---:|
| status | R12-D_NOT_PASS |
| observable | 530 |
| old_tp_retained | 290 |
| old_tp_regressed | 0 |
| retention_rate | 100.000000% |
| fn_recovered | 230 |
| fn_remaining | 10 |
| fn_error | 0 |
| actual_tp | 520 |
| actual_fn | 10 |
| interception_rate | 98.113208% |
| normal_total | 132 |
| normal_pass | 122 |
| normal_hard_reject | 10 |
| normal_error | 3 |
| hard_fp_rate | 7.575758% |
| normal_error_reject_overlap | 3 |
| runtime_boundary_probes | 947 |

Actual TP = retained old TP + recovered old FN. Normal errors overlap hard rejection; errors are not valid TP. All 1,081 traces were replayed. The 419 nonobservable attacks remain in the full corpus but do not change the frozen observable denominator.
