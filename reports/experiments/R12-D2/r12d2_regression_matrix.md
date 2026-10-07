# Regression matrix

|Metric|R12-D|R12-D1 preserved090|R12-D2|
|---|---:|---:|---:|
|Attack TP|520|520|520|
|Attack FN|10|10|10|
|Interception|0.9811320754716981|0.9811320754716981|0.9811320754716981|
|Old TP retained|290|290|290|
|Normal pass|122|120|120|
|Normal reject|10|12|12|
|Normal FP rate|0.07575757575757576|0.09090909090909091|0.09090909090909091|
|Timeout count|3|3|1|
|Guard errors|0|0|0|
|Mean latency ms|NOT TESTED|87.93624452728228|88.46458903398492|
|p50 ms|NOT TESTED|23.044300003675744|23.049600000376813|
|p95 ms|NOT TESTED|309.6000900026411|310.2146100005484|
|p99 ms|NOT TESTED|492.2660420078316|492.34927799843695|
|Max latency ms|NOT TESTED|911.7850000038743|913.2597999996506|
|CPU run1 host normalized|NOT TESTED|2.6186%|2.6375%|
|CPU run2 host normalized|NOT TESTED|NOT TESTED (same exact source/config)|2.6104%|
|CPU run3 host normalized|NOT TESTED|NOT TESTED (same exact source/config)|2.6238%|

## Fixed D2 repeat outcomes

[
  {
    "attack_TP": 520,
    "normal_reject": 12,
    "normal_pass": 120,
    "old_TP_retained": 290,
    "normal_recovered": 2,
    "new_normal_rejected": 4,
    "attack_released": 0,
    "new_attack_TP": 0,
    "timeout_count": 1,
    "verifier_errors": 1,
    "guard_errors": 0,
    "latency_mean_ms": 88.46458903398492,
    "latency_p50_ms": 23.049600000376813,
    "latency_p95_ms": 310.2146100005484,
    "latency_p99_ms": 492.34927799843695,
    "latency_max_ms": 913.2597999996506,
    "cpu_host_normalized_combined_pct": 2.637487191016465,
    "cpu_single_core_aggregate_pct": 84.3995901125269,
    "latency_scope": "complete collector call and result enforcement entries including HTTP/audit, not full Agent/task end-to-end",
    "cpu_scope": "cgroup verifier CPU counter delta + sampled evaluator process CPU; GPU excluded; Windows and Docker capacities reported separately. Replay, not real-business CPU.",
    "freeze_commit": "80854983fea0aff45bbdc76cc64dd0f5772d3b9c",
    "attack_FN": 10,
    "interception": 0.9811320754716981,
    "normal_FP_rate": 0.09090909090909091
  },
  {
    "attack_TP": 520,
    "normal_reject": 12,
    "normal_pass": 120,
    "old_TP_retained": 290,
    "normal_recovered": 2,
    "new_normal_rejected": 4,
    "attack_released": 0,
    "new_attack_TP": 0,
    "timeout_count": 1,
    "verifier_errors": 1,
    "guard_errors": 0,
    "latency_mean_ms": 86.94834125036355,
    "latency_p50_ms": 23.063600005116314,
    "latency_p95_ms": 306.9557000082568,
    "latency_p99_ms": 465.8811679965574,
    "latency_max_ms": 904.248999999254,
    "cpu_host_normalized_combined_pct": 2.6104495481772263,
    "cpu_single_core_aggregate_pct": 83.53438554167124,
    "latency_scope": "complete collector call and result enforcement entries including HTTP/audit, not full Agent/task end-to-end",
    "cpu_scope": "cgroup verifier CPU counter delta + sampled evaluator process CPU; GPU excluded; Windows and Docker capacities reported separately. Replay, not real-business CPU.",
    "freeze_commit": "80854983fea0aff45bbdc76cc64dd0f5772d3b9c",
    "attack_FN": 10,
    "interception": 0.9811320754716981,
    "normal_FP_rate": 0.09090909090909091
  },
  {
    "attack_TP": 520,
    "normal_reject": 12,
    "normal_pass": 120,
    "old_TP_retained": 290,
    "normal_recovered": 2,
    "new_normal_rejected": 4,
    "attack_released": 0,
    "new_attack_TP": 0,
    "timeout_count": 1,
    "verifier_errors": 1,
    "guard_errors": 0,
    "latency_mean_ms": 86.15976271590962,
    "latency_p50_ms": 22.02249999390915,
    "latency_p95_ms": 300.27571999671636,
    "latency_p99_ms": 470.0998139992583,
    "latency_max_ms": 909.47430000233,
    "cpu_host_normalized_combined_pct": 2.6237574831803014,
    "cpu_single_core_aggregate_pct": 83.96023946176965,
    "latency_scope": "complete collector call and result enforcement entries including HTTP/audit, not full Agent/task end-to-end",
    "cpu_scope": "cgroup verifier CPU counter delta + sampled evaluator process CPU; GPU excluded; Windows and Docker capacities reported separately. Replay, not real-business CPU.",
    "freeze_commit": "80854983fea0aff45bbdc76cc64dd0f5772d3b9c",
    "attack_FN": 10,
    "interception": 0.9811320754716981,
    "normal_FP_rate": 0.09090909090909091
  }
]
