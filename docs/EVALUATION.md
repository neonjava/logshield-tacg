# Small labeled comparison

Run `cargo test -p logshield-core --test evaluation -- --nocapture`. This deterministic test compares **critical/automatic-action decisions**, not every medium-severity alert, on five hand-built cases. The cases are: distributed 2/2/1 attack, ordered multi-stage attack, five failures spread over five unrelated accounts, a familiar account/source/host combination making five failures, and normal activity.

| Detector | True positives / 2 | False positives / 3 | False negatives / 2 |
| --- | ---: | ---: | ---: |
| TACG graph path + ordered rules | 2 | 0 | 0 |
| Centralized source counter (5 failures) | 1 | 2 | 1 |
| Per-host counter (5 failures) | 0 | 0 | 2 |

The central counter sees the same five failures in the distributed and benign cases. TACG requires a connected same-account failure path and lowers automatic-response risk when the source and hosts are established in the baseline. The ordered multi-stage case is detected without five failures.

**These figures are only fixture checks, not measured real-world precision, recall, or false-positive rate.** The examples were constructed to expose these rules, contain no natural background traffic, and use trusted lab source labels. A representative labeled log corpus, independent ground truth, multiple organizations, and sustained ingestion load tests are required before production claims. The `confidence` API field is an evidence-strength score, not a calibrated probability.

The separate [local ingestion probe](PERFORMANCE.md) measures delivery and processing of synthetic benign events. It does not measure attack detection quality.

## Mixed-traffic comparison against stateful centralized rules

Run `cargo test -p logshield-core --test mixed_evaluation -- --nocapture`. This deterministic test runs 16 authored cases — 9 attacks and 7 benign — each mixed with 20 normal web-request background events. It compares TACG against a stateful centralized ruleset that sees the same source, account, host, and time data but uses no graph representation.

| Detector | TP | FP | TN | FN | Precision | Recall | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| TACG graph path + ordered rules | 6 | 2 | 5 | 3 | 0.75 | 0.67 | 0.29 |
| Stateful centralized rules | 7 | 3 | 4 | 2 | 0.70 | 0.78 | 0.43 |

Cases include: distributed attacks (rapid, spaced, beyond-window), brute force, rotating sources, MFA attacks, ordered multi-stage chains, success-after-failures, new-source logins, NAT shared-source benign traffic, legitimate password typos with baseline history, and normal activity.

**Key findings on authored data:**

- TACG has **lower false-positive rate** (0.29 vs 0.43) — it does not alert on legitimate new-device logins that the centralized rules flag.
- Centralized rules have **higher recall** (0.78 vs 0.67) — they catch new-source-success patterns that TACG currently misses.
- Both miss the `distributed_beyond_window` case (failures spaced 720s apart exceed the 600s correlation window).
- Both false-positive on `mfa_user_errors` and `legitimate_password_typos` — 3 rapid MFA failures and 2 failures followed by success look identical to attacks without richer context.
- TACG's `benign_critical` count (automatic-action false positives) is 2; lowering this requires richer baseline or user-interaction signals.
- Median detection delay is identical (25s) on these cases.

**These are authored fixtures, not field data.** The 16 cases were constructed to exercise specific rules and edge conditions. They contain no sustained natural background traffic, no overlapping concurrent attacks, no evasion techniques, and no calibration against real organizational log volumes. A representative labeled corpus from multiple organizations with independent ground truth is required before claiming detection superiority.
