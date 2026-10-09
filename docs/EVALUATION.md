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
