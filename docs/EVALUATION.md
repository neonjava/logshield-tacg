# LogShield TACG — Empirical Evaluation & Benchmark Report

This document details the quantitative evaluation of the **Temporal Attack Correlation Graph (TACG)** detection engine across three evaluation methodologies:
1. **5-Case Deterministic Regression Suite:** Verifies basic cross-host vs. per-host threshold logic.
2. **16-Case Mixed-Traffic Evaluation:** Compares TACG against a stateful centralized ruleset on authored scenarios with background noise.
3. **60-Scenario Independent Held-Out Benchmark & Ablation Study:** Evaluates TACG, an ablated model without graph edges, and stateful centralized rules across 12 scenario families and 5 PRNG seeds.

---

## 1. Five-Case Deterministic Regression Check

Run:
```bash
cargo test -p logshield-core --test evaluation -- --nocapture
```

This deterministic test compares **critical/automatic-action decisions** across five foundational test cases:
1. Distributed 2/2/1 attack across 3 hosts.
2. Ordered multi-stage attack (failure $\to$ success $\to$ privilege $\to$ network).
3. Five failures spread over five unrelated accounts.
4. Familiar account/source/host combination making five failures.
5. Normal baseline activity.

### Results

| Detector Architecture | True Positives / 2 | False Positives / 3 | False Negatives / 2 |
|---|---:|---:|---:|
| **TACG Graph Path + Ordered Rules** | **2** | **0** | **0** |
| Centralized source counter (5 failures) | 1 | 2 | 1 |
| Per-host counter (5 failures) | 0 | 0 | 2 |

**Analysis:** The per-host threshold of 5 misses the distributed attack because each host observes at most 2 failures. The centralized source counter flags unrelated accounts and familiar users as attacks. TACG enforces path connectivity for the same targeted identity and incorporates baseline history, correctly identifying both true attacks with zero false alarms.

---

## 2. 16-Case Mixed-Traffic Evaluation Against Stateful Centralized Rules

Run:
```bash
cargo test -p logshield-core --test mixed_evaluation -- --nocapture
```

This deterministic test runs 16 authored cases — 9 attacks and 7 benign scenarios — each mixed with 20 ambient web-request background events. It compares TACG against a stateful centralized ruleset that observes the exact same source, account, host, and timestamp data but lacks graph topology.

### Detection Performance Comparison

| Detector Architecture | TP | FP | TN | FN | Precision | Recall | FPR | Benign Criticals | Median Delay |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Full TACG (Graph + Baseline)** | **7** | **0** | **7** | **2** | **1.00** | **0.78** | **0.00** | **0** | **25s** |
| Stateful Centralized Rules | 7 | 3 | 4 | 2 | 0.70 | 0.78 | 0.43 | 0 | 25s |

### Detailed Case-by-Case Breakdown

| Scenario Name | Label | TACG Detection | TACG Critical | Rules Detection | TACG Delay | Outcome Analysis |
|---|---|:---:|:---:|:---:|:---:|---|
| `normal_shared_login` | Benign | Clean | No | Clean | — | Normal multi-user corporate login. |
| `normal_web_only` | Benign | Clean | No | Clean | — | Routine web browsing without auth events. |
| `distributed_rapid` | Attack | **Detected** | Yes | Detected | 28s | 2/2/1 probe across 3 servers within 30s. |
| `distributed_spaced` | Attack | **Detected** | No | Detected | 280s | 2/2/1 probe spaced over 5 minutes. |
| `distributed_beyond_window` | Attack | Missed | No | Missed | — | **Honest Boundary:** 720s spacing exceeds 600s window. |
| `brute_force` | Attack | **Detected** | No | Detected | 25s | Single host subjected to 6 rapid failures. |
| `mixed_accounts_nat` | Benign | Clean | No | Clean | — | Shared NAT egress with multiple unrelated logins. |
| `rotating_source` | Attack | **Detected** | Yes | Missed | 21s | **TACG Advantage:** Identity-anchored clustering catches rotating IP botnet; centralized per-IP rules miss it. |
| `mfa_attack` | Attack | **Detected** | Yes | Detected | 16s | Rapid MFA push fatigue sequence. |
| `mfa_user_errors` | Benign | Clean | No | False Alarm | — | **TACG Advantage:** Routine MFA retry by familiar user is discounted. Rules falsely alert. |
| `ordered_chain` | Attack | **Detected** | Yes | Detected | 20s | Strict 4-stage kill chain sequence. |
| `reordered_activity` | Benign | Clean | No | Clean | — | Privilege action preceding login (e.g. background job). |
| `success_after_failures` | Attack | **Detected** | Yes | Detected | 25s | Credential stuffing followed by compromise. |
| `legitimate_password_typos`| Benign | Clean | No | False Alarm | — | **TACG Advantage:** 1–2 typos by familiar user discounted. Rules falsely alert. |
| `new_source_success` | Attack | Anomaly | No | Detected | — | Single login from new IP. Scored as Medium anomaly (risk 60) without auto-blocking. |
| `legitimate_new_device` | Benign | Clean | No | False Alarm | — | Familiar user on new laptop. Rules falsely alert; TACG suppresses false alarm. |

### Key Improvements Over Previous Versions
1. **Zero False-Positive Rate (0.00 vs 0.43):** Familiarity discounting eliminates false critical containment on routine user password typos (`legitimate_password_typos`) and expired MFA code retries (`mfa_user_errors`).
2. **Rotating Source Attack Caught:** Identity-anchored correlation (Pass 2) detects attacks alternating IP addresses targeting a single identity, where traditional IP-based rules fail.
3. **Zero Benign Criticals:** No legitimate user is falsely subjected to automated gateway containment.

---

## 3. 60-Scenario Independent Benchmark Suite & Ablation Study

Run:
```bash
cargo test -p logshield-core --test benchmark_suite -- --nocapture
```

To validate TACG beyond small hand-crafted fixtures, we created an independent synthetic benchmark generator with deterministic pseudo-random network jitter (±1–3s) and background web traffic (10–20 requests per scenario).

The benchmark suite generates **60 distinct held-out scenarios** across **5 random seeds** (10001, 20002, 30003, 40004, 50005) covering **12 scenario families**:
- **Benign Families (25 scenarios):** `BenignRoutineUser`, `BenignNatOffice`, `BenignMfaRetry`, `BenignTravelDevice`, `BenignBurstTraffic`.
- **Attack Families (35 scenarios):** `AttackDistributedBruteforce`, `AttackRotatingSources`, `AttackPasswordSpray`, `AttackMfaPushFatigue`, `AttackMultistageKillchain`, `AttackSuccessAfterSpray`, `AttackInterleavedComposite`.

### Model Architectures Compared
1. **Full TACG:** Temporal correlation graph with exponential time decay ($\tau = 90$s), dual-anchor clustering, and behavioral baseline familiarity.
2. **Ablated TACG (Ablation Study):** Disables all graph edges, temporal decay, and account path connectivity, evaluating clusters strictly with static scalar failure counters.
3. **Stateful Centralized Rules Engine:** Stateful rules with multi-host tracking and baseline checks, but no graph representation.

### Empirical Results (60 Held-Out Scenarios)

| Architecture | TP | FP | TN | FN | Precision | Recall | F1 Score | FPR | Benign Criticals | Median Delay |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Full TACG** | **30** | **0** | **25** | **5** | **1.000** | **0.857** | **0.923** | **0.000** | **0** | **25s** |
| Ablated TACG (No Graph Edges) | 20 | 0 | 25 | 15 | 1.000 | 0.571 | 0.727 | 0.000 | 0 | 0s |
| Stateful Centralized Rules | 25 | 0 | 25 | 10 | 1.000 | 0.714 | 0.833 | 0.000 | 0 | 0s |

### Full TACG Confusion Matrix

```
                  Predicted Negative    Predicted Positive
Actual Negative:  TN = 25                 FP = 0
Actual Positive:  FN = 5                  TP = 30
```

### Ablation Study Findings
- **Impact of Graph Edges (+0.196 F1):** Removing temporal edges and causal path reconstruction reduces detection recall from **85.7% to 57.1%** and drops F1 from **0.923 to 0.727**. Static counters fail to detect distributed credential sprays and interleaved composite attacks where failures are interleaved with normal traffic.
- **Superiority Over Centralized Rules (+0.090 F1):** Full TACG achieves higher recall (85.7% vs 71.4%) and F1 (0.923 vs 0.833) than stateful centralized rules, primarily due to identity-anchored graph paths that detect rotating source botnets.

---

## 4. Evaluation Limitations & Scientific Integrity

While these benchmarks provide reproducible evidence of algorithmic soundess:
1. **Synthetic Scenarios:** Both the 16 fixtures and the 60 benchmark scenarios are synthetically generated. They model realistic jitter and background traffic, but do not replace multi-month production logs from enterprise environments.
2. **10-Minute Correlation Window:** Attacks deliberately throttled to $> 600$ seconds between steps are outside the sliding graph window by design.
3. **No Probabilistic Calibration:** The `confidence` score (e.g., 90/100) represents rule and graph structural evidence strength, **not** a calibrated Bayesian probability of attack.
