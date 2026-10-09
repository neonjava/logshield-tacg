# LogShield TACG — Engineering audit and stabilization

**Audit Baseline Commit:** `af93e5f5763f989664416758836351fe59db60fe`
**Date:** October 10, 2026
**Scope:** source review and local verification; no independent security certification

---

## 1. Executive Summary & Audit Baseline

A comprehensive technical audit was conducted across the LogShield TACG workspace (`crates/logshield-core`, `crates/logshield-api`, `crates/logshield-ingest`, `crates/logshield-infra`, `crates/logshield-lab`, and `frontend/`).

### Baseline verification
- `cargo test --workspace` passed locally after the in-progress edits; the Docker lab test and synthetic throughput test are ignored by this command.
- `cargo clippy --workspace --all-targets -- -D warnings` passed locally. `cargo fmt --check` initially found formatting changes; `cargo fmt` was applied.
- The previously reported CI run `38030688780` applies to commit `af93e5f`, not to this working tree.
- `cargo build --release --workspace` and `npm run build` passed locally after these changes.
- `docker compose build` followed by `cargo test -p logshield-api --test lab_e2e -- --ignored --nocapture` passed locally against rebuilt images (one test, 74.62 seconds).
- Final CI remains unverified until the pushed commit's checks complete.

The 60 scenarios are authored synthetic cases. They cannot establish field detection accuracy. The findings below are based on inspected code and need further adversarial and deployment-level verification.

---

## 2. Discovered Engineering & Security Findings

| ID | Component | Severity | Description | Proposed Fix | Status |
|---|---|:---:|---|---|:---:|
| **SEC-01** | Baseline and API | **High** | Historical successful logins were not independently verified benign. Snapshot and quarantine methods were not connected to the private API. | Persist candidates and versioned snapshots; require an operator-reviewed promotion after quarantine, excluding incident evidence. | Implemented and restart-tested; source assertions still require independent review |
| **DET-01** | `crates/logshield-core/src/tacg.rs` | **High** | Same-account paths miss single-source password spraying across distinct users. | Add a distinct-account source path and verify against benign shared-address cases. | Implemented locally; synthetic regression passes; field false-positive rate unknown |
| **DET-02** | Evaluation | **Medium** | The 60-case benchmark did not distinguish decay from uniform edges. | Add a separate 140-second-gap regression; expand the held-out set later without tuning against final labels. | One regression passes; representative evidence open |
| **RESP-01**| Response | **Medium** | The previous response record had no explicit stage or verified rollback/expiry transition. | Preserve approval proof, match gateway source and incident, reconcile pending responses and lease expiry, implement authorized lab rollback. | Implemented and exercised in the isolated Docker lab; non-lab adapter disabled |
| **AUTH-01**| API | **High** | One operator bearer token granted all protected access. Browsers need a trusted proxy for WebSocket authorization headers. | Add a separate viewer token for protected reads; test denied writes and WebSocket access. A session or proxy model and token rotation remain open. | Partial: viewer boundary integration test passes; deployment gate remains |
| **PERF-01**| `crates/logshield-api/src/main.rs` & `database.rs` | **Medium** | Correlation reloads up to 2,000 recent events and is costly under mixed traffic. | Index event time, skip benign-only source anchors, prune old candidate rows; retain the same detector for suspicious input. | Partial: four-producer mixed probe passed at 144 events/s with p95 batch latency 5.3 s; full incremental processing remains open |
| **OPS-01** | `crates/logshield-api/src/main.rs` | **Medium** | **Missing Standard Telemetry & Health Probes:** API lacks standard Kubernetes/Prometheus observability (`/api/healthz`, `/api/readyz`, `/api/metrics`). | Add Prometheus-formatted metrics endpoint and standard liveness/readiness probes. | Open |
| **DEP-01** | `deploy/` | **High** | Repository only provided the lab environment. | Add a separate non-lab Compose stack with TLS, protected dashboard, source authentication, persistent evidence, backup/restore, and a disposable security smoke test. | Implemented; local smoke passed; real-host operation and external review remain open |
| **AGENT-01** | File agent | **High** | An offset alone missed early records when a rotated replacement grew past the old offset before the agent reopened it. | Persist device and inode with the offset; recognize legacy numeric state and reset to byte zero on rotation or truncation. | Implemented; restart and larger-file rotation regression passes |

---

## 3. Detailed Root Cause & Impact Analysis

### 3.1 DET-01: Password Spraying Missed Due to Same-Account Edge Assumption
- **Root Cause:** In `crates/logshield-core/src/tacg.rs:180-207`, `account_failure_paths` uses `previous: HashMap<&str, &SecurityEvent>` keyed by `user`. Edges are only drawn when `prior.is_some_and(...)` matches the same username. When an adversary performs a classic password spray against 8 different accounts, every user appears only once. Zero edges are drawn, `count` remains 1, and `cross` remains 0.0.
- **Impact:** In the 60-scenario held-out benchmark, all 5 instances of `AttackPasswordSpray` (seeds 10001, 20002, 30003, 40004, 50005) were completely missed by Full TACG, causing recall to stall at 85.7% (30/35).
- **Remediation:** A source-anchored candidate now requires at least six failures against six distinct accounts within the sliding window. It constructs time-decayed evidence edges and labels a password spray incident. This threshold is tuned only against authored examples; shared-address field false positives remain unknown.

### 3.2 DET-02: Temporal Decay Equivalence in Rapid Scenarios
- **Root Cause:** Exponential decay with $\tau = 90$s satisfies $\exp(-\Delta t / 90) \ge 0.35$ for all $\Delta t \le 94.5$s. Because existing synthetic attacks generated events spaced by 2–15s, both decayed and non-decayed weights satisfied edge thresholds.
- **Impact:** Disabling decay showed 0 delta in precision/recall across the 60 scenarios, masking the true algorithmic benefit of decay: penalizing slow, unrelated benign login drift that occurs over 200–500 seconds.
- **Remediation:** Add realistic temporal drift scenarios where benign failures are spaced 120s–300s apart. Full TACG decays these below threshold, while `no_temporal_decay` falsely links them into an attack cluster.

### 3.3 SEC-01: Baseline Lifecycle & Poisoning Defenses
- **Root Cause:** A rolling baseline that updates on every ingestion batch without a quarantine period can gradually incorporate compromised account behavior if an adversary conducts slow, low-volume reconnaissance.
- **Remediation status:** The private API stores authenticated collector observations as quarantined candidates in SQLite. A separate operator review endpoint promotes only a specific candidate after three distinct incident-free observations, a one-hour quarantine, and a ten-minute event cutoff. The approved snapshot is persisted and restored after restart. A login success is never promoted automatically. The reported source address is still an application assertion, so the reviewer must independently confirm it. A later-discovered compromised approval is not automatically revoked.

---

## 4. Remaining operational gates

The 35/35 synthetic attack and 0/25 benign regression result is not an independent accuracy estimate. Full incremental correlation, sustained mixed-load sizing, field false-positive measurements, trusted remote-client attribution, certificate and token rotation, operational monitoring, and an external security review remain open. The intended designation is **integration beta** for a private, self-hosted network. See [Production readiness](PRODUCTION_READINESS.md) for each gate and [Deployment](DEPLOYMENT.md) for the tested localhost path.
