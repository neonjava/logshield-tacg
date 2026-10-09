# LogShield TACG — Engineering audit in progress

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
| **SEC-01** | Baseline and API | **High** | Historical successful logins are not independently verified benign. The new snapshot and quarantine library methods are not integrated with API decisions. | Keep private-mode familiarity baseline cold until an approved promotion store and authenticated review path exist. Use collector time for cutoff. | Partial: conservative API guard implemented; approved promotion remains open |
| **DET-01** | `crates/logshield-core/src/tacg.rs` | **High** | Same-account paths miss single-source password spraying across distinct users. | Add a distinct-account source path and verify against benign shared-address cases. | Implemented locally; synthetic regression passes; field false-positive rate unknown |
| **DET-02** | Evaluation | **Medium** | The 60-case benchmark did not distinguish decay from uniform edges. | Add a separate 140-second-gap regression; expand the held-out set later without tuning against final labels. | One regression passes; representative evidence open |
| **RESP-01**| Response | **Medium** | The previous response record had no explicit stage. | Add stages while retaining old serialized records. Wire operator approval and expiry to actual gateway operations before claiming operational support. | Partial: enum added; lifecycle enforcement open |
| **AUTH-01**| API | **High** | One operator bearer token granted all protected access. Browsers need a trusted proxy for WebSocket authorization headers. | Add a separate viewer token for protected reads; test denied writes and WebSocket access. A session or proxy model and token rotation remain open. | Partial: viewer boundary integration test passes; deployment gate remains |
| **PERF-01**| `crates/logshield-api/src/main.rs` & `database.rs` | **Medium** | **Full Database Scan on Every Batch:** `process_batch` executes `SELECT * FROM events ORDER BY timestamp DESC LIMIT 2000` on every ingested batch, incurring unnecessary CPU/memory overhead as event volume grows. | Implement windowed event queries (`WHERE timestamp >= ?`), add database indexes on `timestamp`, `source_ip`, and `username`. | Open |
| **OPS-01** | `crates/logshield-api/src/main.rs` | **Medium** | **Missing Standard Telemetry & Health Probes:** API lacks standard Kubernetes/Prometheus observability (`/api/healthz`, `/api/readyz`, `/api/metrics`). | Add Prometheus-formatted metrics endpoint and standard liveness/readiness probes. | Open |
| **DEP-01** | `deploy/` | **High** | **Lack of Isolated Production Deployment Manifest:** Repository only provided the lab environment with synthetic attackers and unauthenticated lab routes. No ready-to-run self-hosted non-lab production Compose manifest existed. | Create `deploy/production/` with hardened non-lab Compose manifest, reverse proxy (NGINX/TLS), non-root execution, and read-only container volumes. | Open |

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
- **Remediation status:** Versioned snapshot and quarantine methods exist in the core library, but the API has no authenticated approval store or durable promotion path. Private API processing therefore uses an empty trusted baseline; lab training retains historical learning for demonstrations. This avoids treating unreviewed successful logins as trusted in private mode but may increase alert noise.

---

## 4. Remediation Plan

1. **Phase 1:** Implement Password Spray detection in `crates/logshield-core/src/tacg.rs` and Snapshot-based Baseline in `crates/logshield-core/src/baseline.rs`.
2. **Phase 2:** Update benchmark suite to verify Password Spray detection (improving recall from 85.7% to 100% or 35/35 attacks) and add temporal drift test cases demonstrating decay's edge-filtering value.
3. **Phase 3:** Harden API authentication: role-based auth (Viewer vs Operator), constant-time token verification, and WebSocket authorization in `crates/logshield-api/src/main.rs`.
4. **Phase 4:** Formalize response state machine in `crates/logshield-core/src/response.rs` and `crates/logshield-api/src/main.rs`.
5. **Phase 5 & 6:** Database windowed queries, indexing, and SQLite concurrency hardening.
6. **Phase 7 & 8:** Production deployment configuration in `deploy/production/`, Prometheus `/api/metrics`, and health probes.
7. **Phase 9–12:** Complete documentation and production readiness gate.
