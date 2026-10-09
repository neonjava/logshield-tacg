# Production readiness gate

Status: **INTEGRATION BETA** for private, self-hosted evaluation. Do not expose the API or dashboard to the public internet. The Docker lab is an isolated demonstration, not a production deployment test.

| Gate | Status | Evidence or blocker |
| --- | --- | --- |
| Operator authentication | PARTIALLY IMPLEMENTED | Non-lab bearer tokens and REST/WebSocket integration tests; no rotation or sessions. |
| Operator authorization | PARTIALLY IMPLEMENTED | Optional viewer token can read protected GET routes; operator token controls writes. No finer response role or user identity. |
| Secure transport | BLOCKED | Deployment TLS proxy has not been configured or exercised. |
| Source identity | PARTIALLY IMPLEMENTED | Ingest tokens identify collectors, not the reported client IP. |
| Secrets management | PARTIALLY IMPLEMENTED | Environment tokens; no rotation workflow. |
| Persistence durability | PARTIALLY IMPLEMENTED | SQLite transaction and durable receipt; crash and power-loss tests limited. |
| Backup and restore | NOT IMPLEMENTED | No tested procedure. |
| Event integrity | PARTIALLY IMPLEMENTED | IDs deduplicate; no signed source assertions or tamper-evident evidence. |
| Crash recovery | PARTIALLY IMPLEMENTED | SDK queue restart tests; response recovery unverified. |
| SDK and agent reliability | PARTIALLY IMPLEMENTED | Queue retry tests; file rotation and disk-full coverage incomplete. |
| Detector correctness | PARTIALLY IMPLEMENTED | Unit tests and authored synthetic cases; no independent labeled log corpus. |
| False-positive safety | PARTIALLY IMPLEMENTED | Non-lab automatic containment disabled; field FPR unknown. |
| Response authorization | PARTIALLY IMPLEMENTED | Lab response protected by operator token; no separate response role. |
| Deployment security | BLOCKED | No tested hardened non-lab Compose/TLS deployment. |
| Performance limits | PARTIALLY IMPLEMENTED | Sequential localhost benign measurement; mixed and concurrent load unknown. |
| Monitoring | PARTIALLY IMPLEMENTED | Basic health/status; operational metrics and alerts incomplete. |
| Documentation | PARTIALLY IMPLEMENTED | SDK and lab docs exist; operator runbook incomplete. |
| CI coverage | IMPLEMENTED BUT NOT INDEPENDENTLY VERIFIED | Prior commit had green CI; current edits need a new run. |
| Dependency security | NOT IMPLEMENTED | No recorded dependency audit or SBOM gate. |
| Incident investigation | PARTIALLY IMPLEMENTED | Evidence and graph available; retention/access audit open. |
| Recovery and rollback | NOT IMPLEMENTED | Response enum exists, gateway lease rollback and restart recovery untested. |

The new snapshot, quarantine and response-state library APIs are not yet an operational promotion or response workflow. The 35/35 synthetic result is a regression measurement and must not be used as a production accuracy claim. A production designation requires a tested private deployment, external security review, backup/restore drill, traffic-derived evaluation, and a load test at the intended operating rate.
