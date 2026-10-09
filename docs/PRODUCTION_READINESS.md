# Production readiness gate

Status: **INTEGRATION BETA** for private, self-hosted evaluation. Do not expose the API or dashboard to the public internet. The Docker lab is an isolated demonstration, not a production deployment test.

| Gate | Status | Evidence or blocker |
| --- | --- | --- |
| Operator authentication | PARTIALLY IMPLEMENTED | Non-lab bearer tokens and REST/WebSocket integration tests; no rotation or sessions. |
| Operator authorization | PARTIALLY IMPLEMENTED | Optional viewer token can read protected GET routes; operator token controls writes. No finer response role or user identity. |
| Secure transport | VERIFIED | Disposable local Compose test used TLS at the proxy and a protected WebSocket upgrade; certificate lifecycle on a real host remains operator-managed. |
| Source identity | PARTIALLY IMPLEMENTED | Ingest tokens identify collectors, not the reported client IP. |
| Secrets management | PARTIALLY IMPLEMENTED | Environment tokens; no rotation workflow. |
| Persistence durability | PARTIALLY IMPLEMENTED | SQLite transaction and durable receipt; crash and power-loss tests limited. |
| Backup and restore | VERIFIED | Disposable SQLite `VACUUM INTO` backup and restore drill preserved the pre-backup event and removed a post-backup marker. Off-host encrypted backup operation remains open. |
| Event integrity | PARTIALLY IMPLEMENTED | IDs deduplicate; no signed source assertions or tamper-evident evidence. |
| Crash recovery | PARTIALLY IMPLEMENTED | SDK queue restart tests; response recovery unverified. |
| SDK and agent reliability | PARTIALLY IMPLEMENTED | Queue retry and agent restart/rotation tests pass, including a replacement file longer than the prior offset. Disk-full, sustained outage, and multi-process spool coverage remain incomplete. |
| Detector correctness | PARTIALLY IMPLEMENTED | Unit tests include 6–20 shared-NAT users and authored attack cases; no independent labeled log corpus. |
| False-positive safety | PARTIALLY IMPLEMENTED | Non-lab automatic containment disabled; field FPR unknown. |
| Response authorization | PARTIALLY IMPLEMENTED | Lab response protected by operator token; no separate response role. |
| Deployment security | PARTIALLY IMPLEMENTED | Separate private Compose stack tested locally with loopback ports, non-root API/proxy, read-only filesystems, TLS, viewer auth, ingest auth, WebSocket auth, persistent volume, and disabled lab routes. No external review or multi-host test. |
| Performance limits | PARTIALLY IMPLEMENTED | Local four-producer mixed probe measured 144 events/s and p95 batch latency 5.3 s; sustained load and field capacity unknown. |
| Monitoring | PARTIALLY IMPLEMENTED | Basic health/status; operational metrics and alerts incomplete. |
| Documentation | PARTIALLY IMPLEMENTED | SDK and lab docs exist; operator runbook incomplete. |
| CI coverage | IMPLEMENTED BUT NOT INDEPENDENTLY VERIFIED | Prior commit had green CI; current edits need a new run. |
| Dependency security | NOT IMPLEMENTED | No recorded dependency audit or SBOM gate. |
| Incident investigation | PARTIALLY IMPLEMENTED | Evidence and graph available; retention/access audit open. |
| Recovery and rollback | PARTIALLY IMPLEMENTED | Rebuilt local lab test verified matching rollback, duplicate rejection, failed rollback state retention, restart and lease expiry. Non-lab containment adapter remains disabled. |

Private API baseline candidates are now stored transactionally with authenticated agent successes. After three distinct incident-free observations, an hour of quarantine, and a ten-minute event cutoff, an operator may attest that one candidate is benign through `POST /api/baseline/approve` using the operator token and `reviewed_benign: true`. The versioned snapshot survives restart. Application-reported source addresses remain unverified; operators must independently review a candidate before approval. Late discovery of a compromised approved account is not automatically rolled back. The proxy injects only the viewer token; operator writes use the separate localhost management port.

The 35/35 synthetic result is a regression measurement and must not be used as a production accuracy claim. A production designation still requires external security review, trustworthy source attribution, traffic-derived evaluation, sustained load at the intended operating rate, and operational drills with real certificates and off-host backups.
