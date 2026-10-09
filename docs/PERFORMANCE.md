# Reproducible local ingestion probe

This is a **synthetic single-process measurement**, not a production capacity claim or a detection-quality benchmark.

Run from the repository root:

```bash
cargo test -p logshield-api --test private_api synthetic_private_ingest_throughput -- --ignored --nocapture
```

The test starts a fresh private-mode API with a temporary SQLite database on localhost. It sends 50 sequential batches of 100 benign `web_request` events through the authenticated Rust SDK, waits for a durable receipt after each batch, and verifies all 5,000 rows in SQLite. It prints total events/sec and batch p50/p95 latency. The temporary database is removed afterward. It excludes file sensing, parallel senders, attack traffic, TLS proxying, and long-term database growth.

Measured on the same Fedora development machine on October 10, 2026, using the debug test build:

| Implementation | 5,000 events | Rate | Batch p50 | Batch p95 |
| --- | ---: | ---: | ---: | ---: |
| Before benign-only source guard | 71.64 s | 70 events/s | 1,819 ms | 1,966 ms |
| After guard | 8.98 s | 557 events/s | 184 ms | 217 ms |

The guard skips TACG's time-window search for sources whose recent events contain no suspicious event type or completed login. Those events still enter SQLite and baseline learning. Detection rules, thresholds, and score weights are unchanged. Results will vary with CPU, SQLite storage, traffic mix, and build profile.

This probe does **not** establish that TACG outperforms a strong centralized detector on realistic labeled traffic. The API still reloads up to 2,000 recent events and recomputes correlations after batches containing candidates. The mixed-traffic probe below covers a small concurrent case; sustained load, retention, disk pressure, and field false-positive rates remain unmeasured.

## Mixed traffic with four concurrent authenticated producers

Run:

```bash
cargo test -p logshield-api --test private_api concurrent_mixed_ingest_probe -- --ignored --nocapture
```

This localhost debug-build probe uses four concurrent producer tasks, each with a distinct authenticated collector token. It submits 2,000 events in 20 batches of 100: high-cardinality normal web traffic, successful logins, and repeated failed logins from a probe source. It verifies the exact persisted row count. On a Fedora 44 laptop (Intel Core i7-13650HX, 20 logical CPUs, 23 GiB RAM), the first run before skipping benign-only correlation anchors exceeded the SDK's 15-second request timeout. After the guard, a local run measured **13.88 s, 144 events/s, batch p50 1,487 ms, p95 5,297 ms, p99 5,701 ms**. A separate sequential benign run on the updated code measured 5,000 events in 9.61 s (520 events/s), p50 196 ms, p95 234 ms.

This is a small synthetic workload, not sustained capacity. The four tasks are on one host, and the API still loads up to 2,000 recent rows after each candidate batch. Attack traffic is markedly slower than benign-only traffic. The result is a sizing warning for private beta deployments; 10,000 and 100,000 event mixed runs, disk saturation, and multi-host field measurements have not been completed.
