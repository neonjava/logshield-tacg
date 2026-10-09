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

This probe does **not** establish that TACG outperforms a strong centralized detector on realistic labeled traffic. The API still reloads up to 2,000 recent events and recomputes correlations after batches containing candidates. Mixed attack traffic, multiple concurrent agents, sustained load, p99 latency, retention, crash recovery, and false-positive rates need separate evaluation before capacity or detection claims.
